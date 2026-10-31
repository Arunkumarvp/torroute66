// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil TA – GlobalPlatform entry points + command dispatch
 *
 * Entry points called by the OP-TEE OS:
 *   TA_CreateEntryPoint   – called once when the TA image is loaded
 *   TA_OpenSessionEntryPoint  – called for each new client session
 *   TA_InvokeCommandEntryPoint – called for each command
 *   TA_CloseSessionEntryPoint  – called when a session closes
 *   TA_DestroyEntryPoint  – called when the last session is gone
 *
 * Command dispatch:
 *   PQVEIL_CMD_GET_STATUS       → cmd_get_status()
 *   PQVEIL_CMD_PROVISION        → cmd_provision()
 *   PQVEIL_CMD_SIGN_TRANSCRIPT  → cmd_sign_transcript()
 *   PQVEIL_CMD_DECAPS           → cmd_decaps()
 *   PQVEIL_CMD_SIGN_HEALTH      → cmd_sign_health()
 *   PQVEIL_CMD_LOAD_POLICY      → cmd_load_policy()
 *
 * Security invariants enforced here:
 *   1. All input is copied out of shared memory before validation.
 *   2. TEE_Param types and sizes are checked before use.
 *   3. Key material is never written to output parameters.
 *   4. All stack buffers are zeroized on every exit path.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdint.h>

#include "user_ta_header_defines.h"
#include "crypto_service.h"
#include "policy_service.h"

/* -------------------------------------------------------------------------
 * Session context
 * One struct per open session; allocated in TA_OpenSessionEntryPoint.
 * ---------------------------------------------------------------------- */
typedef struct {
    uint32_t session_id;
    bool     provisioned;   /* true after PROVISION succeeds */
} pqveil_session_t;

static uint32_t g_session_count = 0;

/* -------------------------------------------------------------------------
 * TA_CreateEntryPoint
 * Called once when the TA is first loaded into secure memory.
 * ---------------------------------------------------------------------- */
TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result res;

    DMSG("PQVeil TA v%u.%u: CreateEntryPoint",
         PQVEIL_TA_VERSION_MAJOR, PQVEIL_TA_VERSION_MINOR);

    res = crypto_service_init();
    if (res != TEE_SUCCESS) {
        EMSG("crypto_service_init failed: 0x%08x", res);
        return res;
    }

    res = policy_service_init();
    if (res != TEE_SUCCESS) {
        EMSG("policy_service_init failed: 0x%08x", res);
        crypto_service_destroy();
        return res;
    }

    return TEE_SUCCESS;
}

/* -------------------------------------------------------------------------
 * TA_DestroyEntryPoint
 * Called when the last session is closed and the TA is being unloaded.
 * ---------------------------------------------------------------------- */
void TA_DestroyEntryPoint(void)
{
    DMSG("PQVeil TA: DestroyEntryPoint");
    policy_service_destroy();
    crypto_service_destroy();
}

/* -------------------------------------------------------------------------
 * TA_OpenSessionEntryPoint
 * Called for each new GP session from the normal world.
 * ---------------------------------------------------------------------- */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                     TEE_Param params[4],
                                     void **sess_ctx)
{
    /* No input parameters expected on open */
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);
    (void)params;

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    pqveil_session_t *sess = TEE_Malloc(sizeof(*sess), TEE_MALLOC_FILL_ZERO);
    if (!sess)
        return TEE_ERROR_OUT_OF_MEMORY;

    sess->session_id  = ++g_session_count;
    sess->provisioned = policy_service_is_provisioned();
    *sess_ctx = sess;

    DMSG("PQVeil TA: session %u opened", sess->session_id);
    return TEE_SUCCESS;
}

/* -------------------------------------------------------------------------
 * TA_CloseSessionEntryPoint
 * ---------------------------------------------------------------------- */
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    pqveil_session_t *sess = (pqveil_session_t *)sess_ctx;
    if (sess) {
        DMSG("PQVeil TA: session %u closed", sess->session_id);
        TEE_Free(sess);
    }
}

/* =========================================================================
 * Individual command handlers
 * ====================================================================== */

/*
 * cmd_get_status
 *
 * Param[0] memref(output): version_major(u8) || version_minor(u8) ||
 *                          monotonic_counter(u64, LE) ||
 *                          storage_mode(u8)  [0=REE-FS 1=RPMB]
 *                          provisioned(u8)
 *          total: 12 bytes
 */
static TEE_Result cmd_get_status(pqveil_session_t *sess,
                                  uint32_t param_types,
                                  TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].memref.size < 12)
        return TEE_ERROR_SHORT_BUFFER;

    uint8_t *out = (uint8_t *)params[0].memref.buffer;
    uint64_t counter = policy_service_get_counter();

    out[0]  = (uint8_t)PQVEIL_TA_VERSION_MAJOR;
    out[1]  = (uint8_t)PQVEIL_TA_VERSION_MINOR;
    /* counter: 8 bytes little-endian */
    for (int i = 0; i < 8; i++)
        out[2 + i] = (uint8_t)(counter >> (i * 8));
    out[10] = 0u;  /* storage: 0=REE-FS (QEMU); set to 1 on RPMB hardware */
    out[11] = sess->provisioned ? 1u : 0u;

    params[0].memref.size = 12;
    DMSG("GET_STATUS: counter=%llu provisioned=%u",
         (unsigned long long)counter, sess->provisioned);
    return TEE_SUCCESS;
}

/*
 * cmd_provision
 *
 * One-time: generate ML-KEM-768 seed and ML-DSA-65 seed; seal both to
 * secure storage.  Returns the ML-DSA-65 public key.
 *
 * Param[0] memref(output): ML-DSA-65 public key (PQVEIL_MLDSA_PK_SZ bytes)
 */
static TEE_Result cmd_provision(pqveil_session_t *sess,
                                 uint32_t param_types,
                                 TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].memref.size < PQVEIL_MLDSA_PK_SZ)
        return TEE_ERROR_SHORT_BUFFER;

    if (sess->provisioned) {
        EMSG("PROVISION called on already-provisioned TA");
        return TEE_ERROR_ACCESS_CONFLICT;
    }

    TEE_Result res = policy_service_provision(
                         (uint8_t *)params[0].memref.buffer,
                         &params[0].memref.size);
    if (res == TEE_SUCCESS) {
        sess->provisioned = true;
        IMSG("PQVeil TA provisioned successfully");
    }
    return res;
}

/*
 * cmd_sign_transcript
 *
 * Signs a 32-byte transcript hash with the ML-DSA-65 identity key.
 * Domain separated: "PQVeil v1 handshake" prepended before signing.
 *
 * Param[0] memref(input):  32-byte transcript hash
 * Param[1] memref(output): PQVEIL_MLDSA_SIG_SZ byte signature
 */
static TEE_Result cmd_sign_transcript(pqveil_session_t *sess,
                                       uint32_t param_types,
                                       TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                   TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!sess->provisioned)
        return TEE_ERROR_BAD_STATE;

    /* Copy input out of shared memory before validation (anti-TOCTOU) */
    if (params[0].memref.size != PQVEIL_TRANSCRIPT_HASH_SZ)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[1].memref.size < PQVEIL_MLDSA_SIG_SZ)
        return TEE_ERROR_SHORT_BUFFER;

    uint8_t hash_copy[PQVEIL_TRANSCRIPT_HASH_SZ];
    TEE_MemMove(hash_copy, params[0].memref.buffer, PQVEIL_TRANSCRIPT_HASH_SZ);

    TEE_Result res = policy_service_sign_transcript(
                         hash_copy,
                         (uint8_t *)params[1].memref.buffer,
                         &params[1].memref.size);

    /* Zeroize local copy */
    TEE_MemFill(hash_copy, 0, sizeof(hash_copy));
    return res;
}

/*
 * cmd_decaps
 *
 * ML-KEM-768 static decapsulation using the TA's sealed KEM key.
 * Returns only the 32-byte shared secret; never the private key.
 *
 * Param[0] memref(input):  ciphertext (PQVEIL_MLKEM_CT_SZ bytes)
 * Param[1] memref(output): shared secret (PQVEIL_MLKEM_SS_SZ bytes)
 */
static TEE_Result cmd_decaps(pqveil_session_t *sess,
                              uint32_t param_types,
                              TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                   TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!sess->provisioned)
        return TEE_ERROR_BAD_STATE;

    if (params[0].memref.size != PQVEIL_MLKEM_CT_SZ)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[1].memref.size < PQVEIL_MLKEM_SS_SZ)
        return TEE_ERROR_SHORT_BUFFER;

    /* Copy ciphertext out of shared memory */
    uint8_t ct_copy[PQVEIL_MLKEM_CT_SZ];
    TEE_MemMove(ct_copy, params[0].memref.buffer, PQVEIL_MLKEM_CT_SZ);

    uint8_t ss[PQVEIL_MLKEM_SS_SZ];
    TEE_Result res = policy_service_decaps(ct_copy, ss);
    if (res == TEE_SUCCESS) {
        TEE_MemMove(params[1].memref.buffer, ss, PQVEIL_MLKEM_SS_SZ);
        params[1].memref.size = PQVEIL_MLKEM_SS_SZ;
    }

    /* Zeroize both local copies */
    TEE_MemFill(ct_copy, 0, sizeof(ct_copy));
    TEE_MemFill(ss, 0, sizeof(ss));
    return res;
}

/*
 * cmd_sign_health
 *
 * Generates a signed health report including a caller-supplied nonce and
 * current Tor/tunnel state flags.
 *
 * Param[0] memref(input):  nonce (PQVEIL_HEALTH_NONCE_SZ bytes)
 * Param[1] value(input):   [0] = flags (u32): bit0=tor_up, bit1=tunnel_up
 * Param[2] memref(output): signed report (nonce||flags||sig)
 */
static TEE_Result cmd_sign_health(pqveil_session_t *sess,
                                   uint32_t param_types,
                                   TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                   TEE_PARAM_TYPE_VALUE_INPUT,
                                   TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                   TEE_PARAM_TYPE_NONE);
    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!sess->provisioned)
        return TEE_ERROR_BAD_STATE;

    if (params[0].memref.size != PQVEIL_HEALTH_NONCE_SZ)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Minimum output: nonce(16) + flags(4) + sig(3309) = 3329 bytes */
    const size_t MIN_REPORT_SZ = PQVEIL_HEALTH_NONCE_SZ + 4 + PQVEIL_MLDSA_SIG_SZ;
    if (params[2].memref.size < MIN_REPORT_SZ)
        return TEE_ERROR_SHORT_BUFFER;

    uint8_t nonce_copy[PQVEIL_HEALTH_NONCE_SZ];
    TEE_MemMove(nonce_copy, params[0].memref.buffer, PQVEIL_HEALTH_NONCE_SZ);
    uint32_t flags = params[1].value.a;

    TEE_Result res = policy_service_sign_health(
                         nonce_copy, flags,
                         (uint8_t *)params[2].memref.buffer,
                         &params[2].memref.size);

    TEE_MemFill(nonce_copy, 0, sizeof(nonce_copy));
    return res;
}

/*
 * cmd_load_policy
 *
 * Loads a new signed policy blob.  The policy version must be strictly
 * greater than the current monotonic counter; on success the counter
 * advances and the policy is sealed to secure storage.
 *
 * Param[0] memref(input):  signed policy blob (variable length)
 */
static TEE_Result cmd_load_policy(pqveil_session_t *sess,
                                   uint32_t param_types,
                                   TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!sess->provisioned)
        return TEE_ERROR_BAD_STATE;

    if (params[0].memref.size == 0 ||
        params[0].memref.size > 4096)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Copy entire blob out of shared memory first */
    uint8_t *blob = TEE_Malloc(params[0].memref.size, 0);
    if (!blob)
        return TEE_ERROR_OUT_OF_MEMORY;

    TEE_MemMove(blob, params[0].memref.buffer, params[0].memref.size);

    TEE_Result res = policy_service_load_policy(blob, params[0].memref.size);

    TEE_MemFill(blob, 0, params[0].memref.size);
    TEE_Free(blob);
    return res;
}

/* =========================================================================
 * TA_InvokeCommandEntryPoint – main dispatcher
 * ====================================================================== */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                       uint32_t cmd_id,
                                       uint32_t param_types,
                                       TEE_Param params[4])
{
    pqveil_session_t *sess = (pqveil_session_t *)sess_ctx;

    DMSG("PQVeil TA: command 0x%08x (session %u)", cmd_id,
         sess ? sess->session_id : 0);

    switch (cmd_id) {
    case PQVEIL_CMD_GET_STATUS:
        return cmd_get_status(sess, param_types, params);
    case PQVEIL_CMD_PROVISION:
        return cmd_provision(sess, param_types, params);
    case PQVEIL_CMD_SIGN_TRANSCRIPT:
        return cmd_sign_transcript(sess, param_types, params);
    case PQVEIL_CMD_DECAPS:
        return cmd_decaps(sess, param_types, params);
    case PQVEIL_CMD_SIGN_HEALTH:
        return cmd_sign_health(sess, param_types, params);
    case PQVEIL_CMD_LOAD_POLICY:
        return cmd_load_policy(sess, param_types, params);
    default:
        EMSG("Unknown command 0x%08x", cmd_id);
        return TEE_ERROR_NOT_IMPLEMENTED;
    }
}

