// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil TA – Policy and Sealed Identity Service
 *
 * Implements:
 *   - Persistent secure storage of ML-KEM and ML-DSA identity seeds
 *   - Monotonic policy version counter enforcement (anti-rollback)
 *   - On-demand seed expansion to minimize secure-RAM pressure
 *   - Domain-separated signing (handshake transcript, health status)
 *   - Static KEM decapsulation
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "user_ta_header_defines.h"
#include "crypto_service.h"
#include "policy_service.h"

/* -------------------------------------------------------------------------
 * External PQC Shim Declarations for ML-DSA-65 & ML-KEM-768
 * (provided by usepqc / liboqs shim)
 * ---------------------------------------------------------------------- */
extern int pqveil_mlkem768_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqveil_mldsa65_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqveil_mldsa65_sign(uint8_t *sig, size_t *sig_len,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sk);

/* -------------------------------------------------------------------------
 * Internal State
 * ---------------------------------------------------------------------- */
static bool     g_policy_init = false;
static bool     g_is_provisioned = false;
static uint64_t g_monotonic_counter = 0;

static void secure_wipe(void *p, size_t len)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--) {
        *v++ = 0;
    }
}

/* -------------------------------------------------------------------------
 * Secure Storage Helpers
 * ---------------------------------------------------------------------- */
static TEE_Result read_sealed_blob(const char *obj_id, void *data, uint32_t len)
{
    TEE_Result res;
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;
    uint32_t read_bytes = 0;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
                                  (void *)obj_id, strlen(obj_id),
                                  TEE_DATA_FLAG_ACCESS_READ,
                                  &obj);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_ReadObjectData(obj, data, len, &read_bytes);
    TEE_CloseObject(obj);

    if (res == TEE_SUCCESS && read_bytes != len)
        return TEE_ERROR_CORRUPT_OBJECT;

    return res;
}

static TEE_Result write_sealed_blob(const char *obj_id, const void *data, uint32_t len)
{
    TEE_Result res;
    TEE_ObjectHandle obj = TEE_HANDLE_NULL;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                    (void *)obj_id, strlen(obj_id),
                                    TEE_DATA_FLAG_ACCESS_WRITE |
                                    TEE_DATA_FLAG_ACCESS_WRITE_META |
                                    TEE_DATA_FLAG_OVERWRITE,
                                    TEE_HANDLE_NULL,
                                    (void *)data, len,
                                    &obj);
    if (res == TEE_SUCCESS) {
        TEE_CloseObject(obj);
    }
    return res;
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------- */
TEE_Result policy_service_init(void)
{
    TEE_Result res;

    if (g_policy_init)
        return TEE_SUCCESS;

    /* Check if seeds exist in storage */
    uint8_t dsa_seed[PQVEIL_DSA_SEED_SZ];
    res = read_sealed_blob(PQVEIL_STORE_DSA_SEED, dsa_seed, sizeof(dsa_seed));
    secure_wipe(dsa_seed, sizeof(dsa_seed));

    if (res == TEE_SUCCESS) {
        g_is_provisioned = true;
    } else {
        g_is_provisioned = false;
    }

    /* Load monotonic counter if present */
    uint64_t counter = 0;
    res = read_sealed_blob(PQVEIL_STORE_COUNTER, &counter, sizeof(counter));
    if (res == TEE_SUCCESS) {
        g_monotonic_counter = counter;
    } else {
        g_monotonic_counter = 0;
    }

    g_policy_init = true;
    DMSG("PQVeil policy_service init: provisioned=%d counter=%llu",
         g_is_provisioned, (unsigned long long)g_monotonic_counter);
    return TEE_SUCCESS;
}

void policy_service_destroy(void)
{
    g_policy_init = false;
    g_is_provisioned = false;
    g_monotonic_counter = 0;
}

bool policy_service_is_provisioned(void)
{
    return g_is_provisioned;
}

uint64_t policy_service_get_counter(void)
{
    return g_monotonic_counter;
}

/* -------------------------------------------------------------------------
 * One-time Provisioning
 * ---------------------------------------------------------------------- */
TEE_Result policy_service_provision(uint8_t *pk_out, uint32_t *pk_size)
{
    TEE_Result res;
    uint8_t kem_seed[PQVEIL_KEM_SEED_SZ];
    uint8_t dsa_seed[PQVEIL_DSA_SEED_SZ];
    uint8_t dsa_pk[PQVEIL_MLDSA_PK_SZ];
    uint8_t dsa_sk[4032]; /* Temporary buffer for expansion */

    if (!pk_out || !pk_size || *pk_size < PQVEIL_MLDSA_PK_SZ)
        return TEE_ERROR_BAD_PARAMETERS;

    if (g_is_provisioned)
        return TEE_ERROR_ACCESS_CONFLICT;

    /* Generate cryptographically secure seeds */
    TEE_GenerateRandom(kem_seed, sizeof(kem_seed));
    TEE_GenerateRandom(dsa_seed, sizeof(dsa_seed));

    /* Derive the public key from the DSA seed */
    if (pqveil_mldsa65_keypair_from_seed(dsa_pk, dsa_sk, dsa_seed) != 0) {
        secure_wipe(kem_seed, sizeof(kem_seed));
        secure_wipe(dsa_seed, sizeof(dsa_seed));
        secure_wipe(dsa_sk, sizeof(dsa_sk));
        return TEE_ERROR_GENERIC;
    }
    secure_wipe(dsa_sk, sizeof(dsa_sk));

    /* Seal both seeds to secure storage */
    res = write_sealed_blob(PQVEIL_STORE_KEM_SEED, kem_seed, sizeof(kem_seed));
    if (res != TEE_SUCCESS)
        goto cleanup;

    res = write_sealed_blob(PQVEIL_STORE_DSA_SEED, dsa_seed, sizeof(dsa_seed));
    if (res != TEE_SUCCESS)
        goto cleanup;

    /* Initialize persistent counter */
    g_monotonic_counter = 1;
    res = write_sealed_blob(PQVEIL_STORE_COUNTER, &g_monotonic_counter, sizeof(g_monotonic_counter));
    if (res != TEE_SUCCESS)
        goto cleanup;

    /* Copy public key to caller */
    TEE_MemMove(pk_out, dsa_pk, PQVEIL_MLDSA_PK_SZ);
    *pk_size = PQVEIL_MLDSA_PK_SZ;
    g_is_provisioned = true;

    DMSG("Provisioning complete. DSA public key generated.");

cleanup:
    secure_wipe(kem_seed, sizeof(kem_seed));
    secure_wipe(dsa_seed, sizeof(dsa_seed));
    secure_wipe(dsa_pk, sizeof(dsa_pk));
    return res;
}

/* -------------------------------------------------------------------------
 * Handshake Transcript Signing
 * ---------------------------------------------------------------------- */
TEE_Result policy_service_sign_transcript(const uint8_t hash[32],
                                          uint8_t *sig_out,
                                          uint32_t *sig_size)
{
    TEE_Result res;
    uint8_t dsa_seed[PQVEIL_DSA_SEED_SZ];
    uint8_t dsa_pk[PQVEIL_MLDSA_PK_SZ];
    uint8_t dsa_sk[4032];
    size_t sig_len = PQVEIL_MLDSA_SIG_SZ;

    if (!hash || !sig_out || !sig_size || *sig_size < PQVEIL_MLDSA_SIG_SZ)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!g_is_provisioned)
        return TEE_ERROR_BAD_STATE;

    /* Read DSA seed */
    res = read_sealed_blob(PQVEIL_STORE_DSA_SEED, dsa_seed, sizeof(dsa_seed));
    if (res != TEE_SUCCESS)
        return res;

    /* Regenerate private key on-demand */
    if (pqveil_mldsa65_keypair_from_seed(dsa_pk, dsa_sk, dsa_seed) != 0) {
        secure_wipe(dsa_seed, sizeof(dsa_seed));
        return TEE_ERROR_GENERIC;
    }
    secure_wipe(dsa_seed, sizeof(dsa_seed));

    /* Build domain-separated message: Domain || Hash */
    uint8_t msg_buf[sizeof(PQVEIL_SIGN_DOMAIN_HANDSHAKE) + 32];
    size_t domain_len = strlen(PQVEIL_SIGN_DOMAIN_HANDSHAKE);
    TEE_MemMove(msg_buf, PQVEIL_SIGN_DOMAIN_HANDSHAKE, domain_len);
    TEE_MemMove(msg_buf + domain_len, hash, 32);

    if (pqveil_mldsa65_sign(sig_out, &sig_len, msg_buf, domain_len + 32, dsa_sk) != 0) {
        secure_wipe(dsa_sk, sizeof(dsa_sk));
        secure_wipe(msg_buf, sizeof(msg_buf));
        return TEE_ERROR_GENERIC;
    }

    *sig_size = (uint32_t)sig_len;

    secure_wipe(dsa_sk, sizeof(dsa_sk));
    secure_wipe(msg_buf, sizeof(msg_buf));
    return TEE_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Static ML-KEM Decapsulation
 * ---------------------------------------------------------------------- */
TEE_Result policy_service_decaps(const uint8_t *ciphertext,
                                 uint8_t *shared_secret_out)
{
    TEE_Result res;
    uint8_t kem_seed[PQVEIL_KEM_SEED_SZ];
    uint8_t kem_pk[PQVEIL_MLKEM_PK_SZ];
    uint8_t kem_sk[PQVEIL_MLKEM_SK_SZ];

    if (!ciphertext || !shared_secret_out)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!g_is_provisioned)
        return TEE_ERROR_BAD_STATE;

    res = read_sealed_blob(PQVEIL_STORE_KEM_SEED, kem_seed, sizeof(kem_seed));
    if (res != TEE_SUCCESS)
        return res;

    if (pqveil_mlkem768_keypair_from_seed(kem_pk, kem_sk, kem_seed) != 0) {
        secure_wipe(kem_seed, sizeof(kem_seed));
        return TEE_ERROR_GENERIC;
    }
    secure_wipe(kem_seed, sizeof(kem_seed));

    if (pqveil_mlkem768_dec(shared_secret_out, ciphertext, kem_sk) != 0) {
        secure_wipe(kem_sk, sizeof(kem_sk));
        return TEE_ERROR_GENERIC;
    }

    secure_wipe(kem_sk, sizeof(kem_sk));
    return TEE_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Health Report Signing
 * ---------------------------------------------------------------------- */
TEE_Result policy_service_sign_health(const uint8_t *nonce,
                                      uint32_t flags,
                                      uint8_t *report_out,
                                      uint32_t *report_size)
{
    TEE_Result res;
    uint8_t dsa_seed[PQVEIL_DSA_SEED_SZ];
    uint8_t dsa_pk[PQVEIL_MLDSA_PK_SZ];
    uint8_t dsa_sk[4032];
    uint8_t payload[PQVEIL_HEALTH_NONCE_SZ + sizeof(uint32_t)];

    if (!nonce || !report_out || !report_size)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!g_is_provisioned)
        return TEE_ERROR_BAD_STATE;

    const size_t needed = PQVEIL_HEALTH_NONCE_SZ + sizeof(uint32_t) + PQVEIL_MLDSA_SIG_SZ;
    if (*report_size < needed)
        return TEE_ERROR_SHORT_BUFFER;

    /* Assemble payload: Nonce (16) || Flags (4) */
    TEE_MemMove(payload, nonce, PQVEIL_HEALTH_NONCE_SZ);
    TEE_MemMove(payload + PQVEIL_HEALTH_NONCE_SZ, &flags, sizeof(uint32_t));

    /* Assemble message with domain separator */
    size_t dom_len = strlen(PQVEIL_SIGN_DOMAIN_HEALTH);
    size_t msg_len = dom_len + sizeof(payload);
    uint8_t msg[dom_len + sizeof(payload)];
    TEE_MemMove(msg, PQVEIL_SIGN_DOMAIN_HEALTH, dom_len);
    TEE_MemMove(msg + dom_len, payload, sizeof(payload));

    res = read_sealed_blob(PQVEIL_STORE_DSA_SEED, dsa_seed, sizeof(dsa_seed));
    if (res != TEE_SUCCESS)
        return res;

    if (pqveil_mldsa65_keypair_from_seed(dsa_pk, dsa_sk, dsa_seed) != 0) {
        secure_wipe(dsa_seed, sizeof(dsa_seed));
        return TEE_ERROR_GENERIC;
    }
    secure_wipe(dsa_seed, sizeof(dsa_seed));

    size_t sig_len = PQVEIL_MLDSA_SIG_SZ;
    uint8_t sig[PQVEIL_MLDSA_SIG_SZ];
    if (pqveil_mldsa65_sign(sig, &sig_len, msg, msg_len, dsa_sk) != 0) {
        secure_wipe(dsa_sk, sizeof(dsa_sk));
        secure_wipe(msg, sizeof(msg));
        return TEE_ERROR_GENERIC;
    }
    secure_wipe(dsa_sk, sizeof(dsa_sk));

    /* Output structure: Nonce (16) || Flags (4) || Signature (3309) */
    TEE_MemMove(report_out, payload, sizeof(payload));
    TEE_MemMove(report_out + sizeof(payload), sig, sig_len);
    *report_size = sizeof(payload) + sig_len;

    secure_wipe(sig, sizeof(sig));
    secure_wipe(msg, sizeof(msg));
    return TEE_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Load Policy & Monotonic Rollback Check
 * Expected format of blob:
 *   [8 bytes]: new monotonic counter (uint64_t little-endian)
 *   [4 bytes]: policy payload length
 *   [N bytes]: policy payload
 *   [3309 bytes]: ML-DSA-65 signature over (counter || length || payload)
 * ---------------------------------------------------------------------- */
TEE_Result policy_service_load_policy(const uint8_t *blob, uint32_t size)
{
    TEE_Result res;

    if (!blob || size < (8 + 4 + PQVEIL_MLDSA_SIG_SZ))
        return TEE_ERROR_BAD_PARAMETERS;

    uint64_t new_counter = 0;
    for (int i = 0; i < 8; i++) {
        new_counter |= ((uint64_t)blob[i]) << (i * 8);
    }

    /* Monotonicity check */
    if (new_counter <= g_monotonic_counter) {
        EMSG("Rollback detected: new counter %llu <= current %llu",
             (unsigned long long)new_counter, (unsigned long long)g_monotonic_counter);
        return TEE_ERROR_SECURITY;
    }

    uint32_t payload_len = 0;
    TEE_MemMove(&payload_len, blob + 8, sizeof(uint32_t));

    if (size != (8 + 4 + payload_len + PQVEIL_MLDSA_SIG_SZ)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Seal the new policy and update monotonic counter */
    res = write_sealed_blob(PQVEIL_STORE_POLICY, blob + 12, payload_len);
    if (res != TEE_SUCCESS)
        return res;

    g_monotonic_counter = new_counter;
    res = write_sealed_blob(PQVEIL_STORE_COUNTER, &g_monotonic_counter, sizeof(g_monotonic_counter));
    if (res != TEE_SUCCESS)
        return res;

    DMSG("New policy loaded successfully. Counter advanced to %llu",
         (unsigned long long)g_monotonic_counter);
    return TEE_SUCCESS;
}

