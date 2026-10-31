// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil TEE – Tor Crypto Services
 *
 * Implements the cryptographic primitives required by the Tor overlay layer
 * inside an OP-TEE Trusted Application:
 *
 *   • AES-256-CTR  – cell stream cipher (Tor link protocol v3+)
 *   • SHA-256 / SHA-3-256 – digest utilities
 *   • HMAC-SHA256  – KDF / MAC
 *   • HKDF-SHA256  – key derivation (RFC 5869)
 *   • X25519        – Tor ntor handshake ephemeral DH
 *   • Ed25519       – relay identity signing / verification
 *   • ChaCha20-Poly1305 – authenticated cell encryption (PQ hybrid path)
 *   • ML-KEM-768   – post-quantum KEM (NIST FIPS 203, Kyber drop-in)
 *     (represented here via opaque byte-array API over the TEE secure storage;
 *      actual PQC ops are dispatched to the liboqs shim in secure world)
 *
 * All secrets stay inside the TA.  Key handles are 32-bit opaque tokens
 * returned to the host and stored in a fixed-size key table.
 *
 * OP-TEE GlobalPlatform TEE Internal Core API v1.3.1 is assumed.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdint.h>

#include "crypto_service.h"

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

#define PQVEIL_MAX_KEYS          64u
#define PQVEIL_AES_KEY_BITS      256u
#define PQVEIL_AES_BLOCK_SZ      16u
#define PQVEIL_CHACHA_KEY_SZ     32u
#define PQVEIL_CHACHA_NONCE_SZ   12u
#define PQVEIL_CHACHA_TAG_SZ     16u
#define PQVEIL_X25519_SCALAR_SZ  32u
#define PQVEIL_X25519_POINT_SZ   32u
#define PQVEIL_ED25519_SK_SZ     64u   /* seed + public key */
#define PQVEIL_ED25519_PK_SZ     32u
#define PQVEIL_ED25519_SIG_SZ    64u
#define PQVEIL_MLKEM768_PK_SZ    1184u
#define PQVEIL_MLKEM768_SK_SZ    2400u
#define PQVEIL_MLKEM768_CT_SZ    1088u
#define PQVEIL_MLKEM768_SS_SZ    32u
#define PQVEIL_HKDF_MAX_OUT      255u  /* RFC 5869 §2.3 */
#define PQVEIL_HMAC_SZ           32u
#define PQVEIL_SHA256_SZ         32u
#define PQVEIL_HANDLE_NONE       0xFFFFFFFFu

/* Tor ntor constants (tor-spec §5.1.4) */
#define NTOR_PROTOID        "ntor-curve25519-sha256-1"
#define NTOR_PROTOID_LEN    24u
#define NTOR_KEY_SEED_LEN   PQVEIL_SHA256_SZ
#define NTOR_AUTH_LEN       PQVEIL_SHA256_SZ

/* -------------------------------------------------------------------------
 * Key-table entry
 * ---------------------------------------------------------------------- */

typedef enum {
    KEY_TYPE_NONE = 0,
    KEY_TYPE_AES_CTR,
    KEY_TYPE_CHACHA20_POLY1305,
    KEY_TYPE_X25519_PRIVATE,
    KEY_TYPE_X25519_PUBLIC,
    KEY_TYPE_ED25519_PRIVATE,
    KEY_TYPE_ED25519_PUBLIC,
    KEY_TYPE_MLKEM768_PRIVATE,
    KEY_TYPE_MLKEM768_PUBLIC,
    KEY_TYPE_HMAC_SECRET,
    KEY_TYPE_RAW_SEED,
} pqveil_key_type_t;

typedef struct {
    pqveil_key_type_t type;
    uint32_t          key_bits;           /* for symmetric keys */
    TEE_ObjectHandle  tee_obj;            /* GP key object (may be NULL) */
    uint8_t           raw[PQVEIL_MLKEM768_SK_SZ]; /* for opaque blobs */
    uint32_t          raw_len;
    bool              in_use;
} pqveil_key_entry_t;

static pqveil_key_entry_t g_key_table[PQVEIL_MAX_KEYS];
static bool               g_initialised = false;

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

static TEE_Result alloc_handle(uint32_t *out_handle)
{
    for (uint32_t i = 0; i < PQVEIL_MAX_KEYS; i++) {
        if (!g_key_table[i].in_use) {
            g_key_table[i].in_use = true;
            *out_handle = i;
            return TEE_SUCCESS;
        }
    }
    return TEE_ERROR_OUT_OF_MEMORY;
}

static TEE_Result lookup_handle(uint32_t handle, pqveil_key_entry_t **out)
{
    if (handle >= PQVEIL_MAX_KEYS || !g_key_table[handle].in_use)
        return TEE_ERROR_BAD_PARAMETERS;
    *out = &g_key_table[handle];
    return TEE_SUCCESS;
}

/* Securely wipe a buffer. */
static void secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--)
        *p++ = 0;
}

/* -------------------------------------------------------------------------
 * crypto_service_init
 * ---------------------------------------------------------------------- */

TEE_Result crypto_service_init(void)
{
    if (g_initialised)
        return TEE_SUCCESS;

    TEE_MemFill(g_key_table, 0, sizeof(g_key_table));
    g_initialised = true;
    DMSG("PQVeil crypto_service: initialised (%u key slots)", PQVEIL_MAX_KEYS);
    return TEE_SUCCESS;
}

/* -------------------------------------------------------------------------
 * crypto_service_destroy
 * ---------------------------------------------------------------------- */

void crypto_service_destroy(void)
{
    for (uint32_t i = 0; i < PQVEIL_MAX_KEYS; i++) {
        if (g_key_table[i].in_use) {
            if (g_key_table[i].tee_obj != TEE_HANDLE_NULL)
                TEE_FreeTransientObject(g_key_table[i].tee_obj);
            secure_zero(g_key_table[i].raw, sizeof(g_key_table[i].raw));
            TEE_MemFill(&g_key_table[i], 0, sizeof(pqveil_key_entry_t));
        }
    }
    g_initialised = false;
}

/* =========================================================================
 * 1.  AES-256-CTR  (Tor relay cell stream cipher)
 * ====================================================================== */

/*
 * crypto_aes256ctr_import_key
 *
 * Import a 32-byte AES-256 key into a transient TEE key object.
 * Returns an opaque handle the host can use for encrypt/decrypt calls.
 */
TEE_Result crypto_aes256ctr_import_key(const uint8_t *key, size_t key_len,
                                        uint32_t *out_handle)
{
    TEE_Result         res;
    TEE_ObjectHandle   obj = TEE_HANDLE_NULL;
    TEE_Attribute      attr;
    uint32_t           handle;
    pqveil_key_entry_t *entry;

    if (!key || key_len != PQVEIL_AES_KEY_BITS / 8 || !out_handle)
        return TEE_ERROR_BAD_PARAMETERS;

    res = alloc_handle(&handle);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_AllocateTransientObject(TEE_TYPE_AES,
                                      PQVEIL_AES_KEY_BITS, &obj);
    if (res != TEE_SUCCESS)
        goto err_free_handle;

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                         (void *)key, key_len);
    res = TEE_PopulateTransientObject(obj, &attr, 1);
    if (res != TEE_SUCCESS)
        goto err_free_obj;

    entry           = &g_key_table[handle];
    entry->type     = KEY_TYPE_AES_CTR;
    entry->key_bits = PQVEIL_AES_KEY_BITS;
    entry->tee_obj  = obj;
    *out_handle     = handle;
    DMSG("AES-256-CTR key imported -> handle %u", handle);
    return TEE_SUCCESS;

err_free_obj:
    TEE_FreeTransientObject(obj);
err_free_handle:
    g_key_table[handle].in_use = false;
    return res;
}

/*
 * crypto_aes256ctr_crypt
 *
 * Encrypt or decrypt data in-place using AES-256-CTR.
 * iv_len must be 16 bytes (full AES block as counter).
 * AES-CTR is symmetric, so encrypt == decrypt.
 */
TEE_Result crypto_aes256ctr_crypt(uint32_t handle,
                                   const uint8_t *iv, size_t iv_len,
                                   const uint8_t *in, size_t in_len,
                                   uint8_t *out, size_t *out_len)
{
    TEE_Result         res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    pqveil_key_entry_t *entry;
    uint32_t           dest_len;

    res = lookup_handle(handle, &entry);
    if (res != TEE_SUCCESS || entry->type != KEY_TYPE_AES_CTR)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!iv || iv_len != PQVEIL_AES_BLOCK_SZ || !in || !out || !out_len)
        return TEE_ERROR_BAD_PARAMETERS;

    if (*out_len < in_len)
        return TEE_ERROR_SHORT_BUFFER;

    res = TEE_AllocateOperation(&op, TEE_ALG_AES_CTR,
                                TEE_MODE_ENCRYPT, PQVEIL_AES_KEY_BITS);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_SetOperationKey(op, entry->tee_obj);
    if (res != TEE_SUCCESS)
        goto out;

    TEE_CipherInit(op, (void *)iv, iv_len);

    dest_len = (uint32_t)in_len;
    res = TEE_CipherDoFinal(op, (void *)in, in_len, out, &dest_len);
    if (res == TEE_SUCCESS)
        *out_len = dest_len;

out:
    TEE_FreeOperation(op);
    return res;
}

/* =========================================================================
 * 2.  SHA-256  (cell digests, HMAC base)
 * ====================================================================== */

TEE_Result crypto_sha256(const uint8_t *data, size_t data_len,
                          uint8_t out[PQVEIL_SHA256_SZ])
{
    TEE_Result         res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t           hash_len = PQVEIL_SHA256_SZ;

    if (!data || !out)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
        return res;

    TEE_DigestUpdate(op, (void *)data, data_len);
    res = TEE_DigestDoFinal(op, NULL, 0, out, &hash_len);
    TEE_FreeOperation(op);
    return res;
}

/* =========================================================================
 * 3.  HMAC-SHA256
 * ====================================================================== */

/*
 * crypto_hmac_sha256_import_key - import raw bytes as HMAC-SHA256 key.
 */
TEE_Result crypto_hmac_sha256_import_key(const uint8_t *key, size_t key_len,
                                          uint32_t *out_handle)
{
    TEE_Result         res;
    TEE_ObjectHandle   obj = TEE_HANDLE_NULL;
    TEE_Attribute      attr;
    uint32_t           handle;
    pqveil_key_entry_t *entry;
    uint32_t           key_bits;

    if (!key || key_len == 0 || key_len > 64 || !out_handle)
        return TEE_ERROR_BAD_PARAMETERS;

    key_bits = (uint32_t)(key_len * 8);

    res = alloc_handle(&handle);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, key_bits, &obj);
    if (res != TEE_SUCCESS)
        goto err;

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, (void *)key, key_len);
    res = TEE_PopulateTransientObject(obj, &attr, 1);
    if (res != TEE_SUCCESS) {
        TEE_FreeTransientObject(obj);
        goto err;
    }

    entry           = &g_key_table[handle];
    entry->type     = KEY_TYPE_HMAC_SECRET;
    entry->key_bits = key_bits;
    entry->tee_obj  = obj;
    *out_handle     = handle;
    return TEE_SUCCESS;

err:
    g_key_table[handle].in_use = false;
    return res;
}

TEE_Result crypto_hmac_sha256(uint32_t key_handle,
                               const uint8_t *data, size_t data_len,
                               uint8_t out[PQVEIL_HMAC_SZ])
{
    TEE_Result         res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    pqveil_key_entry_t *entry;
    uint32_t           mac_len = PQVEIL_HMAC_SZ;

    res = lookup_handle(key_handle, &entry);
    if (res != TEE_SUCCESS || entry->type != KEY_TYPE_HMAC_SECRET)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256,
                                TEE_MODE_MAC, entry->key_bits);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_SetOperationKey(op, entry->tee_obj);
    if (res != TEE_SUCCESS)
        goto out;

    TEE_MACInit(op, NULL, 0);
    TEE_MACUpdate(op, (void *)data, data_len);
    res = TEE_MACComputeFinal(op, NULL, 0, out, &mac_len);

out:
    TEE_FreeOperation(op);
    return res;
}

/* =========================================================================
 * 4.  HKDF-SHA256   (RFC 5869 - Tor KDF-RFC5869, §5.2.2)
 * ====================================================================== */

/*
 * HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
 */
static TEE_Result hkdf_extract(const uint8_t *salt,  size_t salt_len,
                                const uint8_t *ikm,   size_t ikm_len,
                                uint8_t prk[PQVEIL_SHA256_SZ])
{
    /* default salt = 0x00 * HashLen when not supplied */
    static const uint8_t zero_salt[PQVEIL_SHA256_SZ] = {0};
    const uint8_t *real_salt     = salt ? salt : zero_salt;
    size_t         real_salt_len = salt ? salt_len : sizeof(zero_salt);

    TEE_Result          res;
    TEE_OperationHandle op      = TEE_HANDLE_NULL;
    TEE_ObjectHandle    key_obj = TEE_HANDLE_NULL;
    TEE_Attribute       attr;
    uint32_t            mac_len  = PQVEIL_SHA256_SZ;
    uint32_t            key_bits = (uint32_t)(real_salt_len * 8);

    if (key_bits == 0) key_bits = 8;

    res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, key_bits, &key_obj);
    if (res != TEE_SUCCESS) return res;

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                         (void *)real_salt, real_salt_len);
    res = TEE_PopulateTransientObject(key_obj, &attr, 1);
    if (res != TEE_SUCCESS) goto out;

    res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256,
                                TEE_MODE_MAC, key_bits);
    if (res != TEE_SUCCESS) goto out;

    res = TEE_SetOperationKey(op, key_obj);
    if (res != TEE_SUCCESS) goto out;

    TEE_MACInit(op, NULL, 0);
    TEE_MACUpdate(op, (void *)ikm, ikm_len);
    res = TEE_MACComputeFinal(op, NULL, 0, prk, &mac_len);

out:
    if (op      != TEE_HANDLE_NULL) TEE_FreeOperation(op);
    if (key_obj != TEE_HANDLE_NULL) TEE_FreeTransientObject(key_obj);
    return res;
}

/*
 * HKDF-Expand: OKM = T(1) || T(2) || ... truncated to out_len bytes.
 */
static TEE_Result hkdf_expand(const uint8_t prk[PQVEIL_SHA256_SZ],
                               const uint8_t *info, size_t info_len,
                               uint8_t *okm, size_t out_len)
{
    TEE_Result          res      = TEE_SUCCESS;
    TEE_OperationHandle op       = TEE_HANDLE_NULL;
    TEE_ObjectHandle    key_obj  = TEE_HANDLE_NULL;
    TEE_Attribute       attr;
    uint8_t             t[PQVEIL_SHA256_SZ] = {0};
    uint32_t            mac_len;
    size_t              written  = 0;
    uint8_t             counter;
    uint32_t            key_bits = PQVEIL_SHA256_SZ * 8;

    if (out_len > PQVEIL_HKDF_MAX_OUT * PQVEIL_SHA256_SZ)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, key_bits, &key_obj);
    if (res != TEE_SUCCESS) return res;

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                         (void *)prk, PQVEIL_SHA256_SZ);
    res = TEE_PopulateTransientObject(key_obj, &attr, 1);
    if (res != TEE_SUCCESS) goto out;

    for (counter = 1; written < out_len; counter++) {
        size_t chunk;

        res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256,
                                    TEE_MODE_MAC, key_bits);
        if (res != TEE_SUCCESS) goto out;

        res = TEE_SetOperationKey(op, key_obj);
        if (res != TEE_SUCCESS) {
            TEE_FreeOperation(op); op = TEE_HANDLE_NULL;
            goto out;
        }

        TEE_MACInit(op, NULL, 0);
        if (counter > 1)
            TEE_MACUpdate(op, t, PQVEIL_SHA256_SZ);   /* T(n-1) */
        if (info && info_len)
            TEE_MACUpdate(op, (void *)info, info_len);
        TEE_MACUpdate(op, &counter, 1);

        mac_len = PQVEIL_SHA256_SZ;
        res = TEE_MACComputeFinal(op, NULL, 0, t, &mac_len);
        TEE_FreeOperation(op); op = TEE_HANDLE_NULL;
        if (res != TEE_SUCCESS) goto out;

        chunk = ((out_len - written) < PQVEIL_SHA256_SZ) ?
                (out_len - written) : PQVEIL_SHA256_SZ;
        TEE_MemMove(okm + written, t, chunk);
        written += chunk;
    }

out:
    secure_zero(t, sizeof(t));
    if (op      != TEE_HANDLE_NULL) TEE_FreeOperation(op);
    if (key_obj != TEE_HANDLE_NULL) TEE_FreeTransientObject(key_obj);
    return res;
}

/*
 * crypto_hkdf_sha256 - public entry point.
 *
 * Derives `out_len` bytes into `okm` from (ikm, salt, info).
 */
TEE_Result crypto_hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                               const uint8_t *salt, size_t salt_len,
                               const uint8_t *info, size_t info_len,
                               uint8_t *okm,        size_t out_len)
{
    TEE_Result res;
    uint8_t    prk[PQVEIL_SHA256_SZ];

    if (!ikm || !okm || out_len == 0 ||
        out_len > PQVEIL_HKDF_MAX_OUT * PQVEIL_SHA256_SZ)
        return TEE_ERROR_BAD_PARAMETERS;

    res = hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    if (res != TEE_SUCCESS)
        goto out;

    res = hkdf_expand(prk, info, info_len, okm, out_len);

out:
    secure_zero(prk, sizeof(prk));
    return res;
}

/* =========================================================================
 * 5.  X25519  (Tor ntor ephemeral DH)
 * ====================================================================== */

/*
 * crypto_x25519_generate_keypair
 *
 * Generates a fresh X25519 keypair.  The private scalar is stored in the
 * key table; the public point is returned to the caller.
 */
TEE_Result crypto_x25519_generate_keypair(uint32_t *out_handle,
                                           uint8_t   pub[PQVEIL_X25519_POINT_SZ])
{
    TEE_Result         res;
    TEE_ObjectHandle   obj = TEE_HANDLE_NULL;
    uint32_t           handle;
    pqveil_key_entry_t *entry;
    uint32_t           pub_len = PQVEIL_X25519_POINT_SZ;

    if (!out_handle || !pub)
        return TEE_ERROR_BAD_PARAMETERS;

    res = alloc_handle(&handle);
    if (res != TEE_SUCCESS) return res;

    res = TEE_AllocateTransientObject(TEE_TYPE_X25519, 255, &obj);
    if (res != TEE_SUCCESS) goto err;

    res = TEE_GenerateKey(obj, 255, NULL, 0);
    if (res != TEE_SUCCESS) goto err_free;

    res = TEE_GetObjectBufferAttribute(obj, TEE_ATTR_ECC_PUBLIC_VALUE_X,
                                       pub, &pub_len);
    if (res != TEE_SUCCESS) goto err_free;

    entry          = &g_key_table[handle];
    entry->type    = KEY_TYPE_X25519_PRIVATE;
    entry->tee_obj = obj;
    *out_handle    = handle;
    DMSG("X25519 keypair generated -> handle %u", handle);
    return TEE_SUCCESS;

err_free:
    TEE_FreeTransientObject(obj);
err:
    g_key_table[handle].in_use = false;
    return res;
}

/*
 * crypto_x25519_derive_shared
 *
 * ECDH with our private key (handle) and the peer's public point.
 * Outputs the raw 32-byte shared secret (not yet hashed).
 */
TEE_Result crypto_x25519_derive_shared(uint32_t           priv_handle,
                                        const uint8_t      peer_pub[PQVEIL_X25519_POINT_SZ],
                                        uint8_t            shared[PQVEIL_X25519_SCALAR_SZ])
{
    TEE_Result          res;
    TEE_OperationHandle op         = TEE_HANDLE_NULL;
    TEE_ObjectHandle    peer_obj   = TEE_HANDLE_NULL;  /* peer public key  */
    TEE_ObjectHandle    secret_obj = TEE_HANDLE_NULL;  /* derived secret   */
    TEE_Attribute       pub_attr;
    pqveil_key_entry_t *entry;
    uint32_t            shared_len = PQVEIL_X25519_SCALAR_SZ;

    res = lookup_handle(priv_handle, &entry);
    if (res != TEE_SUCCESS || entry->type != KEY_TYPE_X25519_PRIVATE)
        return TEE_ERROR_BAD_PARAMETERS;

    /*
     * GP API DH pattern:
     *  1. Allocate a transient object of the same type as our private key
     *     to hold the peer's public point.
     *  2. Populate it with the raw public bytes.
     *  3. Allocate a GENERIC_SECRET derived-key object to receive the output.
     *  4. Call TEE_DeriveKey – it writes the Diffie-Hellman result into the
     *     derived object.
     *  5. Read TEE_ATTR_SECRET_VALUE out of the derived object.
     */

    /* Step 1+2: peer public-key object (TEE_TYPE_X25519, 255-bit) */
    res = TEE_AllocateTransientObject(TEE_TYPE_X25519, 255, &peer_obj);
    if (res != TEE_SUCCESS) return res;

    TEE_InitRefAttribute(&pub_attr, TEE_ATTR_ECC_PUBLIC_VALUE_X,
                         (void *)peer_pub, PQVEIL_X25519_POINT_SZ);
    res = TEE_PopulateTransientObject(peer_obj, &pub_attr, 1);
    if (res != TEE_SUCCESS) goto out;

    /* Step 3: generic-secret object to receive the shared secret */
    res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET,
                                      PQVEIL_X25519_SCALAR_SZ * 8,
                                      &secret_obj);
    if (res != TEE_SUCCESS) goto out;

    /* Step 4: ECDH operation with our private key */
    res = TEE_AllocateOperation(&op, TEE_ALG_ECDH_X25519,
                                TEE_MODE_DERIVE, 255);
    if (res != TEE_SUCCESS) goto out;

    res = TEE_SetOperationKey(op, entry->tee_obj);
    if (res != TEE_SUCCESS) goto out;

    TEE_DeriveKey(op, &pub_attr, 1, secret_obj);

    /* Step 5: extract the raw shared secret bytes */
    res = TEE_GetObjectBufferAttribute(secret_obj, TEE_ATTR_SECRET_VALUE,
                                       shared, &shared_len);

out:
    if (op         != TEE_HANDLE_NULL) TEE_FreeOperation(op);
    if (peer_obj   != TEE_HANDLE_NULL) TEE_FreeTransientObject(peer_obj);
    if (secret_obj != TEE_HANDLE_NULL) TEE_FreeTransientObject(secret_obj);
    return res;
}

/* =========================================================================
 * 6.  Tor ntor Handshake (tor-spec §5.1.4)
 *
 * Key material labels:
 *   PROTOID  = "ntor-curve25519-sha256-1"
 *   T_KEY    = PROTOID + ":key_extract"
 *   T_EXPAND = PROTOID + ":key_expand"
 * ====================================================================== */

static const char NTOR_T_KEY[]    = "ntor-curve25519-sha256-1:key_extract";
static const char NTOR_T_EXPAND[] = "ntor-curve25519-sha256-1:key_expand";

/*
 * crypto_ntor_client_handshake
 *
 * Performs the client side of the ntor handshake:
 *   1. Generate ephemeral X25519 key (X, x).
 *   2. Compute:
 *        secret_input = EXP(B,x) || EXP(Y,x) || ID || B || X || Y || PROTOID
 *   3. Derive KEY_SEED and AUTH via HKDF.
 *   4. Return our ephemeral public X and the KEY_SEED bytes.
 *
 * Inputs:
 *   router_id  - 20-byte router identity digest
 *   router_B   - 32-byte router ntor onion key (long-term)
 *   router_Y   - 32-byte router ephemeral public (from server hello)
 *
 * Outputs:
 *   our_X_pub  - 32-byte client ephemeral public (to send to relay)
 *   key_seed   - NTOR_KEY_SEED_LEN bytes of key material
 *   auth_out   - NTOR_AUTH_LEN bytes (verify field)
 */
TEE_Result crypto_ntor_client_handshake(
        const uint8_t  router_id[20],
        const uint8_t  router_B[PQVEIL_X25519_POINT_SZ],
        const uint8_t  router_Y[PQVEIL_X25519_POINT_SZ],
        uint8_t        our_X_pub[PQVEIL_X25519_POINT_SZ],
        uint8_t        key_seed[NTOR_KEY_SEED_LEN],
        uint8_t        auth_out[NTOR_AUTH_LEN])
{
    TEE_Result  res;
    uint32_t    eph_handle = PQVEIL_HANDLE_NONE;

    uint8_t     exp_bx[PQVEIL_X25519_SCALAR_SZ];  /* EXP(B,x) */
    uint8_t     exp_yx[PQVEIL_X25519_SCALAR_SZ];  /* EXP(Y,x) */

    /*
     * secret_input layout (in order):
     *   EXP(B,x)   32 bytes
     *   EXP(Y,x)   32 bytes
     *   ID         20 bytes
     *   B          32 bytes
     *   X          32 bytes
     *   Y          32 bytes
     *   PROTOID    24 bytes
     *              --------
     *              204 bytes total
     */
    uint8_t  secret_input[32 + 32 + 20 + 32 + 32 + 32 + NTOR_PROTOID_LEN];
    uint8_t *p = secret_input;

    uint8_t prk[PQVEIL_SHA256_SZ];
    uint8_t kdf_buf[NTOR_KEY_SEED_LEN + NTOR_AUTH_LEN];

    /* Step 1: generate ephemeral keypair (X, x) */
    res = crypto_x25519_generate_keypair(&eph_handle, our_X_pub);
    if (res != TEE_SUCCESS) return res;

    /* Step 2: EXP(B, x) */
    res = crypto_x25519_derive_shared(eph_handle, router_B, exp_bx);
    if (res != TEE_SUCCESS) goto cleanup;

    /* Step 3: EXP(Y, x) */
    res = crypto_x25519_derive_shared(eph_handle, router_Y, exp_yx);
    if (res != TEE_SUCCESS) goto cleanup;

    /* Step 4: assemble secret_input */
    TEE_MemMove(p, exp_bx,    32);              p += 32;
    TEE_MemMove(p, exp_yx,    32);              p += 32;
    TEE_MemMove(p, router_id, 20);              p += 20;
    TEE_MemMove(p, router_B,  32);              p += 32;
    TEE_MemMove(p, our_X_pub, 32);              p += 32;
    TEE_MemMove(p, router_Y,  32);              p += 32;
    TEE_MemMove(p, NTOR_PROTOID, NTOR_PROTOID_LEN);

    /* Step 5: PRK = HKDF-Extract(T_KEY, secret_input) */
    res = hkdf_extract((const uint8_t *)NTOR_T_KEY,
                        sizeof(NTOR_T_KEY) - 1,
                        secret_input, sizeof(secret_input),
                        prk);
    if (res != TEE_SUCCESS) goto cleanup;

    /* Step 6: OKM = HKDF-Expand(PRK, T_EXPAND, KEY_SEED_LEN + AUTH_LEN) */
    res = hkdf_expand(prk,
                      (const uint8_t *)NTOR_T_EXPAND,
                      sizeof(NTOR_T_EXPAND) - 1,
                      kdf_buf, sizeof(kdf_buf));
    if (res != TEE_SUCCESS) goto cleanup;

    TEE_MemMove(key_seed, kdf_buf,                  NTOR_KEY_SEED_LEN);
    TEE_MemMove(auth_out, kdf_buf + NTOR_KEY_SEED_LEN, NTOR_AUTH_LEN);

cleanup:
    secure_zero(exp_bx,       sizeof(exp_bx));
    secure_zero(exp_yx,       sizeof(exp_yx));
    secure_zero(secret_input, sizeof(secret_input));
    secure_zero(prk,          sizeof(prk));
    secure_zero(kdf_buf,      sizeof(kdf_buf));

    if (eph_handle != PQVEIL_HANDLE_NONE) {
        if (g_key_table[eph_handle].tee_obj != TEE_HANDLE_NULL)
            TEE_FreeTransientObject(g_key_table[eph_handle].tee_obj);
        TEE_MemFill(&g_key_table[eph_handle], 0, sizeof(pqveil_key_entry_t));
    }
    return res;
}

/*
 * crypto_ntor_server_handshake
 *
 * Performs the server (relay) side of the ntor handshake:
 *   1. Look up the long-term ntor key B by handle.
 *   2. Generate ephemeral keypair (Y, y).
 *   3. Compute:
 *        secret_input = EXP(X,y) || EXP(X,b) || ID || B || X || Y || PROTOID
 *   4. Derive KEY_SEED and AUTH.
 *   5. Return Y and AUTH to send back to the client.
 */
TEE_Result crypto_ntor_server_handshake(
        const uint8_t  router_id[20],
        uint32_t       long_term_b_handle,
        const uint8_t  router_B_pub[PQVEIL_X25519_POINT_SZ],
        const uint8_t  client_X[PQVEIL_X25519_POINT_SZ],
        uint8_t        our_Y_pub[PQVEIL_X25519_POINT_SZ],
        uint8_t        key_seed[NTOR_KEY_SEED_LEN],
        uint8_t        auth_out[NTOR_AUTH_LEN])
{
    TEE_Result          res;
    uint32_t            eph_handle = PQVEIL_HANDLE_NONE;
    pqveil_key_entry_t *b_entry;

    uint8_t  exp_xy[PQVEIL_X25519_SCALAR_SZ];   /* EXP(X, y) */
    uint8_t  exp_xb[PQVEIL_X25519_SCALAR_SZ];   /* EXP(X, b) */
    uint8_t  secret_input[32 + 32 + 20 + 32 + 32 + 32 + NTOR_PROTOID_LEN];
    uint8_t *p = secret_input;
    uint8_t  prk[PQVEIL_SHA256_SZ];
    uint8_t  kdf_buf[NTOR_KEY_SEED_LEN + NTOR_AUTH_LEN];

    res = lookup_handle(long_term_b_handle, &b_entry);
    if (res != TEE_SUCCESS || b_entry->type != KEY_TYPE_X25519_PRIVATE)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Generate ephemeral Y */
    res = crypto_x25519_generate_keypair(&eph_handle, our_Y_pub);
    if (res != TEE_SUCCESS) return res;

    /* EXP(X, y) */
    res = crypto_x25519_derive_shared(eph_handle, client_X, exp_xy);
    if (res != TEE_SUCCESS) goto cleanup;

    /* EXP(X, b) */
    res = crypto_x25519_derive_shared(long_term_b_handle, client_X, exp_xb);
    if (res != TEE_SUCCESS) goto cleanup;

    /* Assemble secret_input (same layout as client, symmetric by spec) */
    TEE_MemMove(p, exp_xy,     32);              p += 32;
    TEE_MemMove(p, exp_xb,     32);              p += 32;
    TEE_MemMove(p, router_id,  20);              p += 20;
    TEE_MemMove(p, router_B_pub, 32);            p += 32;
    TEE_MemMove(p, client_X,   32);              p += 32;
    TEE_MemMove(p, our_Y_pub,  32);              p += 32;
    TEE_MemMove(p, NTOR_PROTOID, NTOR_PROTOID_LEN);

    res = hkdf_extract((const uint8_t *)NTOR_T_KEY,
                        sizeof(NTOR_T_KEY) - 1,
                        secret_input, sizeof(secret_input),
                        prk);
    if (res != TEE_SUCCESS) goto cleanup;

    res = hkdf_expand(prk,
                      (const uint8_t *)NTOR_T_EXPAND,
                      sizeof(NTOR_T_EXPAND) - 1,
                      kdf_buf, sizeof(kdf_buf));
    if (res != TEE_SUCCESS) goto cleanup;

    TEE_MemMove(key_seed, kdf_buf,                    NTOR_KEY_SEED_LEN);
    TEE_MemMove(auth_out, kdf_buf + NTOR_KEY_SEED_LEN, NTOR_AUTH_LEN);

cleanup:
    secure_zero(exp_xy,       sizeof(exp_xy));
    secure_zero(exp_xb,       sizeof(exp_xb));
    secure_zero(secret_input, sizeof(secret_input));
    secure_zero(prk,          sizeof(prk));
    secure_zero(kdf_buf,      sizeof(kdf_buf));

    if (eph_handle != PQVEIL_HANDLE_NONE) {
        if (g_key_table[eph_handle].tee_obj != TEE_HANDLE_NULL)
            TEE_FreeTransientObject(g_key_table[eph_handle].tee_obj);
        TEE_MemFill(&g_key_table[eph_handle], 0, sizeof(pqveil_key_entry_t));
    }
    return res;
}

/*
 * crypto_ntor_verify_auth
 *
 * Checks the AUTH tag received from the relay.  Constant-time comparison.
 */
TEE_Result crypto_ntor_verify_auth(const uint8_t expected[NTOR_AUTH_LEN],
                                    const uint8_t received[NTOR_AUTH_LEN])
{
    uint8_t diff = 0;
    for (size_t i = 0; i < NTOR_AUTH_LEN; i++)
        diff |= expected[i] ^ received[i];
    return diff == 0 ? TEE_SUCCESS : TEE_ERROR_SECURITY;
}

/* =========================================================================
 * 7.  Ed25519  (relay identity signing / verification)
 * ====================================================================== */

/*
 * crypto_ed25519_generate_keypair
 *
 * Generates an Ed25519 signing keypair.  Returns:
 *   out_handle  - private key handle in the key table
 *   pub         - 32-byte public key
 */
TEE_Result crypto_ed25519_generate_keypair(uint32_t *out_handle,
                                            uint8_t   pub[PQVEIL_ED25519_PK_SZ])
{
    TEE_Result         res;
    TEE_ObjectHandle   obj = TEE_HANDLE_NULL;
    pqveil_key_entry_t *entry;
    uint32_t           handle;
    uint32_t           pub_len = PQVEIL_ED25519_PK_SZ;

    if (!out_handle || !pub)
        return TEE_ERROR_BAD_PARAMETERS;

    res = alloc_handle(&handle);
    if (res != TEE_SUCCESS) return res;

    res = TEE_AllocateTransientObject(TEE_TYPE_ED25519, 255, &obj);
    if (res != TEE_SUCCESS) goto err;

    res = TEE_GenerateKey(obj, 255, NULL, 0);
    if (res != TEE_SUCCESS) goto err_free;

    res = TEE_GetObjectBufferAttribute(obj, TEE_ATTR_ECC_PUBLIC_VALUE_X,
                                       pub, &pub_len);
    if (res != TEE_SUCCESS) goto err_free;

    entry          = &g_key_table[handle];
    entry->type    = KEY_TYPE_ED25519_PRIVATE;
    entry->tee_obj = obj;
    *out_handle    = handle;
    DMSG("Ed25519 keypair generated -> handle %u", handle);
    return TEE_SUCCESS;

err_free:
    TEE_FreeTransientObject(obj);
err:
    g_key_table[handle].in_use = false;
    return res;
}

/*
 * crypto_ed25519_sign
 *
 * Signs `msg` with the Ed25519 private key identified by `handle`.
 * sig must be PQVEIL_ED25519_SIG_SZ (64) bytes.
 */
TEE_Result crypto_ed25519_sign(uint32_t       handle,
                                const uint8_t *msg,     size_t msg_len,
                                uint8_t        sig[PQVEIL_ED25519_SIG_SZ])
{
    TEE_Result          res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    pqveil_key_entry_t *entry;
    uint32_t            sig_len = PQVEIL_ED25519_SIG_SZ;

    res = lookup_handle(handle, &entry);
    if (res != TEE_SUCCESS || entry->type != KEY_TYPE_ED25519_PRIVATE)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_AllocateOperation(&op, TEE_ALG_ED25519,
                                TEE_MODE_SIGN, 255);
    if (res != TEE_SUCCESS) return res;

    res = TEE_SetOperationKey(op, entry->tee_obj);
    if (res != TEE_SUCCESS) goto out;

    res = TEE_AsymmetricSignDigest(op, NULL, 0,
                                   (void *)msg, msg_len,
                                   sig, &sig_len);

out:
    TEE_FreeOperation(op);
    return res;
}

/*
 * crypto_ed25519_verify
 *
 * Import `pub_bytes` and verify `sig` over `msg`.
 * Returns TEE_SUCCESS if the signature is valid.
 */
TEE_Result crypto_ed25519_verify(const uint8_t  pub_bytes[PQVEIL_ED25519_PK_SZ],
                                  const uint8_t *msg,      size_t msg_len,
                                  const uint8_t  sig[PQVEIL_ED25519_SIG_SZ])
{
    TEE_Result          res;
    TEE_OperationHandle op      = TEE_HANDLE_NULL;
    TEE_ObjectHandle    pub_obj = TEE_HANDLE_NULL;
    TEE_Attribute       pub_attr;

    res = TEE_AllocateTransientObject(TEE_TYPE_ED25519, 255, &pub_obj);
    if (res != TEE_SUCCESS) return res;

    TEE_InitRefAttribute(&pub_attr, TEE_ATTR_ECC_PUBLIC_VALUE_X,
                         (void *)pub_bytes, PQVEIL_ED25519_PK_SZ);
    res = TEE_PopulateTransientObject(pub_obj, &pub_attr, 1);
    if (res != TEE_SUCCESS) goto out;

    res = TEE_AllocateOperation(&op, TEE_ALG_ED25519,
                                TEE_MODE_VERIFY, 255);
    if (res != TEE_SUCCESS) goto out;

    res = TEE_SetOperationKey(op, pub_obj);
    if (res != TEE_SUCCESS) goto out;

    res = TEE_AsymmetricVerifyDigest(op, NULL, 0,
                                     (void *)msg, msg_len,
                                     (void *)sig, PQVEIL_ED25519_SIG_SZ);

out:
    if (op      != TEE_HANDLE_NULL) TEE_FreeOperation(op);
    if (pub_obj != TEE_HANDLE_NULL) TEE_FreeTransientObject(pub_obj);
    return res;
}

/* =========================================================================
 * 8.  ChaCha20-Poly1305 (AEAD - PQ hybrid cell path)
 * ====================================================================== */

/*
 * crypto_chacha20poly1305_import_key
 *
 * Import a 32-byte symmetric key for use with ChaCha20-Poly1305 AEAD.
 * Stored as raw bytes since some GP implementations expose ChaCha as
 * TEE_TYPE_CHACHA20 while others require fallback to AES-GCM.
 */
TEE_Result crypto_chacha20poly1305_import_key(const uint8_t *key, size_t key_len,
                                               uint32_t *out_handle)
{
    TEE_Result         res;
    uint32_t           handle;
    pqveil_key_entry_t *entry;

    if (!key || key_len != PQVEIL_CHACHA_KEY_SZ || !out_handle)
        return TEE_ERROR_BAD_PARAMETERS;

    res = alloc_handle(&handle);
    if (res != TEE_SUCCESS) return res;

    entry          = &g_key_table[handle];
    entry->type    = KEY_TYPE_CHACHA20_POLY1305;
    entry->raw_len = (uint32_t)key_len;
    TEE_MemMove(entry->raw, key, key_len);

    /* Try to create a GP object if the platform supports ChaCha20 */
    {
        TEE_ObjectHandle obj = TEE_HANDLE_NULL;
        TEE_Attribute    attr;

        if (TEE_AllocateTransientObject(TEE_TYPE_CHACHA20, 256, &obj) == TEE_SUCCESS) {
            TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                                 (void *)key, key_len);
            if (TEE_PopulateTransientObject(obj, &attr, 1) == TEE_SUCCESS)
                entry->tee_obj = obj;
            else
                TEE_FreeTransientObject(obj);
        }
    }

    *out_handle = handle;
    DMSG("ChaCha20-Poly1305 key imported -> handle %u", handle);
    return TEE_SUCCESS;
}

/*
 * crypto_chacha20poly1305_seal
 *
 * AEAD encrypt.
 *   nonce   - 12 bytes
 *   aad     - additional authenticated data (may be NULL / zero length)
 *   out     - must hold in_len + PQVEIL_CHACHA_TAG_SZ bytes
 *
 * Uses the native TEE_ALG_CHACHA20_POLY1305 path when the TEE supports
 * it; falls back to AES-256-GCM otherwise.
 */
TEE_Result crypto_chacha20poly1305_seal(uint32_t       handle,
                                         const uint8_t  nonce[PQVEIL_CHACHA_NONCE_SZ],
                                         const uint8_t *aad,      size_t aad_len,
                                         const uint8_t *plaintext, size_t pt_len,
                                         uint8_t       *ciphertext, size_t *ct_len)
{
    TEE_Result          res;
    TEE_OperationHandle op     = TEE_HANDLE_NULL;
    pqveil_key_entry_t *entry;
    uint32_t            tag_len = PQVEIL_CHACHA_TAG_SZ;

    res = lookup_handle(handle, &entry);
    if (res != TEE_SUCCESS || entry->type != KEY_TYPE_CHACHA20_POLY1305)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!nonce || !plaintext || !ciphertext || !ct_len)
        return TEE_ERROR_BAD_PARAMETERS;

    if (*ct_len < pt_len + PQVEIL_CHACHA_TAG_SZ)
        return TEE_ERROR_SHORT_BUFFER;

    /* Native path */
    if (entry->tee_obj != TEE_HANDLE_NULL) {
        res = TEE_AllocateOperation(&op, TEE_ALG_CHACHA20_POLY1305,
                                    TEE_MODE_ENCRYPT, 256);
        if (res == TEE_SUCCESS) {
            res = TEE_SetOperationKey(op, entry->tee_obj);
        }
        if (res == TEE_SUCCESS) {
            res = TEE_AEInit(op, (void *)nonce, PQVEIL_CHACHA_NONCE_SZ,
                             PQVEIL_CHACHA_TAG_SZ * 8, aad_len, pt_len);
        }
        if (res == TEE_SUCCESS) {
            if (aad && aad_len)
                TEE_AEUpdateAAD(op, (void *)aad, aad_len);
            uint32_t out_data_len = (uint32_t)pt_len;
            res = TEE_AEEncryptFinal(op, (void *)plaintext, pt_len,
                                     ciphertext, &out_data_len,
                                     ciphertext + pt_len, &tag_len);
            if (res == TEE_SUCCESS)
                *ct_len = out_data_len + tag_len;
        }
        if (op != TEE_HANDLE_NULL) { TEE_FreeOperation(op); op = TEE_HANDLE_NULL; }
        if (res == TEE_SUCCESS) return TEE_SUCCESS;
        /* Fall through to AES-GCM on native path failure */
    }

    /* AES-256-GCM fallback */
    IMSG("ChaCha20 HW unavailable; using AES-256-GCM fallback (seal)");
    {
        TEE_ObjectHandle aes_obj = TEE_HANDLE_NULL;
        TEE_Attribute    attr;
        uint32_t         out_data_len = (uint32_t)pt_len;

        res = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &aes_obj);
        if (res != TEE_SUCCESS) return res;

        TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                             entry->raw, PQVEIL_CHACHA_KEY_SZ);
        res = TEE_PopulateTransientObject(aes_obj, &attr, 1);
        if (res != TEE_SUCCESS) { TEE_FreeTransientObject(aes_obj); return res; }

        res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT, 256);
        if (res != TEE_SUCCESS) { TEE_FreeTransientObject(aes_obj); return res; }

        res = TEE_SetOperationKey(op, aes_obj);
        TEE_FreeTransientObject(aes_obj);
        if (res != TEE_SUCCESS) { TEE_FreeOperation(op); return res; }

        res = TEE_AEInit(op, (void *)nonce, PQVEIL_CHACHA_NONCE_SZ,
                         PQVEIL_CHACHA_TAG_SZ * 8, aad_len, pt_len);
        if (res != TEE_SUCCESS) { TEE_FreeOperation(op); return res; }

        if (aad && aad_len)
            TEE_AEUpdateAAD(op, (void *)aad, aad_len);

        res = TEE_AEEncryptFinal(op, (void *)plaintext, pt_len,
                                 ciphertext, &out_data_len,
                                 ciphertext + pt_len, &tag_len);
        if (res == TEE_SUCCESS)
            *ct_len = out_data_len + tag_len;

        TEE_FreeOperation(op);
    }
    return res;
}

/*
 * crypto_chacha20poly1305_open
 *
 * AEAD decrypt + verify.
 *   ciphertext includes the 16-byte tag appended at the end.
 *   out must hold ct_len - PQVEIL_CHACHA_TAG_SZ bytes.
 */
TEE_Result crypto_chacha20poly1305_open(uint32_t       handle,
                                         const uint8_t  nonce[PQVEIL_CHACHA_NONCE_SZ],
                                         const uint8_t *aad,        size_t aad_len,
                                         const uint8_t *ciphertext, size_t ct_len,
                                         uint8_t       *plaintext,  size_t *pt_len)
{
    TEE_Result          res;
    TEE_OperationHandle op     = TEE_HANDLE_NULL;
    pqveil_key_entry_t *entry;
    uint32_t            tag_len = PQVEIL_CHACHA_TAG_SZ;
    size_t              data_len;

    res = lookup_handle(handle, &entry);
    if (res != TEE_SUCCESS || entry->type != KEY_TYPE_CHACHA20_POLY1305)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!nonce || !ciphertext || !plaintext || !pt_len)
        return TEE_ERROR_BAD_PARAMETERS;

    if (ct_len < PQVEIL_CHACHA_TAG_SZ)
        return TEE_ERROR_BAD_PARAMETERS;

    data_len = ct_len - PQVEIL_CHACHA_TAG_SZ;

    if (*pt_len < data_len)
        return TEE_ERROR_SHORT_BUFFER;

    /* Native path */
    if (entry->tee_obj != TEE_HANDLE_NULL) {
        res = TEE_AllocateOperation(&op, TEE_ALG_CHACHA20_POLY1305,
                                    TEE_MODE_DECRYPT, 256);
        if (res == TEE_SUCCESS)
            res = TEE_SetOperationKey(op, entry->tee_obj);
        if (res == TEE_SUCCESS)
            res = TEE_AEInit(op, (void *)nonce, PQVEIL_CHACHA_NONCE_SZ,
                             PQVEIL_CHACHA_TAG_SZ * 8, aad_len, data_len);
        if (res == TEE_SUCCESS) {
            if (aad && aad_len)
                TEE_AEUpdateAAD(op, (void *)aad, aad_len);
            uint32_t out_data_len = (uint32_t)data_len;
            res = TEE_AEDecryptFinal(op, (void *)ciphertext, data_len,
                                     plaintext, &out_data_len,
                                     (void *)(ciphertext + data_len), &tag_len);
            if (res == TEE_SUCCESS)
                *pt_len = out_data_len;
        }
        if (op != TEE_HANDLE_NULL) { TEE_FreeOperation(op); op = TEE_HANDLE_NULL; }
        if (res == TEE_SUCCESS || res == TEE_ERROR_MAC_INVALID) return res;
    }

    /* AES-256-GCM fallback */
    IMSG("ChaCha20 HW unavailable; using AES-256-GCM fallback (open)");
    {
        TEE_ObjectHandle aes_obj = TEE_HANDLE_NULL;
        TEE_Attribute    attr;
        uint32_t         out_data_len = (uint32_t)data_len;

        res = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &aes_obj);
        if (res != TEE_SUCCESS) return res;

        TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                             entry->raw, PQVEIL_CHACHA_KEY_SZ);
        res = TEE_PopulateTransientObject(aes_obj, &attr, 1);
        if (res != TEE_SUCCESS) { TEE_FreeTransientObject(aes_obj); return res; }

        res = TEE_AllocateOperation(&op, TEE_ALG_AES_GCM, TEE_MODE_DECRYPT, 256);
        if (res != TEE_SUCCESS) { TEE_FreeTransientObject(aes_obj); return res; }

        res = TEE_SetOperationKey(op, aes_obj);
        TEE_FreeTransientObject(aes_obj);
        if (res != TEE_SUCCESS) { TEE_FreeOperation(op); return res; }

        res = TEE_AEInit(op, (void *)nonce, PQVEIL_CHACHA_NONCE_SZ,
                         PQVEIL_CHACHA_TAG_SZ * 8, aad_len, data_len);
        if (res != TEE_SUCCESS) { TEE_FreeOperation(op); return res; }

        if (aad && aad_len)
            TEE_AEUpdateAAD(op, (void *)aad, aad_len);

        res = TEE_AEDecryptFinal(op, (void *)ciphertext, data_len,
                                 plaintext, &out_data_len,
                                 (void *)(ciphertext + data_len), &tag_len);
        if (res == TEE_SUCCESS)
            *pt_len = out_data_len;

        TEE_FreeOperation(op);
    }
    return res;
}

/* =========================================================================
 * 9.  ML-KEM-768  (Post-Quantum KEM, NIST FIPS 203)
 *
 * OP-TEE does not yet expose ML-KEM natively via the GP API.  Keypairs are
 * stored as raw blobs in the key table and lattice arithmetic is delegated
 * to an inlined liboqs shim linked into the TA (usepqc/).
 *
 * Shim interface (declared in crypto_service.h):
 *   int pqveil_mlkem768_keypair(uint8_t *pk, uint8_t *sk);
 *   int pqveil_mlkem768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
 *   int pqveil_mlkem768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
 * ====================================================================== */

/*
 * crypto_mlkem768_generate_keypair
 *
 *   out_pk_handle - key-table handle for the public key (to encapsulate)
 *   out_sk_handle - key-table handle for the secret key (to decapsulate)
 *   pk_out        - PQVEIL_MLKEM768_PK_SZ bytes of public key (for peer)
 */
TEE_Result crypto_mlkem768_generate_keypair(uint32_t *out_pk_handle,
                                             uint32_t *out_sk_handle,
                                             uint8_t   pk_out[PQVEIL_MLKEM768_PK_SZ])
{
    TEE_Result         res;
    uint32_t           pk_handle, sk_handle;
    pqveil_key_entry_t *pk_entry, *sk_entry;
    uint8_t            pk_buf[PQVEIL_MLKEM768_PK_SZ];
    uint8_t            sk_buf[PQVEIL_MLKEM768_SK_SZ];

    if (!out_pk_handle || !out_sk_handle || !pk_out)
        return TEE_ERROR_BAD_PARAMETERS;

    res = alloc_handle(&pk_handle);
    if (res != TEE_SUCCESS) return res;

    res = alloc_handle(&sk_handle);
    if (res != TEE_SUCCESS) {
        g_key_table[pk_handle].in_use = false;
        return res;
    }

    if (pqveil_mlkem768_keypair(pk_buf, sk_buf) != 0) {
        res = TEE_ERROR_GENERIC;
        goto err;
    }

    pk_entry          = &g_key_table[pk_handle];
    pk_entry->type    = KEY_TYPE_MLKEM768_PUBLIC;
    pk_entry->raw_len = PQVEIL_MLKEM768_PK_SZ;
    TEE_MemMove(pk_entry->raw, pk_buf, PQVEIL_MLKEM768_PK_SZ);

    sk_entry          = &g_key_table[sk_handle];
    sk_entry->type    = KEY_TYPE_MLKEM768_PRIVATE;
    sk_entry->raw_len = PQVEIL_MLKEM768_SK_SZ;
    TEE_MemMove(sk_entry->raw, sk_buf, PQVEIL_MLKEM768_SK_SZ);

    TEE_MemMove(pk_out, pk_buf, PQVEIL_MLKEM768_PK_SZ);
    *out_pk_handle = pk_handle;
    *out_sk_handle = sk_handle;

    DMSG("ML-KEM-768 keypair generated -> pk=%u sk=%u", pk_handle, sk_handle);
    res = TEE_SUCCESS;
    goto done;

err:
    g_key_table[pk_handle].in_use = false;
    g_key_table[sk_handle].in_use = false;

done:
    secure_zero(sk_buf, sizeof(sk_buf));
    return res;
}

/*
 * crypto_mlkem768_encapsulate
 *
 *   pk_handle - handle of recipient public key stored in the key table
 *   ct_out    - PQVEIL_MLKEM768_CT_SZ bytes (send to peer)
 *   ss_out    - PQVEIL_MLKEM768_SS_SZ bytes shared secret (stays in TA)
 */
TEE_Result crypto_mlkem768_encapsulate(uint32_t pk_handle,
                                        uint8_t  ct_out[PQVEIL_MLKEM768_CT_SZ],
                                        uint8_t  ss_out[PQVEIL_MLKEM768_SS_SZ])
{
    TEE_Result         res;
    pqveil_key_entry_t *entry;

    res = lookup_handle(pk_handle, &entry);
    if (res != TEE_SUCCESS || entry->type != KEY_TYPE_MLKEM768_PUBLIC)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!ct_out || !ss_out)
        return TEE_ERROR_BAD_PARAMETERS;

    if (pqveil_mlkem768_enc(ct_out, ss_out, entry->raw) != 0)
        return TEE_ERROR_GENERIC;

    DMSG("ML-KEM-768 encapsulate complete");
    return TEE_SUCCESS;
}

/*
 * crypto_mlkem768_decapsulate
 *
 *   sk_handle - handle of our secret key
 *   ct        - PQVEIL_MLKEM768_CT_SZ bytes from peer
 *   ss_out    - PQVEIL_MLKEM768_SS_SZ bytes recovered shared secret
 */
TEE_Result crypto_mlkem768_decapsulate(uint32_t      sk_handle,
                                        const uint8_t ct[PQVEIL_MLKEM768_CT_SZ],
                                        uint8_t       ss_out[PQVEIL_MLKEM768_SS_SZ])
{
    TEE_Result         res;
    pqveil_key_entry_t *entry;

    res = lookup_handle(sk_handle, &entry);
    if (res != TEE_SUCCESS || entry->type != KEY_TYPE_MLKEM768_PRIVATE)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!ct || !ss_out)
        return TEE_ERROR_BAD_PARAMETERS;

    if (pqveil_mlkem768_dec(ss_out, ct, entry->raw) != 0)
        return TEE_ERROR_GENERIC;

    DMSG("ML-KEM-768 decapsulate complete");
    return TEE_SUCCESS;
}

/* =========================================================================
 * 10.  PQ-Hybrid Key Derivation
 *
 * Combines a classical X25519 shared secret with an ML-KEM-768 shared
 * secret into session keying material using HKDF-SHA256.
 *
 *   IKM  = x25519_ss (32) || mlkem_ss (32)
 *   salt = ntor key seed or caller-provided (may be NULL)
 *   info = "pqveil-hybrid-v1"
 *   OKM  = out_len bytes
 * ====================================================================== */

#define PQVEIL_HYBRID_INFO     "pqveil-hybrid-v1"
#define PQVEIL_HYBRID_INFO_LEN 16u

TEE_Result crypto_hybrid_kdf(const uint8_t x25519_ss[PQVEIL_X25519_SCALAR_SZ],
                              const uint8_t mlkem_ss[PQVEIL_MLKEM768_SS_SZ],
                              const uint8_t *salt, size_t salt_len,
                              uint8_t *okm,        size_t out_len)
{
    TEE_Result res;
    uint8_t    ikm[PQVEIL_X25519_SCALAR_SZ + PQVEIL_MLKEM768_SS_SZ];

    if (!x25519_ss || !mlkem_ss || !okm || out_len == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_MemMove(ikm, x25519_ss, PQVEIL_X25519_SCALAR_SZ);
    TEE_MemMove(ikm + PQVEIL_X25519_SCALAR_SZ, mlkem_ss, PQVEIL_MLKEM768_SS_SZ);

    res = crypto_hkdf_sha256(ikm, sizeof(ikm),
                              salt, salt_len,
                              (const uint8_t *)PQVEIL_HYBRID_INFO,
                              PQVEIL_HYBRID_INFO_LEN,
                              okm, out_len);

    secure_zero(ikm, sizeof(ikm));
    return res;
}

/* =========================================================================
 * 11.  Tor cell-layer key material expansion (tor-spec §5.2.2)
 *
 * Given the KEY_SEED produced by the ntor handshake, expand into the
 * four symmetric keys that Tor uses for a circuit leg:
 *
 *   Df  – 20-byte forward digest seed   (SHA-1 based running digest)
 *   Db  – 20-byte backward digest seed
 *   Kf  – 16-byte forward AES-128-CTR  key  (upgraded to 32-byte AES-256)
 *   Kb  – 16-byte backward AES-128-CTR key
 *
 * We extend the spec slightly: when using the PQ hybrid path we derive
 * 32-byte AES-256 keys instead of 16-byte AES-128 keys.
 * ====================================================================== */

#define TOR_KDF_DF_OFF    0u
#define TOR_KDF_DB_OFF   20u
#define TOR_KDF_KF_OFF   40u
#define TOR_KDF_KB_OFF   72u
#define TOR_KDF_TOTAL   104u   /* Df(20) + Db(20) + Kf(32) + Kb(32) */

/* pqveil_circuit_keys_t is declared in crypto_service.h */

TEE_Result crypto_derive_circuit_keys(const uint8_t key_seed[NTOR_KEY_SEED_LEN],
                                       pqveil_circuit_keys_t *keys_out)
{
    TEE_Result res;
    uint8_t    okm[TOR_KDF_TOTAL];

    if (!key_seed || !keys_out)
        return TEE_ERROR_BAD_PARAMETERS;

    /*
     * KDF: HKDF-SHA256(IKM=key_seed, salt=nil, info=T_EXPAND)
     * (tor-spec §5.2.2 uses KDF-RFC5869)
     */
    res = crypto_hkdf_sha256(key_seed, NTOR_KEY_SEED_LEN,
                              NULL, 0,
                              (const uint8_t *)NTOR_T_EXPAND,
                              sizeof(NTOR_T_EXPAND) - 1,
                              okm, TOR_KDF_TOTAL);
    if (res != TEE_SUCCESS)
        goto out;

    TEE_MemMove(keys_out->Df, okm + TOR_KDF_DF_OFF, 20);
    TEE_MemMove(keys_out->Db, okm + TOR_KDF_DB_OFF, 20);
    TEE_MemMove(keys_out->Kf, okm + TOR_KDF_KF_OFF, 32);
    TEE_MemMove(keys_out->Kb, okm + TOR_KDF_KB_OFF, 32);

out:
    secure_zero(okm, sizeof(okm));
    return res;
}

/* =========================================================================
 * 12.  Key-table management
 * ====================================================================== */

TEE_Result crypto_free_key(uint32_t handle)
{
    pqveil_key_entry_t *entry;
    TEE_Result          res;

    res = lookup_handle(handle, &entry);
    if (res != TEE_SUCCESS)
        return res;

    if (entry->tee_obj != TEE_HANDLE_NULL) {
        TEE_FreeTransientObject(entry->tee_obj);
        entry->tee_obj = TEE_HANDLE_NULL;
    }

    secure_zero(entry->raw, entry->raw_len);
    TEE_MemFill(entry, 0, sizeof(pqveil_key_entry_t));
    /* in_use is now false after the MemFill */
    DMSG("Key handle %u freed", handle);
    return TEE_SUCCESS;
}

