/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil TEE – Tor Crypto Services: public header
 *
 * All functions operate entirely inside secure world.  Key handles are
 * 32-bit opaque tokens valid only for the lifetime of the TA session.
 */

#ifndef PQVEIL_CRYPTO_SERVICE_H
#define PQVEIL_CRYPTO_SERVICE_H

#include <tee_internal_api.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* -------------------------------------------------------------------------
 * Size constants (mirrors the .c definitions; safe to include by host code)
 * ---------------------------------------------------------------------- */

#define PQVEIL_SHA256_SZ         32u
#define PQVEIL_HMAC_SZ           32u
#define PQVEIL_AES_BLOCK_SZ      16u
#define PQVEIL_CHACHA_NONCE_SZ   12u
#define PQVEIL_CHACHA_TAG_SZ     16u
#define PQVEIL_X25519_SCALAR_SZ  32u
#define PQVEIL_X25519_POINT_SZ   32u
#define PQVEIL_ED25519_PK_SZ     32u
#define PQVEIL_ED25519_SIG_SZ    64u
#define PQVEIL_MLKEM768_PK_SZ    1184u
#define PQVEIL_MLKEM768_SK_SZ    2400u
#define PQVEIL_MLKEM768_CT_SZ    1088u
#define PQVEIL_MLKEM768_SS_SZ    32u

/* ntor key-material sizes */
#define NTOR_KEY_SEED_LEN        PQVEIL_SHA256_SZ
#define NTOR_AUTH_LEN            PQVEIL_SHA256_SZ
#define NTOR_PROTOID             "ntor-curve25519-sha256-1"
#define NTOR_PROTOID_LEN         24u

/* -------------------------------------------------------------------------
 * Circuit key bundle (output of crypto_derive_circuit_keys)
 * ---------------------------------------------------------------------- */

typedef struct {
    uint8_t Df[20];   /* forward  digest seed  */
    uint8_t Db[20];   /* backward digest seed  */
    uint8_t Kf[32];   /* forward  AES-256 cell key */
    uint8_t Kb[32];   /* backward AES-256 cell key */
} pqveil_circuit_keys_t;

/* -------------------------------------------------------------------------
 * liboqs shim interface (implemented in usepqc/)
 * The TA links against these at build time.
 * ---------------------------------------------------------------------- */

int pqveil_mlkem768_keypair(uint8_t *pk, uint8_t *sk);
int pqveil_mlkem768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqveil_mlkem768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* =========================================================================
 * Lifecycle
 * ====================================================================== */

TEE_Result crypto_service_init(void);
void       crypto_service_destroy(void);

/* =========================================================================
 * Key-table management
 * ====================================================================== */

TEE_Result crypto_free_key(uint32_t handle);

/* =========================================================================
 * 1. AES-256-CTR  (Tor relay cell stream cipher)
 * ====================================================================== */

TEE_Result crypto_aes256ctr_import_key(const uint8_t *key, size_t key_len,
                                        uint32_t *out_handle);

TEE_Result crypto_aes256ctr_crypt(uint32_t handle,
                                   const uint8_t *iv,  size_t iv_len,
                                   const uint8_t *in,  size_t in_len,
                                   uint8_t       *out, size_t *out_len);

/* =========================================================================
 * 2. SHA-256
 * ====================================================================== */

TEE_Result crypto_sha256(const uint8_t *data, size_t data_len,
                          uint8_t out[PQVEIL_SHA256_SZ]);

/* =========================================================================
 * 3. HMAC-SHA256
 * ====================================================================== */

TEE_Result crypto_hmac_sha256_import_key(const uint8_t *key, size_t key_len,
                                          uint32_t *out_handle);

TEE_Result crypto_hmac_sha256(uint32_t key_handle,
                               const uint8_t *data, size_t data_len,
                               uint8_t out[PQVEIL_HMAC_SZ]);

/* =========================================================================
 * 4. HKDF-SHA256  (RFC 5869)
 * ====================================================================== */

TEE_Result crypto_hkdf_sha256(const uint8_t *ikm,  size_t ikm_len,
                               const uint8_t *salt, size_t salt_len,
                               const uint8_t *info, size_t info_len,
                               uint8_t *okm,        size_t out_len);

/* =========================================================================
 * 5. X25519  (ntor ephemeral DH)
 * ====================================================================== */

TEE_Result crypto_x25519_generate_keypair(uint32_t *out_handle,
                                           uint8_t   pub[PQVEIL_X25519_POINT_SZ]);

TEE_Result crypto_x25519_derive_shared(uint32_t      priv_handle,
                                        const uint8_t peer_pub[PQVEIL_X25519_POINT_SZ],
                                        uint8_t       shared[PQVEIL_X25519_SCALAR_SZ]);

/* =========================================================================
 * 6. ntor Handshake  (tor-spec §5.1.4)
 * ====================================================================== */

TEE_Result crypto_ntor_client_handshake(
        const uint8_t  router_id[20],
        const uint8_t  router_B[PQVEIL_X25519_POINT_SZ],
        const uint8_t  router_Y[PQVEIL_X25519_POINT_SZ],
        uint8_t        our_X_pub[PQVEIL_X25519_POINT_SZ],
        uint8_t        key_seed[NTOR_KEY_SEED_LEN],
        uint8_t        auth_out[NTOR_AUTH_LEN]);

TEE_Result crypto_ntor_server_handshake(
        const uint8_t  router_id[20],
        uint32_t       long_term_b_handle,
        const uint8_t  router_B_pub[PQVEIL_X25519_POINT_SZ],
        const uint8_t  client_X[PQVEIL_X25519_POINT_SZ],
        uint8_t        our_Y_pub[PQVEIL_X25519_POINT_SZ],
        uint8_t        key_seed[NTOR_KEY_SEED_LEN],
        uint8_t        auth_out[NTOR_AUTH_LEN]);

TEE_Result crypto_ntor_verify_auth(const uint8_t expected[NTOR_AUTH_LEN],
                                    const uint8_t received[NTOR_AUTH_LEN]);

/* =========================================================================
 * 7. Ed25519  (relay identity)
 * ====================================================================== */

TEE_Result crypto_ed25519_generate_keypair(uint32_t *out_handle,
                                            uint8_t   pub[PQVEIL_ED25519_PK_SZ]);

TEE_Result crypto_ed25519_sign(uint32_t       handle,
                                const uint8_t *msg,     size_t msg_len,
                                uint8_t        sig[PQVEIL_ED25519_SIG_SZ]);

TEE_Result crypto_ed25519_verify(const uint8_t  pub_bytes[PQVEIL_ED25519_PK_SZ],
                                  const uint8_t *msg,      size_t msg_len,
                                  const uint8_t  sig[PQVEIL_ED25519_SIG_SZ]);

/* =========================================================================
 * 8. ChaCha20-Poly1305  (AEAD – PQ hybrid cell path)
 * ====================================================================== */

TEE_Result crypto_chacha20poly1305_import_key(const uint8_t *key, size_t key_len,
                                               uint32_t *out_handle);

TEE_Result crypto_chacha20poly1305_seal(uint32_t       handle,
                                         const uint8_t  nonce[PQVEIL_CHACHA_NONCE_SZ],
                                         const uint8_t *aad,       size_t aad_len,
                                         const uint8_t *plaintext, size_t pt_len,
                                         uint8_t       *ciphertext, size_t *ct_len);

TEE_Result crypto_chacha20poly1305_open(uint32_t       handle,
                                         const uint8_t  nonce[PQVEIL_CHACHA_NONCE_SZ],
                                         const uint8_t *aad,        size_t aad_len,
                                         const uint8_t *ciphertext, size_t ct_len,
                                         uint8_t       *plaintext,  size_t *pt_len);

/* =========================================================================
 * 9. ML-KEM-768  (NIST FIPS 203 post-quantum KEM)
 * ====================================================================== */

TEE_Result crypto_mlkem768_generate_keypair(uint32_t *out_pk_handle,
                                             uint32_t *out_sk_handle,
                                             uint8_t   pk_out[PQVEIL_MLKEM768_PK_SZ]);

TEE_Result crypto_mlkem768_encapsulate(uint32_t pk_handle,
                                        uint8_t  ct_out[PQVEIL_MLKEM768_CT_SZ],
                                        uint8_t  ss_out[PQVEIL_MLKEM768_SS_SZ]);

TEE_Result crypto_mlkem768_decapsulate(uint32_t      sk_handle,
                                        const uint8_t ct[PQVEIL_MLKEM768_CT_SZ],
                                        uint8_t       ss_out[PQVEIL_MLKEM768_SS_SZ]);

/* =========================================================================
 * 10. PQ-Hybrid KDF
 *     IKM = x25519_ss || mlkem_ss  →  HKDF-SHA256  →  okm
 * ====================================================================== */

TEE_Result crypto_hybrid_kdf(const uint8_t x25519_ss[PQVEIL_X25519_SCALAR_SZ],
                              const uint8_t mlkem_ss[PQVEIL_MLKEM768_SS_SZ],
                              const uint8_t *salt, size_t salt_len,
                              uint8_t *okm,        size_t out_len);

/* =========================================================================
 * 11. Tor circuit key expansion  (tor-spec §5.2.2, extended to AES-256)
 * ====================================================================== */

TEE_Result crypto_derive_circuit_keys(const uint8_t key_seed[NTOR_KEY_SEED_LEN],
                                       pqveil_circuit_keys_t *keys_out);

#endif /* PQVEIL_CRYPTO_SERVICE_H */

