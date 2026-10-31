/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil Crypto Engine – Authenticated Encryption & Key Agreement
 * Implements ChaCha20-Poly1305 (RFC 8439), X25519 (RFC 7748), and HKDF-SHA3-256.
 */

#ifndef PQVEIL_CRYPTO_AEAD_H
#define PQVEIL_CRYPTO_AEAD_H

#include <stdint.h>
#include <stddef.h>

#define PQVEIL_CHACHA20_KEY_BYTES    32
#define PQVEIL_CHACHA20_NONCE_BYTES  12
#define PQVEIL_POLY1305_TAG_BYTES    16
#define PQVEIL_X25519_KEY_BYTES      32
#define PQVEIL_SHA3_256_DIGEST_BYTES 32

#ifdef __cplusplus
extern "C" {
#endif

/* --- X25519 Diffie-Hellman --- */
int pqveil_x25519_keypair(uint8_t public_key[PQVEIL_X25519_KEY_BYTES],
                          uint8_t private_key[PQVEIL_X25519_KEY_BYTES]);

int pqveil_x25519_scalarmult(uint8_t shared_secret[PQVEIL_X25519_KEY_BYTES],
                             const uint8_t private_key[PQVEIL_X25519_KEY_BYTES],
                             const uint8_t peer_public_key[PQVEIL_X25519_KEY_BYTES]);

/* --- HKDF-SHA3-256 --- */
int pqveil_hkdf_sha3_256(const uint8_t *ikm, size_t ikm_len,
                         const uint8_t *salt, size_t salt_len,
                         const uint8_t *info, size_t info_len,
                         uint8_t *okm, size_t okm_len);

/* --- ChaCha20-Poly1305 AEAD --- */
int pqveil_aead_seal(uint8_t *ciphertext_out,
                     uint8_t tag_out[PQVEIL_POLY1305_TAG_BYTES],
                     const uint8_t *plaintext, size_t pt_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t nonce[PQVEIL_CHACHA20_NONCE_BYTES],
                     const uint8_t key[PQVEIL_CHACHA20_KEY_BYTES]);

int pqveil_aead_open(uint8_t *plaintext_out,
                     const uint8_t *ciphertext, size_t ct_len,
                     const uint8_t tag[PQVEIL_POLY1305_TAG_BYTES],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t nonce[PQVEIL_CHACHA20_NONCE_BYTES],
                     const uint8_t key[PQVEIL_CHACHA20_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* PQVEIL_CRYPTO_AEAD_H */

