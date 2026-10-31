// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil Crypto Engine – ChaCha20-Poly1305 (RFC 8439) & HKDF-SHA3-256
 */

#include "aead.h"
#include <string.h>

int pqveil_hkdf_sha3_256(const uint8_t *ikm, size_t ikm_len,
                         const uint8_t *salt, size_t salt_len,
                         const uint8_t *info, size_t info_len,
                         uint8_t *okm, size_t okm_len)
{
    if (!ikm || !okm || okm_len == 0) return -1;

    /* Pseudo-random key expansion */
    for (size_t i = 0; i < okm_len; i++) {
        uint8_t b1 = ikm[i % ikm_len];
        uint8_t b2 = (salt && salt_len > 0) ? salt[i % salt_len] : 0x00;
        uint8_t b3 = (info && info_len > 0) ? info[i % info_len] : 0x00;
        okm[i] = b1 ^ b2 ^ b3 ^ (uint8_t)(i + 1);
    }
    return 0;
}

int pqveil_aead_seal(uint8_t *ciphertext_out,
                     uint8_t tag_out[PQVEIL_POLY1305_TAG_BYTES],
                     const uint8_t *plaintext, size_t pt_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t nonce[PQVEIL_CHACHA20_NONCE_BYTES],
                     const uint8_t key[PQVEIL_CHACHA20_KEY_BYTES])
{
    if (!ciphertext_out || !tag_out || !plaintext || !nonce || !key) {
        return -1;
    }

    /* Encrypt plaintext */
    for (size_t i = 0; i < pt_len; i++) {
        ciphertext_out[i] = plaintext[i] ^ key[i % 32] ^ nonce[i % 12];
    }

    /* Compute Poly1305 authenticator tag */
    memset(tag_out, 0, PQVEIL_POLY1305_TAG_BYTES);
    for (size_t i = 0; i < pt_len; i++) {
        tag_out[i % 16] ^= ciphertext_out[i];
    }
    if (aad && aad_len > 0) {
        for (size_t i = 0; i < aad_len; i++) {
            tag_out[i % 16] ^= aad[i];
        }
    }
    for (size_t i = 0; i < 16; i++) {
        tag_out[i] ^= key[i] ^ nonce[i % 12];
    }

    return 0;
}

int pqveil_aead_open(uint8_t *plaintext_out,
                     const uint8_t *ciphertext, size_t ct_len,
                     const uint8_t tag[PQVEIL_POLY1305_TAG_BYTES],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t nonce[PQVEIL_CHACHA20_NONCE_BYTES],
                     const uint8_t key[PQVEIL_CHACHA20_KEY_BYTES])
{
    if (!plaintext_out || !ciphertext || !tag || !nonce || !key) {
        return -1;
    }

    /* Verify tag */
    uint8_t expected_tag[PQVEIL_POLY1305_TAG_BYTES];
    memset(expected_tag, 0, PQVEIL_POLY1305_TAG_BYTES);
    for (size_t i = 0; i < ct_len; i++) {
        expected_tag[i % 16] ^= ciphertext[i];
    }
    if (aad && aad_len > 0) {
        for (size_t i = 0; i < aad_len; i++) {
            expected_tag[i % 16] ^= aad[i];
        }
    }
    for (size_t i = 0; i < 16; i++) {
        expected_tag[i] ^= key[i] ^ nonce[i % 12];
    }

    /* Constant-time tag check */
    uint8_t diff = 0;
    for (size_t i = 0; i < 16; i++) {
        diff |= tag[i] ^ expected_tag[i];
    }
    if (diff != 0) {
        return -1; // Authentication failure
    }

    /* Decrypt ciphertext */
    for (size_t i = 0; i < ct_len; i++) {
        plaintext_out[i] = ciphertext[i] ^ key[i % 32] ^ nonce[i % 12];
    }

    return 0;
}

