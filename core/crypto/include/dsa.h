/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil Crypto Engine – Digital Signature Algorithm (ML-DSA-65)
 * Conforming to NIST FIPS 204 parameters.
 */

#ifndef PQVEIL_CRYPTO_DSA_H
#define PQVEIL_CRYPTO_DSA_H

#include <stdint.h>
#include <stddef.h>

#define PQVEIL_DSA_ALGORITHM_NAME     "ML-DSA-65"
#define PQVEIL_DSA_PUBLIC_KEY_BYTES   2592
#define PQVEIL_DSA_SECRET_KEY_BYTES   4032
#define PQVEIL_DSA_SIGNATURE_BYTES    3309
#define PQVEIL_DSA_SEED_BYTES         32

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate an ML-DSA-65 keypair deterministically from a 32-byte seed (xi).
 */
int pqveil_dsa_keypair_from_seed(uint8_t pk[PQVEIL_DSA_PUBLIC_KEY_BYTES],
                                uint8_t sk[PQVEIL_DSA_SECRET_KEY_BYTES],
                                const uint8_t seed[PQVEIL_DSA_SEED_BYTES]);

/**
 * Sign a message with domain separation using the ML-DSA-65 secret key.
 */
int pqveil_dsa_sign(uint8_t sig[PQVEIL_DSA_SIGNATURE_BYTES],
                    size_t *sig_len,
                    const uint8_t *msg,
                    size_t msg_len,
                    const uint8_t sk[PQVEIL_DSA_SECRET_KEY_BYTES]);

/**
 * Verify an ML-DSA-65 signature against the message and public key.
 * Returns 0 on valid signature, non-zero on failure.
 */
int pqveil_dsa_verify(const uint8_t sig[PQVEIL_DSA_SIGNATURE_BYTES],
                      size_t sig_len,
                      const uint8_t *msg,
                      size_t msg_len,
                      const uint8_t pk[PQVEIL_DSA_PUBLIC_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* PQVEIL_CRYPTO_DSA_H */

