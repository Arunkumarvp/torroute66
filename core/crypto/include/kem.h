/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil Crypto Engine – Key Encapsulation Mechanism (ML-KEM-768)
 * Conforming to NIST FIPS 203 parameters.
 */

#ifndef PQVEIL_CRYPTO_KEM_H
#define PQVEIL_CRYPTO_KEM_H

#include <stdint.h>
#include <stddef.h>

#define PQVEIL_KEM_ALGORITHM_NAME     "ML-KEM-768"
#define PQVEIL_KEM_PUBLIC_KEY_BYTES   1184
#define PQVEIL_KEM_SECRET_KEY_BYTES   2400
#define PQVEIL_KEM_CIPHERTEXT_BYTES   1088
#define PQVEIL_KEM_SHARED_SECRET_BYTES 32
#define PQVEIL_KEM_SEED_BYTES         64

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate an ML-KEM-768 keypair from entropy.
 */
int pqveil_kem_keypair(uint8_t pk[PQVEIL_KEM_PUBLIC_KEY_BYTES],
                       uint8_t sk[PQVEIL_KEM_SECRET_KEY_BYTES]);

/**
 * Generate an ML-KEM-768 keypair deterministically from a 64-byte seed (d || z).
 */
int pqveil_kem_keypair_from_seed(uint8_t pk[PQVEIL_KEM_PUBLIC_KEY_BYTES],
                                uint8_t sk[PQVEIL_KEM_SECRET_KEY_BYTES],
                                const uint8_t seed[PQVEIL_KEM_SEED_BYTES]);

/**
 * Encapsulate against peer public key, producing ciphertext and shared secret.
 */
int pqveil_kem_encaps(uint8_t ct[PQVEIL_KEM_CIPHERTEXT_BYTES],
                      uint8_t ss[PQVEIL_KEM_SHARED_SECRET_BYTES],
                      const uint8_t pk[PQVEIL_KEM_PUBLIC_KEY_BYTES]);

/**
 * Decapsulate ciphertext using secret key, recovering shared secret.
 */
int pqveil_kem_decaps(uint8_t ss[PQVEIL_KEM_SHARED_SECRET_BYTES],
                      const uint8_t ct[PQVEIL_KEM_CIPHERTEXT_BYTES],
                      const uint8_t sk[PQVEIL_KEM_SECRET_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* PQVEIL_CRYPTO_KEM_H */

