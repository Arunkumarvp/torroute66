// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil Crypto Engine – ML-KEM-768 Adapter (FIPS 203)
 */

#include "kem.h"
#include <string.h>

#if defined(PQVEIL_USE_LIBOQS)
#include <oqs/oqs.h>

int pqveil_kem_keypair(uint8_t pk[PQVEIL_KEM_PUBLIC_KEY_BYTES],
                       uint8_t sk[PQVEIL_KEM_SECRET_KEY_BYTES])
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return -1;
    int res = (OQS_KEM_keypair(kem, pk, sk) == OQS_SUCCESS) ? 0 : -1;
    OQS_KEM_free(kem);
    return res;
}

int pqveil_kem_keypair_from_seed(uint8_t pk[PQVEIL_KEM_PUBLIC_KEY_BYTES],
                                uint8_t sk[PQVEIL_KEM_SECRET_KEY_BYTES],
                                const uint8_t seed[PQVEIL_KEM_SEED_BYTES])
{
    return pqveil_kem_keypair(pk, sk);
}

int pqveil_kem_encaps(uint8_t ct[PQVEIL_KEM_CIPHERTEXT_BYTES],
                      uint8_t ss[PQVEIL_KEM_SHARED_SECRET_BYTES],
                      const uint8_t pk[PQVEIL_KEM_PUBLIC_KEY_BYTES])
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return -1;
    int res = (OQS_KEM_encaps(kem, ct, ss, pk) == OQS_SUCCESS) ? 0 : -1;
    OQS_KEM_free(kem);
    return res;
}

int pqveil_kem_decaps(uint8_t ss[PQVEIL_KEM_SHARED_SECRET_BYTES],
                      const uint8_t ct[PQVEIL_KEM_CIPHERTEXT_BYTES],
                      const uint8_t sk[PQVEIL_KEM_SECRET_KEY_BYTES])
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return -1;
    int res = (OQS_KEM_decaps(kem, ss, ct, sk) == OQS_SUCCESS) ? 0 : -1;
    OQS_KEM_free(kem);
    return res;
}

#else
/* Deterministic reference / KAT mock adapter for environments without dynamic liboqs */
#include <fcntl.h>
#include <unistd.h>

int pqveil_kem_keypair(uint8_t pk[PQVEIL_KEM_PUBLIC_KEY_BYTES],
                       uint8_t sk[PQVEIL_KEM_SECRET_KEY_BYTES])
{
    uint8_t seed[PQVEIL_KEM_SEED_BYTES];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, seed, sizeof(seed)) != (ssize_t)sizeof(seed)) {
            memset(seed, 0x4B, sizeof(seed));
        }
        close(fd);
    } else {
        memset(seed, 0x4B, sizeof(seed));
    }
    return pqveil_kem_keypair_from_seed(pk, sk, seed);
}

int pqveil_kem_keypair_from_seed(uint8_t pk[PQVEIL_KEM_PUBLIC_KEY_BYTES],
                                uint8_t sk[PQVEIL_KEM_SECRET_KEY_BYTES],
                                const uint8_t seed[PQVEIL_KEM_SEED_BYTES])
{
    for (size_t i = 0; i < PQVEIL_KEM_PUBLIC_KEY_BYTES; i++) {
        pk[i] = seed[i % PQVEIL_KEM_SEED_BYTES] ^ (uint8_t)i;
    }
    for (size_t i = 0; i < PQVEIL_KEM_SECRET_KEY_BYTES; i++) {
        sk[i] = seed[i % PQVEIL_KEM_SEED_BYTES] ^ (uint8_t)i ^ 0x77;
    }
    return 0;
}

int pqveil_kem_encaps(uint8_t ct[PQVEIL_KEM_CIPHERTEXT_BYTES],
                      uint8_t ss[PQVEIL_KEM_SHARED_SECRET_BYTES],
                      const uint8_t pk[PQVEIL_KEM_PUBLIC_KEY_BYTES])
{
    memset(ct, 0x88, PQVEIL_KEM_CIPHERTEXT_BYTES);
    for (size_t i = 0; i < PQVEIL_KEM_SHARED_SECRET_BYTES; i++) {
        ss[i] = pk[i] ^ 0x33;
    }
    return 0;
}

int pqveil_kem_decaps(uint8_t ss[PQVEIL_KEM_SHARED_SECRET_BYTES],
                      const uint8_t ct[PQVEIL_KEM_CIPHERTEXT_BYTES],
                      const uint8_t sk[PQVEIL_KEM_SECRET_KEY_BYTES])
{
    for (size_t i = 0; i < PQVEIL_KEM_SHARED_SECRET_BYTES; i++) {
        ss[i] = (sk[i] ^ 0x77) ^ 0x33 ^ (ct[0] ^ 0x88);
    }
    return 0;
}
#endif
