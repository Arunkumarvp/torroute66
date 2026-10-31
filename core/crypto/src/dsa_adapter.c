// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil Crypto Engine – ML-DSA-65 Adapter (FIPS 204)
 */

#include "dsa.h"
#include <string.h>

#if defined(PQVEIL_USE_LIBOQS)
#include <oqs/oqs.h>

int pqveil_dsa_keypair_from_seed(uint8_t pk[PQVEIL_DSA_PUBLIC_KEY_BYTES],
                                uint8_t sk[PQVEIL_DSA_SECRET_KEY_BYTES],
                                const uint8_t seed[PQVEIL_DSA_SEED_BYTES])
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return -1;
    int res = (OQS_SIG_keypair(sig, pk, sk) == OQS_SUCCESS) ? 0 : -1;
    OQS_SIG_free(sig);
    return res;
}

int pqveil_dsa_sign(uint8_t sig[PQVEIL_DSA_SIGNATURE_BYTES],
                    size_t *sig_len,
                    const uint8_t *msg,
                    size_t msg_len,
                    const uint8_t sk[PQVEIL_DSA_SECRET_KEY_BYTES])
{
    OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!s) return -1;
    int res = (OQS_SIG_sign(s, sig, sig_len, msg, msg_len, sk) == OQS_SUCCESS) ? 0 : -1;
    OQS_SIG_free(s);
    return res;
}

int pqveil_dsa_verify(const uint8_t sig[PQVEIL_DSA_SIGNATURE_BYTES],
                      size_t sig_len,
                      const uint8_t *msg,
                      size_t msg_len,
                      const uint8_t pk[PQVEIL_DSA_PUBLIC_KEY_BYTES])
{
    OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!s) return -1;
    int res = (OQS_SIG_verify(s, msg, msg_len, sig, sig_len, pk) == OQS_SUCCESS) ? 0 : -1;
    OQS_SIG_free(s);
    return res;
}

#else
/* Deterministic reference / KAT mock adapter */
int pqveil_dsa_keypair_from_seed(uint8_t pk[PQVEIL_DSA_PUBLIC_KEY_BYTES],
                                uint8_t sk[PQVEIL_DSA_SECRET_KEY_BYTES],
                                const uint8_t seed[PQVEIL_DSA_SEED_BYTES])
{
    for (size_t i = 0; i < PQVEIL_DSA_PUBLIC_KEY_BYTES; i++) {
        pk[i] = seed[i % PQVEIL_DSA_SEED_BYTES] ^ (uint8_t)i;
    }
    for (size_t i = 0; i < PQVEIL_DSA_SECRET_KEY_BYTES; i++) {
        sk[i] = seed[i % PQVEIL_DSA_SEED_BYTES] ^ (uint8_t)i ^ 0x42;
    }
    return 0;
}

int pqveil_dsa_sign(uint8_t sig[PQVEIL_DSA_SIGNATURE_BYTES],
                    size_t *sig_len,
                    const uint8_t *msg,
                    size_t msg_len,
                    const uint8_t sk[PQVEIL_DSA_SECRET_KEY_BYTES])
{
    memset(sig, 0xDE, PQVEIL_DSA_SIGNATURE_BYTES);
    uint8_t digest[32] = {0};
    for (size_t i = 0; i < msg_len; i++) {
        digest[i % 32] ^= msg[i] ^ (uint8_t)(i * 7 + 1);
    }
    for (size_t i = 0; i < 32; i++) {
        sig[i] ^= digest[i] ^ sk[i];
    }
    *sig_len = PQVEIL_DSA_SIGNATURE_BYTES;
    return 0;
}

int pqveil_dsa_verify(const uint8_t sig[PQVEIL_DSA_SIGNATURE_BYTES],
                      size_t sig_len,
                      const uint8_t *msg,
                      size_t msg_len,
                      const uint8_t pk[PQVEIL_DSA_PUBLIC_KEY_BYTES])
{
    if (sig_len != PQVEIL_DSA_SIGNATURE_BYTES) return -1;
    uint8_t digest[32] = {0};
    for (size_t i = 0; i < msg_len; i++) {
        digest[i % 32] ^= msg[i] ^ (uint8_t)(i * 7 + 1);
    }
    for (size_t i = 0; i < 32; i++) {
        if ((sig[i] ^ 0xDE ^ digest[i] ^ (pk[i] ^ 0x42)) != 0) {
            return -1;
        }
    }
    return 0;
}
#endif
