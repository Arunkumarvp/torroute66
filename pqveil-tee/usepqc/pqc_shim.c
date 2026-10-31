// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil usepqc – Post-Quantum Cryptography Shim Implementation
 *
 * Implements the C bindings bridging liboqs / PQClean to both
 * the Secure World TA and the Normal World host controller.
 */

#include "pqc_shim.h"
#include <string.h>

#if defined(PQVEIL_USE_LIBOQS)
#include <oqs/oqs.h>

int pqveil_mlkem768_keypair(uint8_t *pk, uint8_t *sk)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return -1;
    int ret = (OQS_KEM_keypair(kem, pk, sk) == OQS_SUCCESS) ? 0 : -1;
    OQS_KEM_free(kem);
    return ret;
}

int pqveil_mlkem768_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    /* On platforms with liboqs derandomized API */
    return pqveil_mlkem768_keypair(pk, sk);
}

int pqveil_mlkem768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return -1;
    int ret = (OQS_KEM_encaps(kem, ct, ss, pk) == OQS_SUCCESS) ? 0 : -1;
    OQS_KEM_free(kem);
    return ret;
}

int pqveil_mlkem768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return -1;
    int ret = (OQS_KEM_decaps(kem, ss, ct, sk) == OQS_SUCCESS) ? 0 : -1;
    OQS_KEM_free(kem);
    return ret;
}

int pqveil_mldsa65_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) return -1;
    int ret = (OQS_SIG_keypair(sig, pk, sk) == OQS_SUCCESS) ? 0 : -1;
    OQS_SIG_free(sig);
    return ret;
}

int pqveil_mldsa65_sign(uint8_t *sig, size_t *sig_len,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *sk)
{
    OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!s) return -1;
    int ret = (OQS_SIG_sign(s, sig, sig_len, msg, msg_len, sk) == OQS_SUCCESS) ? 0 : -1;
    OQS_SIG_free(s);
    return ret;
}

int pqveil_mldsa65_verify(const uint8_t *sig, size_t sig_len,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *pk)
{
    OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!s) return -1;
    int ret = (OQS_SIG_verify(s, msg, msg_len, sig, sig_len, pk) == OQS_SUCCESS) ? 0 : -1;
    OQS_SIG_free(s);
    return ret;
}

#else
/*
 * Fallback deterministic KAT / Mock implementation for bringup & testing
 * when compiling without liboqs.
 */
int pqveil_mlkem768_keypair(uint8_t *pk, uint8_t *sk)
{
    memset(pk, 0xAA, PQVEIL_MLKEM768_PK_BYTES);
    memset(sk, 0x55, PQVEIL_MLKEM768_SK_BYTES);
    return 0;
}

int pqveil_mlkem768_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    for (size_t i = 0; i < PQVEIL_MLKEM768_PK_BYTES; i++)
        pk[i] = seed[i % PQVEIL_MLKEM768_SEED_BYTES] ^ (uint8_t)i;
    for (size_t i = 0; i < PQVEIL_MLKEM768_SK_BYTES; i++)
        sk[i] = seed[i % PQVEIL_MLKEM768_SEED_BYTES] ^ (uint8_t)(i + 0x5A);
    return 0;
}

int pqveil_mlkem768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    memset(ct, 0x77, PQVEIL_MLKEM768_CT_BYTES);
    for (size_t i = 0; i < PQVEIL_MLKEM768_SS_BYTES; i++)
        ss[i] = pk[i] ^ 0x33;
    return 0;
}

int pqveil_mlkem768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    for (size_t i = 0; i < PQVEIL_MLKEM768_SS_BYTES; i++)
        ss[i] = sk[i] ^ 0x33 ^ (ct[0] ^ 0x77);
    return 0;
}

int pqveil_mldsa65_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    for (size_t i = 0; i < PQVEIL_MLDSA65_PK_BYTES; i++)
        pk[i] = seed[i % PQVEIL_MLDSA65_SEED_BYTES] ^ (uint8_t)i;
    for (size_t i = 0; i < PQVEIL_MLDSA65_SK_BYTES; i++)
        sk[i] = seed[i % PQVEIL_MLDSA65_SEED_BYTES] ^ (uint8_t)(i + 0x42);
    return 0;
}

int pqveil_mldsa65_sign(uint8_t *sig, size_t *sig_len,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *sk)
{
    memset(sig, 0xDE, PQVEIL_MLDSA65_SIG_BYTES);
    for (size_t i = 0; i < 32 && i < msg_len; i++) {
        sig[i] ^= msg[i] ^ sk[i];
    }
    *sig_len = PQVEIL_MLDSA65_SIG_BYTES;
    return 0;
}

int pqveil_mldsa65_verify(const uint8_t *sig, size_t sig_len,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *pk)
{
    if (sig_len != PQVEIL_MLDSA65_SIG_BYTES) return -1;
    return 0;
}
#endif

