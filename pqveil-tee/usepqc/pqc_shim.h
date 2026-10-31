/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil usepqc – Post-Quantum Cryptography Shim Definitions
 */

#ifndef PQVEIL_USEPQC_SHIM_H
#define PQVEIL_USEPQC_SHIM_H

#include <stdint.h>
#include <stddef.h>

#define PQVEIL_MLKEM768_PK_BYTES  1184
#define PQVEIL_MLKEM768_SK_BYTES  2400
#define PQVEIL_MLKEM768_CT_BYTES  1088
#define PQVEIL_MLKEM768_SS_BYTES  32
#define PQVEIL_MLKEM768_SEED_BYTES 64

#define PQVEIL_MLDSA65_PK_BYTES   2592
#define PQVEIL_MLDSA65_SK_BYTES   4032
#define PQVEIL_MLDSA65_SIG_BYTES  3309
#define PQVEIL_MLDSA65_SEED_BYTES 32

/* ML-KEM-768 Operations */
int pqveil_mlkem768_keypair(uint8_t *pk, uint8_t *sk);
int pqveil_mlkem768_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int pqveil_mlkem768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqveil_mlkem768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* ML-DSA-65 Operations */
int pqveil_mldsa65_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int pqveil_mldsa65_sign(uint8_t *sig, size_t *sig_len,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *sk);
int pqveil_mldsa65_verify(const uint8_t *sig, size_t sig_len,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *pk);

#endif /* PQVEIL_USEPQC_SHIM_H */

