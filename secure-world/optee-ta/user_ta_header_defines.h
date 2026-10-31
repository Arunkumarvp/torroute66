/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil Trusted Application – header defines
 *
 * OP-TEE reads these macros when linking the TA binary.
 * Keep TA_UUID in sync with the Rust controller's PQVEIL_TA_UUID constant.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

/* -------------------------------------------------------------------------
 * TA UUID:  b3a4e5f6-7c8d-4a2b-9e0f-1d2c3b4a5e6f
 * ---------------------------------------------------------------------- */
#define TA_UUID \
    { 0xb3a4e5f6, 0x7c8d, 0x4a2b, \
      { 0x9e, 0x0f, 0x1d, 0x2c, 0x3b, 0x4a, 0x5e, 0x6f } }

/* -------------------------------------------------------------------------
 * TA flags
 *   TA_FLAG_SINGLE_INSTANCE   – only one TA instance at a time
 *   TA_FLAG_MULTI_SESSION     – allow multiple concurrent sessions
 *   TA_FLAG_INSTANCE_KEEP_ALIVE – keep instance alive between sessions
 * ---------------------------------------------------------------------- */
#define TA_FLAGS            (TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)

/* -------------------------------------------------------------------------
 * Stack size
 *   ML-DSA-65 signing needs ~12 KB of stack in the reference implementation.
 *   We round up to 32 KB to give margin for future additions and the HKDF
 *   temporary buffers in crypto_service.c.
 * ---------------------------------------------------------------------- */
#define TA_STACK_SIZE       (32 * 1024)   /* 32 KB */

/* -------------------------------------------------------------------------
 * Heap / data size
 *   The TA keeps a 64-slot key table (~160 KB for ML-KEM-768 raw blobs),
 *   plus liboqs internal state for ML-KEM and ML-DSA expand.  We allocate
 *   512 KB which is enough for the first version; measure and tune in M4.
 * ---------------------------------------------------------------------- */
#define TA_DATA_SIZE        (512 * 1024)  /* 512 KB */

/* -------------------------------------------------------------------------
 * Version reported by GET_STATUS
 * ---------------------------------------------------------------------- */
#define PQVEIL_TA_VERSION_MAJOR  1u
#define PQVEIL_TA_VERSION_MINOR  0u

/* -------------------------------------------------------------------------
 * TA command IDs (must match tee_client.rs)
 * ---------------------------------------------------------------------- */
#define PQVEIL_CMD_GET_STATUS       0u
#define PQVEIL_CMD_PROVISION        1u
#define PQVEIL_CMD_SIGN_TRANSCRIPT  2u
#define PQVEIL_CMD_DECAPS           3u
#define PQVEIL_CMD_SIGN_HEALTH      4u
#define PQVEIL_CMD_LOAD_POLICY      5u

/* -------------------------------------------------------------------------
 * Secure-storage object IDs
 * ---------------------------------------------------------------------- */
#define PQVEIL_STORE_KEM_SEED    "pqveil.kem_seed"
#define PQVEIL_STORE_DSA_SEED    "pqveil.dsa_seed"
#define PQVEIL_STORE_POLICY      "pqveil.policy"
#define PQVEIL_STORE_COUNTER     "pqveil.counter"

/* -------------------------------------------------------------------------
 * Algorithm / key size constants shared with ta_entry.c
 * ---------------------------------------------------------------------- */
#define PQVEIL_KEM_SEED_SZ        64u    /* ML-KEM-768 seed (d||z) */
#define PQVEIL_DSA_SEED_SZ        32u    /* ML-DSA-65 seed (xi) */
#define PQVEIL_MLKEM_CT_SZ        1088u
#define PQVEIL_MLKEM_SS_SZ        32u
#define PQVEIL_MLDSA_PK_SZ        2592u
#define PQVEIL_MLDSA_SIG_SZ       3309u
#define PQVEIL_TRANSCRIPT_HASH_SZ 32u    /* SHA-256 or SHA3-256 */
#define PQVEIL_HEALTH_NONCE_SZ    16u

/* -------------------------------------------------------------------------
 * Signing domain separator
 * ---------------------------------------------------------------------- */
#define PQVEIL_SIGN_DOMAIN_HANDSHAKE  "PQVeil v1 handshake"
#define PQVEIL_SIGN_DOMAIN_HEALTH     "PQVeil v1 health"

#endif /* USER_TA_HEADER_DEFINES_H */

