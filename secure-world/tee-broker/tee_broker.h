/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil TEE Broker – Host-Side OP-TEE Client Wrapper
 *
 * Implements the GlobalPlatform TEE Client API abstraction for
 * communicating with the PQVeil Trusted Application (TA) over `/dev/tee0`.
 */

#ifndef PQVEIL_TEE_BROKER_H
#define PQVEIL_TEE_BROKER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PQVEIL_TA_UUID_STRING "b3a4e5f6-7c8d-4a2b-9e0f-1d2c3b4a5e6f"

/* TA Command IDs matching user_ta_header_defines.h */
#define TEE_CMD_GET_STATUS       0
#define TEE_CMD_PROVISION        1
#define TEE_CMD_SIGN_TRANSCRIPT  2
#define TEE_CMD_DECAPS           3
#define TEE_CMD_SIGN_HEALTH      4
#define TEE_CMD_LOAD_POLICY      5

/* PQC Buffer Sizes */
#define TEE_MLDSA65_PK_SZ        2592
#define TEE_MLDSA65_SIG_SZ       3309
#define TEE_MLKEM768_CT_SZ       1088
#define TEE_MLKEM768_SS_SZ       32
#define TEE_TRANSCRIPT_HASH_SZ   32
#define TEE_HEALTH_NONCE_SZ      16

typedef struct {
    uint8_t version_major;
    uint8_t version_minor;
    uint64_t monotonic_counter;
    uint8_t storage_mode; // 0 = REE-FS, 1 = RPMB
    bool is_provisioned;
} pqveil_ta_status_t;

typedef struct {
    int dev_fd;
    uint32_t session_id;
    bool is_open;
    bool is_emulated;
    uint64_t emulated_counter;
    bool emulated_provisioned;
    uint8_t emulated_dsa_seed[32];
    uint8_t emulated_kem_seed[64];
} pqveil_teec_session_t;

#ifdef __cplusplus
extern "C" {
#endif

int pqveil_teec_init(pqveil_teec_session_t *sess);

int pqveil_teec_get_status(pqveil_teec_session_t *sess, pqveil_ta_status_t *status);

int pqveil_teec_provision(pqveil_teec_session_t *sess, uint8_t *pk_out, size_t *pk_len);

int pqveil_teec_sign_transcript(
    pqveil_teec_session_t *sess,
    const uint8_t hash[TEE_TRANSCRIPT_HASH_SZ],
    uint8_t *sig_out,
    size_t *sig_len
);

int pqveil_teec_decaps(
    pqveil_teec_session_t *sess,
    const uint8_t *ciphertext,
    size_t ct_len,
    uint8_t ss_out[TEE_MLKEM768_SS_SZ]
);

int pqveil_teec_sign_health(
    pqveil_teec_session_t *sess,
    const uint8_t nonce[TEE_HEALTH_NONCE_SZ],
    uint32_t flags,
    uint8_t *report_out,
    size_t *report_len
);

int pqveil_teec_load_policy(
    pqveil_teec_session_t *sess,
    const uint8_t *policy_blob,
    size_t blob_len
);

void pqveil_teec_close(pqveil_teec_session_t *sess);

#ifdef __cplusplus
}
#endif

#endif /* PQVEIL_TEE_BROKER_H */

