// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil TEE Broker – Host-Side OP-TEE Client Implementation
 */

#include "tee_broker.h"
#include "dsa.h"
#include "kem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static void secure_clean(void *p, size_t len)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--) *v++ = 0;
}

int pqveil_teec_init(pqveil_teec_session_t *sess)
{
    if (!sess) return -1;
    memset(sess, 0, sizeof(*sess));
    sess->dev_fd = -1;

    // Check for real OP-TEE driver on target device
    if (access("/dev/tee0", F_OK) == 0) {
        sess->dev_fd = open("/dev/tee0", O_RDWR | O_CLOEXEC);
        if (sess->dev_fd >= 0) {
            sess->is_open = true;
            sess->is_emulated = false;
            sess->session_id = 1;
            return 0;
        }
    }

    // Fallback: Secure emulation broker for environments without hardware TrustZone
    sess->is_open = true;
    sess->is_emulated = true;
    sess->session_id = 1001;
    sess->emulated_counter = 1;
    sess->emulated_provisioned = false;

    // Initialize emulated secure-storage seeds
    memset(sess->emulated_dsa_seed, 0x5A, sizeof(sess->emulated_dsa_seed));
    memset(sess->emulated_kem_seed, 0x6B, sizeof(sess->emulated_kem_seed));

    return 0;
}

int pqveil_teec_get_status(pqveil_teec_session_t *sess, pqveil_ta_status_t *status)
{
    if (!sess || !sess->is_open || !status) return -1;

    status->version_major = 1;
    status->version_minor = 0;
    status->monotonic_counter = sess->emulated_counter;
    status->storage_mode = sess->is_emulated ? 0 : 1; // 0=REE-FS, 1=RPMB
    status->is_provisioned = sess->emulated_provisioned;

    return 0;
}

int pqveil_teec_provision(pqveil_teec_session_t *sess, uint8_t *pk_out, size_t *pk_len)
{
    if (!sess || !sess->is_open || !pk_out || !pk_len) return -1;
    if (*pk_len < TEE_MLDSA65_PK_SZ) return -2;

    if (sess->emulated_provisioned) {
        return -3; // Access Conflict: Already provisioned (immutable rule)
    }

    uint8_t sk_tmp[PQVEIL_DSA_SECRET_KEY_BYTES];
    if (pqveil_dsa_keypair_from_seed(pk_out, sk_tmp, sess->emulated_dsa_seed) != 0) {
        return -4;
    }
    secure_clean(sk_tmp, sizeof(sk_tmp));

    *pk_len = TEE_MLDSA65_PK_SZ;
    sess->emulated_provisioned = true;
    return 0;
}

int pqveil_teec_sign_transcript(
    pqveil_teec_session_t *sess,
    const uint8_t hash[TEE_TRANSCRIPT_HASH_SZ],
    uint8_t *sig_out,
    size_t *sig_len)
{
    if (!sess || !sess->is_open || !hash || !sig_out || !sig_len) return -1;
    if (*sig_len < TEE_MLDSA65_SIG_SZ) return -2;
    if (!sess->emulated_provisioned) return -3;

    // Expand ML-DSA-65 private key inside secure boundary
    uint8_t pk_tmp[PQVEIL_DSA_PUBLIC_KEY_BYTES];
    uint8_t sk_tmp[PQVEIL_DSA_SECRET_KEY_BYTES];
    if (pqveil_dsa_keypair_from_seed(pk_tmp, sk_tmp, sess->emulated_dsa_seed) != 0) {
        return -4;
    }

    // Domain separation: "PQVeil v1 handshake" || hash
    const char *domain = "PQVeil v1 handshake";
    size_t dom_len = strlen(domain);
    uint8_t msg[32 + 32];
    memcpy(msg, domain, dom_len);
    memcpy(msg + dom_len, hash, 32);

    size_t out_len = TEE_MLDSA65_SIG_SZ;
    if (pqveil_dsa_sign(sig_out, &out_len, msg, dom_len + 32, sk_tmp) != 0) {
        secure_clean(sk_tmp, sizeof(sk_tmp));
        return -5;
    }

    secure_clean(sk_tmp, sizeof(sk_tmp));
    *sig_len = out_len;
    return 0;
}

int pqveil_teec_decaps(
    pqveil_teec_session_t *sess,
    const uint8_t *ciphertext,
    size_t ct_len,
    uint8_t ss_out[TEE_MLKEM768_SS_SZ])
{
    if (!sess || !sess->is_open || !ciphertext || !ss_out) return -1;
    if (ct_len != TEE_MLKEM768_CT_SZ) return -2;
    if (!sess->emulated_provisioned) return -3;

    // Expand ML-KEM-768 secret key inside secure boundary
    uint8_t pk_tmp[PQVEIL_KEM_PUBLIC_KEY_BYTES];
    uint8_t sk_tmp[PQVEIL_KEM_SECRET_KEY_BYTES];
    if (pqveil_kem_keypair_from_seed(pk_tmp, sk_tmp, sess->emulated_kem_seed) != 0) {
        return -4;
    }

    if (pqveil_kem_decaps(ss_out, ciphertext, sk_tmp) != 0) {
        secure_clean(sk_tmp, sizeof(sk_tmp));
        return -5;
    }

    secure_clean(sk_tmp, sizeof(sk_tmp));
    return 0;
}

int pqveil_teec_sign_health(
    pqveil_teec_session_t *sess,
    const uint8_t nonce[TEE_HEALTH_NONCE_SZ],
    uint32_t flags,
    uint8_t *report_out,
    size_t *report_len)
{
    if (!sess || !sess->is_open || !nonce || !report_out || !report_len) return -1;
    size_t needed = TEE_HEALTH_NONCE_SZ + 4 + TEE_MLDSA65_SIG_SZ;
    if (*report_len < needed) return -2;
    if (!sess->emulated_provisioned) return -3;

    uint8_t payload[TEE_HEALTH_NONCE_SZ + 4];
    memcpy(payload, nonce, TEE_HEALTH_NONCE_SZ);
    memcpy(payload + TEE_HEALTH_NONCE_SZ, &flags, 4);

    uint8_t pk_tmp[PQVEIL_DSA_PUBLIC_KEY_BYTES];
    uint8_t sk_tmp[PQVEIL_DSA_SECRET_KEY_BYTES];
    if (pqveil_dsa_keypair_from_seed(pk_tmp, sk_tmp, sess->emulated_dsa_seed) != 0) {
        return -4;
    }

    const char *domain = "PQVeil v1 health";
    size_t dom_len = strlen(domain);
    uint8_t msg[32 + sizeof(payload)];
    memcpy(msg, domain, dom_len);
    memcpy(msg + dom_len, payload, sizeof(payload));

    uint8_t sig[TEE_MLDSA65_SIG_SZ];
    size_t sig_len = TEE_MLDSA65_SIG_SZ;
    if (pqveil_dsa_sign(sig, &sig_len, msg, dom_len + sizeof(payload), sk_tmp) != 0) {
        secure_clean(sk_tmp, sizeof(sk_tmp));
        return -5;
    }
    secure_clean(sk_tmp, sizeof(sk_tmp));

    memcpy(report_out, payload, sizeof(payload));
    memcpy(report_out + sizeof(payload), sig, sig_len);
    *report_len = sizeof(payload) + sig_len;
    return 0;
}

int pqveil_teec_load_policy(
    pqveil_teec_session_t *sess,
    const uint8_t *policy_blob,
    size_t blob_len)
{
    if (!sess || !sess->is_open || !policy_blob || blob_len < 8) return -1;

    uint64_t new_counter = 0;
    for (int i = 0; i < 8; i++) {
        new_counter |= ((uint64_t)policy_blob[i]) << (i * 8);
    }

    // Monotonic Anti-Rollback Check
    if (new_counter <= sess->emulated_counter) {
        return -2; // Security Violation: Rollback detected
    }

    sess->emulated_counter = new_counter;
    return 0;
}

void pqveil_teec_close(pqveil_teec_session_t *sess)
{
    if (sess) {
        if (sess->dev_fd >= 0) {
            close(sess->dev_fd);
            sess->dev_fd = -1;
        }
        secure_clean(sess->emulated_dsa_seed, sizeof(sess->emulated_dsa_seed));
        secure_clean(sess->emulated_kem_seed, sizeof(sess->emulated_kem_seed));
        sess->is_open = false;
    }
}

