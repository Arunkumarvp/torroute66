/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil Remote Protocol Engine – `usepqc` Handshake & Wire Specification
 *
 * Implements mutual post-quantum authentication with:
 *   - Ephemeral X25519 (RFC 7748)
 *   - Ephemeral ML-KEM-768 (NIST FIPS 203)
 *   - Identity ML-DSA-65 (NIST FIPS 204)
 *   - HKDF-SHA3-256 Session Key Derivation
 */

#ifndef PQVEIL_PROTOCOL_HANDSHAKE_H
#define PQVEIL_PROTOCOL_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "kem.h"
#include "dsa.h"
#include "aead.h"

#define PQVEIL_PROTO_VERSION_MAJOR 1
#define PQVEIL_PROTO_VERSION_MINOR 0

/* Message Sizes */
#define PQVEIL_CLIENT_HELLO_BYTES (2 + PQVEIL_X25519_KEY_BYTES + PQVEIL_KEM_PUBLIC_KEY_BYTES) // 1218 B
#define PQVEIL_SERVER_HELLO_BYTES (PQVEIL_X25519_KEY_BYTES + PQVEIL_KEM_CIPHERTEXT_BYTES + PQVEIL_DSA_SIGNATURE_BYTES) // 4429 B
#define PQVEIL_CLIENT_AUTH_BYTES  (PQVEIL_DSA_SIGNATURE_BYTES) // 3309 B

#define PQVEIL_SESSION_KEY_BYTES  32
#define PQVEIL_TRANSCRIPT_HASH_SZ 32

#define PQVEIL_SIGN_DOMAIN_TAG    "PQVeil v1 handshake"

#pragma pack(push, 1)

typedef struct {
    uint8_t version_major;
    uint8_t version_minor;
    uint8_t x25519_public[PQVEIL_X25519_KEY_BYTES];
    uint8_t mlkem_public[PQVEIL_KEM_PUBLIC_KEY_BYTES];
} pqveil_msg_client_hello_t;

typedef struct {
    uint8_t x25519_public[PQVEIL_X25519_KEY_BYTES];
    uint8_t mlkem_ciphertext[PQVEIL_KEM_CIPHERTEXT_BYTES];
    uint8_t server_signature[PQVEIL_DSA_SIGNATURE_BYTES];
} pqveil_msg_server_hello_t;

typedef struct {
    uint8_t client_signature[PQVEIL_DSA_SIGNATURE_BYTES];
} pqveil_msg_client_auth_t;

#pragma pack(pop)

typedef struct {
    uint8_t client_to_server_key[PQVEIL_SESSION_KEY_BYTES];
    uint8_t server_to_client_key[PQVEIL_SESSION_KEY_BYTES];
    uint64_t client_seq;
    uint64_t server_seq;
    bool is_established;
} pqveil_session_keys_t;

/* Client-side Handshake State */
typedef struct {
    uint8_t client_x25519_priv[PQVEIL_X25519_KEY_BYTES];
    uint8_t client_mlkem_sk[PQVEIL_KEM_SECRET_KEY_BYTES];
    pqveil_msg_client_hello_t hello_out;
    uint8_t transcript1_hash[PQVEIL_TRANSCRIPT_HASH_SZ];
    uint8_t transcript2_hash[PQVEIL_TRANSCRIPT_HASH_SZ];
} pqveil_client_handshake_t;

/* Server-side Handshake State */
typedef struct {
    uint8_t server_x25519_priv[PQVEIL_X25519_KEY_BYTES];
    uint8_t x25519_shared[PQVEIL_X25519_KEY_BYTES];
    uint8_t mlkem_shared[PQVEIL_KEM_SHARED_SECRET_BYTES];
    pqveil_msg_server_hello_t hello_out;
    uint8_t transcript1_hash[PQVEIL_TRANSCRIPT_HASH_SZ];
    uint8_t transcript2_hash[PQVEIL_TRANSCRIPT_HASH_SZ];
} pqveil_server_handshake_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Client Handshake Lifecycle */
int pqveil_client_handshake_init(pqveil_client_handshake_t *client_ctx);

int pqveil_client_handshake_process_server_hello(
    pqveil_client_handshake_t *client_ctx,
    const pqveil_msg_server_hello_t *server_hello,
    const uint8_t server_identity_pk[PQVEIL_DSA_PUBLIC_KEY_BYTES],
    pqveil_msg_client_auth_t *auth_out,
    const uint8_t client_identity_sk[PQVEIL_DSA_SECRET_KEY_BYTES],
    pqveil_session_keys_t *keys_out
);

/* Server Handshake Lifecycle */
int pqveil_server_handshake_process_client_hello(
    pqveil_server_handshake_t *server_ctx,
    const pqveil_msg_client_hello_t *client_hello,
    const uint8_t server_identity_sk[PQVEIL_DSA_SECRET_KEY_BYTES],
    pqveil_msg_server_hello_t *hello_out
);

int pqveil_server_handshake_verify_client_auth(
    pqveil_server_handshake_t *server_ctx,
    const pqveil_msg_client_auth_t *client_auth,
    const uint8_t client_identity_pk[PQVEIL_DSA_PUBLIC_KEY_BYTES],
    pqveil_session_keys_t *keys_out
);

/* Session framing */
int pqveil_session_encrypt_record(
    pqveil_session_keys_t *keys,
    bool is_client,
    const uint8_t *plaintext,
    size_t pt_len,
    uint8_t *record_out,
    size_t *record_len
);

int pqveil_session_decrypt_record(
    pqveil_session_keys_t *keys,
    bool is_client,
    const uint8_t *record,
    size_t record_len,
    uint8_t *plaintext_out,
    size_t *pt_len
);

void pqveil_session_keys_destroy(pqveil_session_keys_t *keys);

#ifdef __cplusplus
}
#endif

#endif /* PQVEIL_PROTOCOL_HANDSHAKE_H */

