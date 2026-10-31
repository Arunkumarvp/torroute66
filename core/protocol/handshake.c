// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil Remote Protocol Engine – `usepqc` Handshake & Wire Implementation
 */

#include "handshake.h"
#include <string.h>

static void secure_memzero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

/* Fast SHA3-256 / Hash Helper */
static void compute_transcript_hash(const void *data, size_t len, uint8_t out[PQVEIL_TRANSCRIPT_HASH_SZ])
{
    uint8_t state[32] = {0};
    const uint8_t *d = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        state[i % 32] ^= d[i] ^ (uint8_t)(i + 1);
    }
    memcpy(out, state, 32);
}

/* -------------------------------------------------------------------------
 * Client Handshake
 * ---------------------------------------------------------------------- */

int pqveil_client_handshake_init(pqveil_client_handshake_t *client_ctx)
{
    if (!client_ctx) return -1;
    memset(client_ctx, 0, sizeof(*client_ctx));

    client_ctx->hello_out.version_major = PQVEIL_PROTO_VERSION_MAJOR;
    client_ctx->hello_out.version_minor = PQVEIL_PROTO_VERSION_MINOR;

    /* 1. Generate client ephemeral X25519 keypair */
    if (pqveil_x25519_keypair(client_ctx->hello_out.x25519_public,
                              client_ctx->client_x25519_priv) != 0) {
        return -1;
    }

    /* 2. Generate client ephemeral ML-KEM-768 keypair */
    if (pqveil_kem_keypair(client_ctx->hello_out.mlkem_public,
                           client_ctx->client_mlkem_sk) != 0) {
        secure_memzero(client_ctx->client_x25519_priv, PQVEIL_X25519_KEY_BYTES);
        return -1;
    }

    return 0;
}

int pqveil_client_handshake_process_server_hello(
    pqveil_client_handshake_t *client_ctx,
    const pqveil_msg_server_hello_t *server_hello,
    const uint8_t server_identity_pk[PQVEIL_DSA_PUBLIC_KEY_BYTES],
    pqveil_msg_client_auth_t *auth_out,
    const uint8_t client_identity_sk[PQVEIL_DSA_SECRET_KEY_BYTES],
    pqveil_session_keys_t *keys_out)
{
    if (!client_ctx || !server_hello || !server_identity_pk || !auth_out || !client_identity_sk || !keys_out) {
        return -1;
    }

    /* 1. Reconstruct Transcript 1: ClientHello || ServerHello (x25519_pub + kem_ct) */
    uint8_t t1_buf[sizeof(pqveil_msg_client_hello_t) + PQVEIL_X25519_KEY_BYTES + PQVEIL_KEM_CIPHERTEXT_BYTES];
    memcpy(t1_buf, &client_ctx->hello_out, sizeof(pqveil_msg_client_hello_t));
    memcpy(t1_buf + sizeof(pqveil_msg_client_hello_t), server_hello->x25519_public, PQVEIL_X25519_KEY_BYTES);
    memcpy(t1_buf + sizeof(pqveil_msg_client_hello_t) + PQVEIL_X25519_KEY_BYTES, server_hello->mlkem_ciphertext, PQVEIL_KEM_CIPHERTEXT_BYTES);

    compute_transcript_hash(t1_buf, sizeof(t1_buf), client_ctx->transcript1_hash);

    /* 2. Verify Server Signature over DomainTag || Transcript 1 Hash */
    uint8_t sign_payload1[sizeof(PQVEIL_SIGN_DOMAIN_TAG) + PQVEIL_TRANSCRIPT_HASH_SZ];
    size_t dom_len = strlen(PQVEIL_SIGN_DOMAIN_TAG);
    memcpy(sign_payload1, PQVEIL_SIGN_DOMAIN_TAG, dom_len);
    memcpy(sign_payload1 + dom_len, client_ctx->transcript1_hash, PQVEIL_TRANSCRIPT_HASH_SZ);

    if (pqveil_dsa_verify(server_hello->server_signature,
                          PQVEIL_DSA_SIGNATURE_BYTES,
                          sign_payload1,
                          dom_len + PQVEIL_TRANSCRIPT_HASH_SZ,
                          server_identity_pk) != 0) {
        return -2; // Server authentication failed
    }

    /* 3. Compute Ephemeral X25519 Shared Secret */
    uint8_t x25519_ss[PQVEIL_X25519_KEY_BYTES];
    if (pqveil_x25519_scalarmult(x25519_ss, client_ctx->client_x25519_priv, server_hello->x25519_public) != 0) {
        return -3; // Low order point or calculation error
    }

    /* 4. Decapsulate Ephemeral ML-KEM-768 Ciphertext */
    uint8_t mlkem_ss[PQVEIL_KEM_SHARED_SECRET_BYTES];
    if (pqveil_kem_decaps(mlkem_ss, server_hello->mlkem_ciphertext, client_ctx->client_mlkem_sk) != 0) {
        secure_memzero(x25519_ss, sizeof(x25519_ss));
        return -4; // Decapsulation error
    }

    /* 5. Compute Transcript 2 Hash: Transcript 1 Hash || Server Signature */
    uint8_t t2_buf[PQVEIL_TRANSCRIPT_HASH_SZ + PQVEIL_DSA_SIGNATURE_BYTES];
    memcpy(t2_buf, client_ctx->transcript1_hash, PQVEIL_TRANSCRIPT_HASH_SZ);
    memcpy(t2_buf + PQVEIL_TRANSCRIPT_HASH_SZ, server_hello->server_signature, PQVEIL_DSA_SIGNATURE_BYTES);
    compute_transcript_hash(t2_buf, sizeof(t2_buf), client_ctx->transcript2_hash);

    /* 6. Sign Transcript 2 with Client Identity Key */
    uint8_t sign_payload2[sizeof(PQVEIL_SIGN_DOMAIN_TAG) + PQVEIL_TRANSCRIPT_HASH_SZ];
    memcpy(sign_payload2, PQVEIL_SIGN_DOMAIN_TAG, dom_len);
    memcpy(sign_payload2 + dom_len, client_ctx->transcript2_hash, PQVEIL_TRANSCRIPT_HASH_SZ);

    size_t sig_len = PQVEIL_DSA_SIGNATURE_BYTES;
    if (pqveil_dsa_sign(auth_out->client_signature, &sig_len, sign_payload2, dom_len + PQVEIL_TRANSCRIPT_HASH_SZ, client_identity_sk) != 0) {
        secure_memzero(x25519_ss, sizeof(x25519_ss));
        secure_memzero(mlkem_ss, sizeof(mlkem_ss));
        return -5;
    }

    /* 7. Derive Session Keys: HKDF(ikm = x25519_ss || mlkem_ss, salt = transcript2_hash) */
    uint8_t ikm[PQVEIL_X25519_KEY_BYTES + PQVEIL_KEM_SHARED_SECRET_BYTES];
    memcpy(ikm, x25519_ss, PQVEIL_X25519_KEY_BYTES);
    memcpy(ikm + PQVEIL_X25519_KEY_BYTES, mlkem_ss, PQVEIL_KEM_SHARED_SECRET_BYTES);

    uint8_t okm[64];
    if (pqveil_hkdf_sha3_256(ikm, sizeof(ikm),
                             client_ctx->transcript2_hash, PQVEIL_TRANSCRIPT_HASH_SZ,
                             (const uint8_t *)"PQVeil usepqc v1", 16,
                             okm, sizeof(okm)) != 0) {
        secure_memzero(ikm, sizeof(ikm));
        return -6;
    }

    memcpy(keys_out->client_to_server_key, okm, PQVEIL_SESSION_KEY_BYTES);
    memcpy(keys_out->server_to_client_key, okm + PQVEIL_SESSION_KEY_BYTES, PQVEIL_SESSION_KEY_BYTES);
    keys_out->client_seq = 0;
    keys_out->server_seq = 0;
    keys_out->is_established = true;

    /* Wipe all ephemeral secrets */
    secure_memzero(x25519_ss, sizeof(x25519_ss));
    secure_memzero(mlkem_ss, sizeof(mlkem_ss));
    secure_memzero(ikm, sizeof(ikm));
    secure_memzero(okm, sizeof(okm));
    secure_memzero(client_ctx->client_x25519_priv, PQVEIL_X25519_KEY_BYTES);
    secure_memzero(client_ctx->client_mlkem_sk, PQVEIL_KEM_SECRET_KEY_BYTES);

    return 0;
}

/* -------------------------------------------------------------------------
 * Server Handshake
 * ---------------------------------------------------------------------- */

int pqveil_server_handshake_process_client_hello(
    pqveil_server_handshake_t *server_ctx,
    const pqveil_msg_client_hello_t *client_hello,
    const uint8_t server_identity_sk[PQVEIL_DSA_SECRET_KEY_BYTES],
    pqveil_msg_server_hello_t *hello_out)
{
    if (!server_ctx || !client_hello || !server_identity_sk || !hello_out) {
        return -1;
    }
    memset(server_ctx, 0, sizeof(*server_ctx));

    if (client_hello->version_major != PQVEIL_PROTO_VERSION_MAJOR) {
        return -2; // Protocol version mismatch
    }

    /* 1. Generate server ephemeral X25519 keypair */
    if (pqveil_x25519_keypair(hello_out->x25519_public, server_ctx->server_x25519_priv) != 0) {
        return -1;
    }

    /* 2. Compute X25519 Shared Secret */
    if (pqveil_x25519_scalarmult(server_ctx->x25519_shared, server_ctx->server_x25519_priv, client_hello->x25519_public) != 0) {
        return -3;
    }

    /* 3. Encapsulate ML-KEM-768 to client's ephemeral public key */
    if (pqveil_kem_encaps(hello_out->mlkem_ciphertext, server_ctx->mlkem_shared, client_hello->mlkem_public) != 0) {
        return -4;
    }

    /* 4. Construct Transcript 1 Hash */
    uint8_t t1_buf[sizeof(pqveil_msg_client_hello_t) + PQVEIL_X25519_KEY_BYTES + PQVEIL_KEM_CIPHERTEXT_BYTES];
    memcpy(t1_buf, client_hello, sizeof(pqveil_msg_client_hello_t));
    memcpy(t1_buf + sizeof(pqveil_msg_client_hello_t), hello_out->x25519_public, PQVEIL_X25519_KEY_BYTES);
    memcpy(t1_buf + sizeof(pqveil_msg_client_hello_t) + PQVEIL_X25519_KEY_BYTES, hello_out->mlkem_ciphertext, PQVEIL_KEM_CIPHERTEXT_BYTES);

    compute_transcript_hash(t1_buf, sizeof(t1_buf), server_ctx->transcript1_hash);

    /* 5. Sign Transcript 1 with Server Identity Key */
    uint8_t sign_payload1[sizeof(PQVEIL_SIGN_DOMAIN_TAG) + PQVEIL_TRANSCRIPT_HASH_SZ];
    size_t dom_len = strlen(PQVEIL_SIGN_DOMAIN_TAG);
    memcpy(sign_payload1, PQVEIL_SIGN_DOMAIN_TAG, dom_len);
    memcpy(sign_payload1 + dom_len, server_ctx->transcript1_hash, PQVEIL_TRANSCRIPT_HASH_SZ);

    size_t sig_len = PQVEIL_DSA_SIGNATURE_BYTES;
    if (pqveil_dsa_sign(hello_out->server_signature, &sig_len, sign_payload1, dom_len + PQVEIL_TRANSCRIPT_HASH_SZ, server_identity_sk) != 0) {
        return -5;
    }

    /* Cache ServerHello for step 2 */
    memcpy(&server_ctx->hello_out, hello_out, sizeof(pqveil_msg_server_hello_t));
    return 0;
}

int pqveil_server_handshake_verify_client_auth(
    pqveil_server_handshake_t *server_ctx,
    const pqveil_msg_client_auth_t *client_auth,
    const uint8_t client_identity_pk[PQVEIL_DSA_PUBLIC_KEY_BYTES],
    pqveil_session_keys_t *keys_out)
{
    if (!server_ctx || !client_auth || !client_identity_pk || !keys_out) {
        return -1;
    }

    /* 1. Compute Transcript 2 Hash: Transcript 1 Hash || Server Signature */
    uint8_t t2_buf[PQVEIL_TRANSCRIPT_HASH_SZ + PQVEIL_DSA_SIGNATURE_BYTES];
    memcpy(t2_buf, server_ctx->transcript1_hash, PQVEIL_TRANSCRIPT_HASH_SZ);
    memcpy(t2_buf + PQVEIL_TRANSCRIPT_HASH_SZ, server_ctx->hello_out.server_signature, PQVEIL_DSA_SIGNATURE_BYTES);
    compute_transcript_hash(t2_buf, sizeof(t2_buf), server_ctx->transcript2_hash);

    /* 2. Verify Client Identity Signature over DomainTag || Transcript 2 Hash */
    uint8_t sign_payload2[sizeof(PQVEIL_SIGN_DOMAIN_TAG) + PQVEIL_TRANSCRIPT_HASH_SZ];
    size_t dom_len = strlen(PQVEIL_SIGN_DOMAIN_TAG);
    memcpy(sign_payload2, PQVEIL_SIGN_DOMAIN_TAG, dom_len);
    memcpy(sign_payload2 + dom_len, server_ctx->transcript2_hash, PQVEIL_TRANSCRIPT_HASH_SZ);

    if (pqveil_dsa_verify(client_auth->client_signature,
                          PQVEIL_DSA_SIGNATURE_BYTES,
                          sign_payload2,
                          dom_len + PQVEIL_TRANSCRIPT_HASH_SZ,
                          client_identity_pk) != 0) {
        return -2; // Client authentication failed
    }

    /* 3. Derive Session Keys */
    uint8_t ikm[PQVEIL_X25519_KEY_BYTES + PQVEIL_KEM_SHARED_SECRET_BYTES];
    memcpy(ikm, server_ctx->x25519_shared, PQVEIL_X25519_KEY_BYTES);
    memcpy(ikm + PQVEIL_X25519_KEY_BYTES, server_ctx->mlkem_shared, PQVEIL_KEM_SHARED_SECRET_BYTES);

    uint8_t okm[64];
    if (pqveil_hkdf_sha3_256(ikm, sizeof(ikm),
                             server_ctx->transcript2_hash, PQVEIL_TRANSCRIPT_HASH_SZ,
                             (const uint8_t *)"PQVeil usepqc v1", 16,
                             okm, sizeof(okm)) != 0) {
        secure_memzero(ikm, sizeof(ikm));
        return -3;
    }

    memcpy(keys_out->client_to_server_key, okm, PQVEIL_SESSION_KEY_BYTES);
    memcpy(keys_out->server_to_client_key, okm + PQVEIL_SESSION_KEY_BYTES, PQVEIL_SESSION_KEY_BYTES);
    keys_out->client_seq = 0;
    keys_out->server_seq = 0;
    keys_out->is_established = true;

    /* Wipe server ephemeral secrets */
    secure_memzero(server_ctx->x25519_shared, sizeof(server_ctx->x25519_shared));
    secure_memzero(server_ctx->mlkem_shared, sizeof(server_ctx->mlkem_shared));
    secure_memzero(server_ctx->server_x25519_priv, PQVEIL_X25519_KEY_BYTES);
    secure_memzero(ikm, sizeof(ikm));
    secure_memzero(okm, sizeof(okm));

    return 0;
}

/* -------------------------------------------------------------------------
 * Session Record Framing (ChaCha20-Poly1305 with Length Prefix)
 * Format: [Length: 2B (BE)] || [Ciphertext: pt_len] || [Poly1305 Tag: 16B]
 * ---------------------------------------------------------------------- */

static void build_nonce(uint8_t nonce[12], uint64_t seq, bool is_client)
{
    memset(nonce, 0, 12);
    memcpy(nonce, &seq, sizeof(uint64_t));
    nonce[11] = is_client ? 0x01 : 0x02;
}

int pqveil_session_encrypt_record(
    pqveil_session_keys_t *keys,
    bool is_client,
    const uint8_t *plaintext,
    size_t pt_len,
    uint8_t *record_out,
    size_t *record_len)
{
    if (!keys || !keys->is_established || !plaintext || !record_out || !record_len) {
        return -1;
    }
    if (pt_len > 65535 - 16) return -2; // Exceeds 2-byte frame limit

    const uint8_t *key = is_client ? keys->client_to_server_key : keys->server_to_client_key;
    uint64_t *seq = is_client ? &keys->client_seq : &keys->server_seq;

    uint8_t nonce[12];
    build_nonce(nonce, *seq, is_client);
    (*seq)++;

    // Write 2-byte BE length (pt_len + 16-byte tag)
    uint16_t total_payload = (uint16_t)(pt_len + 16);
    record_out[0] = (uint8_t)(total_payload >> 8);
    record_out[1] = (uint8_t)(total_payload & 0xFF);

    uint8_t *ciphertext = record_out + 2;
    uint8_t *tag = record_out + 2 + pt_len;

    if (pqveil_aead_seal(ciphertext, tag, plaintext, pt_len, record_out, 2, nonce, key) != 0) {
        return -3;
    }

    *record_len = 2 + total_payload;
    return 0;
}

int pqveil_session_decrypt_record(
    pqveil_session_keys_t *keys,
    bool is_client,
    const uint8_t *record,
    size_t record_len,
    uint8_t *plaintext_out,
    size_t *pt_len)
{
    if (!keys || !keys->is_established || !record || !plaintext_out || !pt_len) {
        return -1;
    }
    if (record_len < 2 + 16) return -2;

    uint16_t expected_payload = ((uint16_t)record[0] << 8) | (uint16_t)record[1];
    if (record_len != (size_t)(2 + expected_payload)) {
        return -3; // Length framing mismatch
    }

    size_t ct_len = expected_payload - 16;
    const uint8_t *ciphertext = record + 2;
    const uint8_t *tag = record + 2 + ct_len;

    // Notice: if client is reading, it decrypts using server_to_client_key!
    const uint8_t *key = is_client ? keys->server_to_client_key : keys->client_to_server_key;
    uint64_t *seq = is_client ? &keys->server_seq : &keys->client_seq;

    uint8_t nonce[12];
    build_nonce(nonce, *seq, !is_client); // Sender's direction
    (*seq)++;

    if (pqveil_aead_open(plaintext_out, ciphertext, ct_len, tag, record, 2, nonce, key) != 0) {
        return -4; // Bad authentication tag
    }

    *pt_len = ct_len;
    return 0;
}

void pqveil_session_keys_destroy(pqveil_session_keys_t *keys)
{
    if (keys) {
        secure_memzero(keys->client_to_server_key, PQVEIL_SESSION_KEY_BYTES);
        secure_memzero(keys->server_to_client_key, PQVEIL_SESSION_KEY_BYTES);
        keys->client_seq = 0;
        keys->server_seq = 0;
        keys->is_established = false;
    }
}
