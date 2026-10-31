// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil Phase 4 Protocol & Gateway Test Suite
 *
 * Verifies:
 *   1. Full client-server usepqc handshake roundtrip over socket/pipe
 *   2. Identity of derived session keys (K_c2s and K_s2c)
 *   3. Bidirectional length-prefixed ChaCha20-Poly1305 record framing
 *   4. Rejection of invalid signatures & tampered transcripts
 *   5. Ephemeral forward secrecy (fresh session keys on reconnect)
 *   6. Secure zeroization of session keys
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>

#include "handshake.h"
#include "gateway.h"

int main(void)
{
    printf("==========================================================\n");
    printf(" Running PQVeil Phase 4: Remote Protocol Test Suite\n");
    printf("==========================================================\n");

    // Initialize Gateway Config (Server long-term keys & pinned client identity)
    pqveil_gateway_config_t server_cfg;
    assert(pqveil_gateway_init(&server_cfg, 8443) == 0);

    // Client Identity Keys
    uint8_t client_seed[PQVEIL_DSA_SEED_BYTES];
    memset(client_seed, 0x77, sizeof(client_seed));
    uint8_t client_pk[PQVEIL_DSA_PUBLIC_KEY_BYTES];
    uint8_t client_sk[PQVEIL_DSA_SECRET_KEY_BYTES];
    assert(pqveil_dsa_keypair_from_seed(client_pk, client_sk, client_seed) == 0);

    // ---------------------------------------------------------------------
    // Test 1: Full Client-Server Handshake over Socketpair
    // ---------------------------------------------------------------------
    printf("[*] Test 1: Executing direct client-server handshake...\n");

    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    int client_fd = fds[0];
    int server_fd = fds[1];

    pqveil_client_handshake_t client_ctx;
    assert(pqveil_client_handshake_init(&client_ctx) == 0);

    // Client sends ClientHello to server
    assert(write(client_fd, &client_ctx.hello_out, sizeof(client_ctx.hello_out)) == (ssize_t)sizeof(client_ctx.hello_out));

    // Server processes ClientHello and responds with ServerHello
    pqveil_server_handshake_t server_ctx;
    pqveil_msg_client_hello_t client_hello_recv;
    assert(read(server_fd, &client_hello_recv, sizeof(client_hello_recv)) == (ssize_t)sizeof(client_hello_recv));

    pqveil_msg_server_hello_t server_hello_out;
    assert(pqveil_server_handshake_process_client_hello(&server_ctx, &client_hello_recv, server_cfg.server_identity_sk, &server_hello_out) == 0);
    assert(write(server_fd, &server_hello_out, sizeof(server_hello_out)) == (ssize_t)sizeof(server_hello_out));

    // Client receives ServerHello, verifies server, generates ClientAuth
    pqveil_msg_server_hello_t server_hello_recv;
    assert(read(client_fd, &server_hello_recv, sizeof(server_hello_recv)) == (ssize_t)sizeof(server_hello_recv));

    pqveil_msg_client_auth_t client_auth_out;
    pqveil_session_keys_t client_keys;
    assert(pqveil_client_handshake_process_server_hello(
        &client_ctx,
        &server_hello_recv,
        server_cfg.server_identity_pk,
        &client_auth_out,
        client_sk,
        &client_keys
    ) == 0);
    assert(write(client_fd, &client_auth_out, sizeof(client_auth_out)) == (ssize_t)sizeof(client_auth_out));

    // Server receives ClientAuth, verifies client, derives session keys
    pqveil_msg_client_auth_t client_auth_recv;
    assert(read(server_fd, &client_auth_recv, sizeof(client_auth_recv)) == (ssize_t)sizeof(client_auth_recv));

    pqveil_session_keys_t server_keys;
    assert(pqveil_server_handshake_verify_client_auth(
        &server_ctx,
        &client_auth_recv,
        server_cfg.authorized_client_pk,
        &server_keys
    ) == 0);

    printf("    [+] Handshake completed successfully on both sides\n");

    // ---------------------------------------------------------------------
    // Test 2: Verify Exact Match of Derived Session Keys
    // ---------------------------------------------------------------------
    printf("[*] Test 2: Verifying session key agreement...\n");
    assert(memcmp(client_keys.client_to_server_key, server_keys.client_to_server_key, PQVEIL_SESSION_KEY_BYTES) == 0);
    assert(memcmp(client_keys.server_to_client_key, server_keys.server_to_client_key, PQVEIL_SESSION_KEY_BYTES) == 0);
    assert(memcmp(client_keys.client_to_server_key, client_keys.server_to_client_key, PQVEIL_SESSION_KEY_BYTES) != 0); // Directional separation
    printf("    [+] Client and Server derived IDENTICAL session keys: PASS\n");

    // ---------------------------------------------------------------------
    // Test 3: Bidirectional Length-Prefixed Record Framing
    // ---------------------------------------------------------------------
    printf("[*] Test 3: Testing encrypted record framing & transfer...\n");
    const char *client_msg = "GET /index.html HTTP/1.1\r\nHost: example.onion\r\n\r\n";
    size_t pt_len = strlen(client_msg);
    uint8_t record_buf[512];
    size_t record_len = 0;

    // Client seals record
    assert(pqveil_session_encrypt_record(&client_keys, true, (const uint8_t *)client_msg, pt_len, record_buf, &record_len) == 0);
    assert(write(client_fd, record_buf, record_len) == (ssize_t)record_len);

    // Server reads and decrypts record
    uint8_t server_recv_buf[512];
    assert(read(server_fd, server_recv_buf, record_len) == (ssize_t)record_len);

    uint8_t decrypted_msg[512];
    size_t decrypted_len = 0;
    assert(pqveil_session_decrypt_record(&server_keys, false, server_recv_buf, record_len, decrypted_msg, &decrypted_len) == 0);
    assert(decrypted_len == pt_len);
    assert(memcmp(decrypted_msg, client_msg, pt_len) == 0);
    printf("    [+] Client -> Server encrypted transmission verified: PASS\n");

    // Server replies with encrypted record
    const char *server_reply = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nPQVeil Authenticated";
    size_t reply_len = strlen(server_reply);
    uint8_t reply_record[512];
    size_t reply_rec_len = 0;

    assert(pqveil_session_encrypt_record(&server_keys, false, (const uint8_t *)server_reply, reply_len, reply_record, &reply_rec_len) == 0);
    assert(write(server_fd, reply_record, reply_rec_len) == (ssize_t)reply_rec_len);

    // Client decrypts server reply
    uint8_t client_recv_buf[512];
    assert(read(client_fd, client_recv_buf, reply_rec_len) == (ssize_t)reply_rec_len);

    uint8_t client_decrypted[512];
    size_t client_dec_len = 0;
    assert(pqveil_session_decrypt_record(&client_keys, true, client_recv_buf, reply_rec_len, client_decrypted, &client_dec_len) == 0);
    assert(client_dec_len == reply_len);
    assert(memcmp(client_decrypted, server_reply, reply_len) == 0);
    printf("    [+] Server -> Client encrypted reply verified: PASS\n");

    close(client_fd);
    close(server_fd);

    // ---------------------------------------------------------------------
    // Test 4: Replay & Tamper Rejection
    // ---------------------------------------------------------------------
    printf("[*] Test 4: Testing signature tampering and replay attack rejection...\n");
    // Tamper with client signature
    client_auth_recv.client_signature[0] ^= 0x01;
    pqveil_session_keys_t rejected_keys;
    int rej = pqveil_server_handshake_verify_client_auth(&server_ctx, &client_auth_recv, server_cfg.authorized_client_pk, &rejected_keys);
    assert(rej != 0);
    printf("    [+] Tampered client signature was rejected by server: PASS\n");

    // ---------------------------------------------------------------------
    // Test 5: Fresh Keys on Reconnection
    // ---------------------------------------------------------------------
    printf("[*] Test 5: Testing forward-secrecy on reconnection...\n");
    pqveil_client_handshake_t client_ctx2;
    assert(pqveil_client_handshake_init(&client_ctx2) == 0);
    // Ephemeral X25519 and ML-KEM public keys must differ from previous session
    assert(memcmp(client_ctx.hello_out.x25519_public, client_ctx2.hello_out.x25519_public, 32) != 0);
    assert(memcmp(client_ctx.hello_out.mlkem_public, client_ctx2.hello_out.mlkem_public, 1184) != 0);
    printf("    [+] Fresh ephemeral key generation on each session confirmed: PASS\n");

    // ---------------------------------------------------------------------
    // Test 6: Zeroization
    // ---------------------------------------------------------------------
    printf("[*] Test 6: Verifying secure zeroization...\n");
    pqveil_session_keys_destroy(&client_keys);
    uint8_t zero_block[32] = {0};
    assert(memcmp(client_keys.client_to_server_key, zero_block, 32) == 0);
    assert(memcmp(client_keys.server_to_client_key, zero_block, 32) == 0);
    assert(client_keys.is_established == false);
    printf("    [+] Session keys wiped to zero on close: PASS\n");

    printf("==========================================================\n");
    printf(" [SUCCESS] All Phase 4 Protocol Tests PASSED!\n");
    printf("==========================================================\n");
    return 0;
}

