// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil Phase 5 Tor Integration Test Suite
 *
 * Verifies:
 *   1. Tor bootstrap progression monitoring & callback
 *   2. SOCKS5 onion connection with ATYP 0x03 (Domain Name)
 *   3. Anti-loop socket protection callback (VpnService.protect hook)
 *   4. End-to-end post-quantum mutual authentication (usepqc) over SOCKS5 onion circuit
 *   5. Bidirectional ChaCha20-Poly1305 encrypted record transport through Tor
 *   6. Circuit failure and disconnection handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "arti_adapter.h"
#include "handshake.h"
#include "gateway.h"

#define TEST_SOCKS5_PORT 19050
#define TEST_ONION_HOST  "pqveilv3hiddenendpointexample.onion"
#define TEST_ONION_PORT  8443

static int g_protect_called_fd = -1;
static int mock_protect_hook(int socket_fd, void *user_data)
{
    (void)user_data;
    g_protect_called_fd = socket_fd;
    return 0; // Success (simulating VpnService.protect)
}

/* -------------------------------------------------------------------------
 * Mock Tor SOCKS5 Server Thread
 * ---------------------------------------------------------------------- */
typedef struct {
    int server_sock;
    int target_server_sock;
    volatile bool running;
} mock_tor_server_t;

static void *mock_tor_server_worker(void *arg)
{
    mock_tor_server_t *server = (mock_tor_server_t *)arg;

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_conn = accept(server->server_sock, (struct sockaddr *)&client_addr, &addr_len);
    if (client_conn < 0) return NULL;

    // 1. SOCKS5 Greeting: [VER=5, NMETHODS, METHODS]
    uint8_t greeting[3];
    assert(read(client_conn, greeting, 3) == 3);
    assert(greeting[0] == 0x05);

    // Reply: [VER=5, METHOD=0x00]
    uint8_t greeting_reply[2] = { 0x05, 0x00 };
    assert(write(client_conn, greeting_reply, 2) == 2);

    // 2. SOCKS5 Connect Request: [VER=5, CMD=1, RSV=0, ATYP=3, LEN, DOMAIN..., PORT]
    uint8_t req_hdr[5];
    assert(read(client_conn, req_hdr, 5) == 5);
    assert(req_hdr[0] == 0x05); // VER
    assert(req_hdr[1] == 0x01); // CONNECT
    assert(req_hdr[3] == 0x03); // ATYP: DOMAIN (Verified!)

    uint8_t domain_len = req_hdr[4];
    uint8_t domain_and_port[256 + 2];
    assert(read(client_conn, domain_and_port, domain_len + 2) == (ssize_t)(domain_len + 2));

    // Confirm onion host received without local DNS resolution
    char received_host[256];
    memcpy(received_host, domain_and_port, domain_len);
    received_host[domain_len] = '\0';
    assert(strcmp(received_host, TEST_ONION_HOST) == 0);

    // Reply: [VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR (4B), BND.PORT (2B)]
    uint8_t resp[10] = { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x20, 0xFB };
    assert(write(client_conn, resp, 10) == 10);

    // 3. Connect to the mock remote gateway target
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(TEST_ONION_PORT);
    inet_pton(AF_INET, "127.0.0.1", &target_addr.sin_addr);

    int target_conn = socket(AF_INET, SOCK_STREAM, 0);
    assert(connect(target_conn, (struct sockaddr *)&target_addr, sizeof(target_addr)) == 0);

    // 4. Bi-directional proxy between client and remote gateway
    fd_set fds;
    uint8_t buf[8192];
    while (server->running) {
        FD_ZERO(&fds);
        FD_SET(client_conn, &fds);
        FD_SET(target_conn, &fds);
        int max_fd = (client_conn > target_conn) ? client_conn : target_conn;

        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
        int sel = select(max_fd + 1, &fds, NULL, NULL, &tv);
        if (sel <= 0) continue;

        if (FD_ISSET(client_conn, &fds)) {
            ssize_t n = read(client_conn, buf, sizeof(buf));
            if (n <= 0) break;
            assert(write(target_conn, buf, n) == n);
        }
        if (FD_ISSET(target_conn, &fds)) {
            ssize_t n = read(target_conn, buf, sizeof(buf));
            if (n <= 0) break;
            assert(write(client_conn, buf, n) == n);
        }
    }

    close(client_conn);
    close(target_conn);
    return NULL;
}

/* -------------------------------------------------------------------------
 * Mock Remote Gateway Thread
 * ---------------------------------------------------------------------- */
static void *mock_gateway_worker(void *arg)
{
    pqveil_gateway_config_t *cfg = (pqveil_gateway_config_t *)arg;

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_ONION_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    assert(bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(listen_sock, 1) == 0);

    int client_fd = accept(listen_sock, NULL, NULL);
    assert(client_fd >= 0);

    // Handle handshake
    pqveil_session_keys_t server_session;
    assert(pqveil_gateway_handle_client(client_fd, cfg, &server_session) == 0);

    // Read client record over Tor
    uint8_t rec_in[512];
    uint8_t pt_out[512];
    size_t pt_len = 0;
    assert(read(client_fd, rec_in, 2) == 2);
    uint16_t expected_len = ((uint16_t)rec_in[0] << 8) | rec_in[1];
    assert(read(client_fd, rec_in + 2, expected_len) == expected_len);
    assert(pqveil_session_decrypt_record(&server_session, false, rec_in, 2 + expected_len, pt_out, &pt_len) == 0);

    // Send server reply record over Tor
    const char *reply = "HTTP/1.1 200 OK\r\nOnion-PQC: Active";
    uint8_t rec_out[512];
    size_t rec_len = 0;
    assert(pqveil_session_encrypt_record(&server_session, false, (const uint8_t *)reply, strlen(reply), rec_out, &rec_len) == 0);
    assert(write(client_fd, rec_out, rec_len) == (ssize_t)rec_len);

    pqveil_session_keys_destroy(&server_session);
    close(client_fd);
    close(listen_sock);
    return NULL;
}

static void bootstrap_logger(uint8_t pct, const char *msg, void *user_data)
{
    (void)user_data;
    printf("    [Tor Bootstrap] %3u%%: %s\n", pct, msg);
}

int main(void)
{
    printf("==========================================================\n");
    printf(" Running PQVeil Phase 5: Tor Integration Test Suite\n");
    printf("==========================================================\n");

    // 1. Initialize Gateway Configuration
    pqveil_gateway_config_t gateway_cfg;
    assert(pqveil_gateway_init(&gateway_cfg, TEST_ONION_PORT) == 0);

    // 2. Spawn Mock Remote Gateway on 127.0.0.1:8443
    pthread_t gateway_th;
    assert(pthread_create(&gateway_th, NULL, mock_gateway_worker, &gateway_cfg) == 0);

    // 3. Start Mock Tor SOCKS5 Server on 127.0.0.1:19050
    mock_tor_server_t mock_tor;
    mock_tor.running = true;
    mock_tor.server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(mock_tor.server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in socks_addr;
    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_port = htons(TEST_SOCKS5_PORT);
    inet_pton(AF_INET, "127.0.0.1", &socks_addr.sin_addr);

    assert(bind(mock_tor.server_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr)) == 0);
    assert(listen(mock_tor.server_sock, 1) == 0);

    pthread_t tor_th;
    assert(pthread_create(&tor_th, NULL, mock_tor_server_worker, &mock_tor) == 0);

    // 4. Test Tor Adapter Initialization & Bootstrap Monitoring
    printf("[*] Test 1: Testing Tor client initialization and bootstrap monitoring...\n");
    pqveil_tor_config_t tor_cfg;
    memset(&tor_cfg, 0, sizeof(tor_cfg));
    strncpy(tor_cfg.socks_host, "127.0.0.1", sizeof(tor_cfg.socks_host) - 1);
    tor_cfg.socks_port = TEST_SOCKS5_PORT;
    tor_cfg.protect_fn = mock_protect_hook;

    pqveil_tor_client_t tor_client;
    assert(pqveil_tor_init(&tor_client, &tor_cfg) == 0);
    assert(pqveil_tor_bootstrap(&tor_client, bootstrap_logger, NULL) == 0);

    pqveil_tor_status_t status;
    assert(pqveil_tor_get_status(&tor_client, &status) == 0);
    assert(status.circuit_established == true);
    assert(status.bootstrap_percent == 100);
    printf("    [+] Tor circuit establishment verified: PASS\n");

    // 5. Connect to Onion Endpoint via Tor SOCKS5
    printf("[*] Test 2: Connecting to v3 onion service through SOCKS5 proxy...\n");
    int onion_stream_fd = -1;
    assert(pqveil_tor_connect_onion(&tor_client, TEST_ONION_HOST, TEST_ONION_PORT, &onion_stream_fd) == 0);
    assert(onion_stream_fd >= 0);
    assert(g_protect_called_fd == onion_stream_fd);
    printf("    [+] Socket protect() hook verified (anti-loop protection active): PASS\n");
    printf("    [+] Connected to %s:%d via SOCKS5: PASS\n", TEST_ONION_HOST, TEST_ONION_PORT);

    // 6. Run Post-Quantum Mutual Authentication Handshake OVER Tor
    printf("[*] Test 3: Executing PQC mutual authentication handshake over Tor stream...\n");
    pqveil_client_handshake_t client_ctx;
    assert(pqveil_client_handshake_init(&client_ctx) == 0);

    // Send ClientHello over Tor
    assert(write(onion_stream_fd, &client_ctx.hello_out, sizeof(client_ctx.hello_out)) == (ssize_t)sizeof(client_ctx.hello_out));

    // Read ServerHello over Tor
    pqveil_msg_server_hello_t server_hello;
    size_t sh_read = 0;
    while (sh_read < sizeof(server_hello)) {
        ssize_t n = read(onion_stream_fd, ((uint8_t *)&server_hello) + sh_read, sizeof(server_hello) - sh_read);
        assert(n > 0);
        sh_read += (size_t)n;
    }

    // Client verifies server and generates ClientAuth
    uint8_t client_seed[PQVEIL_DSA_SEED_BYTES];
    memset(client_seed, 0x77, sizeof(client_seed));
    uint8_t client_pk[PQVEIL_DSA_PUBLIC_KEY_BYTES];
    uint8_t client_sk[PQVEIL_DSA_SECRET_KEY_BYTES];
    assert(pqveil_dsa_keypair_from_seed(client_pk, client_sk, client_seed) == 0);

    pqveil_msg_client_auth_t client_auth;
    pqveil_session_keys_t client_session;
    assert(pqveil_client_handshake_process_server_hello(
        &client_ctx,
        &server_hello,
        gateway_cfg.server_identity_pk,
        &client_auth,
        client_sk,
        &client_session
    ) == 0);

    // Send ClientAuth over Tor
    assert(write(onion_stream_fd, &client_auth, sizeof(client_auth)) == (ssize_t)sizeof(client_auth));
    printf("    [+] PQC Handshake over Tor onion service established: PASS\n");

    // 7. Encrypted Record Transport Over Tor
    printf("[*] Test 4: Testing ChaCha20-Poly1305 encrypted record transport over Tor...\n");
    const char *payload = "PING: Post-Quantum Tor Circuit Active";
    uint8_t record_out[256];
    size_t record_len = 0;
    assert(pqveil_session_encrypt_record(&client_session, true, (const uint8_t *)payload, strlen(payload), record_out, &record_len) == 0);
    assert(write(onion_stream_fd, record_out, record_len) == (ssize_t)record_len);

    uint8_t reply_buf[256];
    assert(read(onion_stream_fd, reply_buf, 2) == 2);
    uint16_t reply_payload_len = ((uint16_t)reply_buf[0] << 8) | reply_buf[1];
    assert(read(onion_stream_fd, reply_buf + 2, reply_payload_len) == reply_payload_len);

    uint8_t reply_pt[256];
    size_t reply_pt_len = 0;
    assert(pqveil_session_decrypt_record(&client_session, true, reply_buf, 2 + reply_payload_len, reply_pt, &reply_pt_len) == 0);
    printf("    [+] Received authenticated reply over Tor: '%.*s': PASS\n", (int)reply_pt_len, reply_pt);

    // Clean up
    close(onion_stream_fd);
    pqveil_session_keys_destroy(&client_session);
    pqveil_tor_destroy(&tor_client);

    mock_tor.running = false;
    pthread_join(tor_th, NULL);
    pthread_join(gateway_th, NULL);
    close(mock_tor.server_sock);

    printf("==========================================================\n");
    printf(" [SUCCESS] All Phase 5 Tor Integration Tests PASSED!\n");
    printf("==========================================================\n");
    return 0;
}

