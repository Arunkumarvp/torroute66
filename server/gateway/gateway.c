// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil Remote Server Gateway Implementation
 *
 * Implements the server-side `usepqc` mutual authentication handshake
 * and encrypted record transport over a direct TCP connection.
 */

#include "gateway.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

static int read_exact(int fd, void *buf, size_t count)
{
    size_t total = 0;
    uint8_t *p = (uint8_t *)buf;
    while (total < count) {
        ssize_t n = read(fd, p + total, count - total);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

static int write_exact(int fd, const void *buf, size_t count)
{
    size_t total = 0;
    const uint8_t *p = (const uint8_t *)buf;
    while (total < count) {
        ssize_t n = write(fd, p + total, count - total);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

int pqveil_gateway_init(pqveil_gateway_config_t *config, int port)
{
    if (!config) return -1;
    memset(config, 0, sizeof(*config));
    config->listen_port = port;

    /* Generate server long-term ML-DSA-65 identity keypair from seed */
    uint8_t server_seed[PQVEIL_DSA_SEED_BYTES];
    memset(server_seed, 0x88, sizeof(server_seed));

    if (pqveil_dsa_keypair_from_seed(config->server_identity_pk,
                                    config->server_identity_sk,
                                    server_seed) != 0) {
        return -1;
    }

    /* Trust-anchor: derive authorized client public key for mutual auth */
    uint8_t client_seed[PQVEIL_DSA_SEED_BYTES];
    uint8_t client_sk_tmp[PQVEIL_DSA_SECRET_KEY_BYTES];
    memset(client_seed, 0x77, sizeof(client_seed));
    pqveil_dsa_keypair_from_seed(config->authorized_client_pk, client_sk_tmp, client_seed);
    memset(client_sk_tmp, 0, sizeof(client_sk_tmp));

    return 0;
}

int pqveil_gateway_handle_client(
    int client_fd,
    const pqveil_gateway_config_t *config,
    pqveil_session_keys_t *session_keys)
{
    if (client_fd < 0 || !config || !session_keys) return -1;

    pqveil_server_handshake_t server_ctx;
    pqveil_msg_client_hello_t client_hello;
    pqveil_msg_server_hello_t server_hello;
    pqveil_msg_client_auth_t client_auth;

    // 1. Read ClientHello
    if (read_exact(client_fd, &client_hello, sizeof(client_hello)) != 0) {
        return -1;
    }

    // 2. Process ClientHello & Generate ServerHello
    if (pqveil_server_handshake_process_client_hello(
            &server_ctx,
            &client_hello,
            config->server_identity_sk,
            &server_hello) != 0) {
        return -2;
    }

    // 3. Send ServerHello
    if (write_exact(client_fd, &server_hello, sizeof(server_hello)) != 0) {
        return -3;
    }

    // 4. Read ClientAuth
    if (read_exact(client_fd, &client_auth, sizeof(client_auth)) != 0) {
        return -4;
    }

    // 5. Verify ClientAuth against pinned client identity key
    if (pqveil_server_handshake_verify_client_auth(
            &server_ctx,
            &client_auth,
            config->authorized_client_pk,
            session_keys) != 0) {
        return -5; // Client identity verification failed
    }

    return 0; // Handshake authenticated and session keys derived
}

