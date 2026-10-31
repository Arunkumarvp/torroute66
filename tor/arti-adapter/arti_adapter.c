// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil Tor Transport – Arti Adapter Implementation
 *
 * Implements:
 *   - SOCKS5 proxy protocol with ATYP 0x03 (Domain Name) for .onion routing
 *   - Variable-length SOCKS5 reply parsing
 *   - Socket protection hook invocation (anti-loop protection)
 *   - Circuit state and bootstrap tracking
 */

#include "arti_adapter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int read_n_bytes(int fd, void *buf, size_t count)
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

static int write_n_bytes(int fd, const void *buf, size_t count)
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

int pqveil_tor_init(pqveil_tor_client_t *client, const pqveil_tor_config_t *config)
{
    if (!client) return -1;
    memset(client, 0, sizeof(*client));

    if (config) {
        memcpy(&client->config, config, sizeof(pqveil_tor_config_t));
    } else {
        strncpy(client->config.socks_host, "127.0.0.1", sizeof(client->config.socks_host) - 1);
        client->config.socks_port = PQVEIL_SOCKS5_DEFAULT_PORT;
    }

    if (client->config.socks_port == 0) {
        client->config.socks_port = PQVEIL_SOCKS5_DEFAULT_PORT;
    }

    client->status.is_running = true;
    client->status.bootstrap_percent = 0;
    client->status.circuit_established = false;
    client->control_socket_fd = -1;

    return 0;
}

int pqveil_tor_bootstrap(pqveil_tor_client_t *client, pqveil_tor_bootstrap_cb cb, void *user_data)
{
    if (!client) return -1;

    // Simulate / step through bootstrap progression
    const uint8_t stages[] = { 10, 25, 50, 75, 100 };
    const char *msgs[] = {
        "Connecting to directory server",
        "Loading consensus documents",
        "Loading microdescriptors",
        "Establishing 1-hop circuit",
        "Tor circuit established and ready"
    };

    for (size_t i = 0; i < 5; i++) {
        client->status.bootstrap_percent = stages[i];
        if (cb) {
            cb(stages[i], msgs[i], user_data);
        }
    }

    client->status.circuit_established = true;
    return 0;
}

int pqveil_tor_connect_onion(
    pqveil_tor_client_t *client,
    const char *onion_host,
    uint16_t port,
    int *stream_fd)
{
    if (!client || !onion_host || port == 0 || !stream_fd) {
        return -1;
    }

    size_t host_len = strlen(onion_host);
    if (host_len == 0 || host_len > 255) {
        snprintf(client->status.last_error, sizeof(client->status.last_error), "Invalid onion host length: %zu", host_len);
        return -2;
    }

    // 1. Create TCP Socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        snprintf(client->status.last_error, sizeof(client->status.last_error), "Socket creation failed: %s", strerror(errno));
        return -3;
    }

    // 2. Anti-Loop Protection Hook (Critical: VpnService.protect() must be called BEFORE connect)
    if (client->config.protect_fn) {
        if (client->config.protect_fn(sock, client->config.protect_user_data) != 0) {
            close(sock);
            snprintf(client->status.last_error, sizeof(client->status.last_error), "VpnService socket protect() failed");
            return -4;
        }
    }

    // 3. Connect to SOCKS5 Proxy
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(client->config.socks_port);
    if (inet_pton(AF_INET, client->config.socks_host, &proxy_addr.sin_addr) <= 0) {
        close(sock);
        snprintf(client->status.last_error, sizeof(client->status.last_error), "Invalid SOCKS5 proxy IP: %s", client->config.socks_host);
        return -5;
    }

    if (connect(sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) != 0) {
        close(sock);
        snprintf(client->status.last_error, sizeof(client->status.last_error), "Failed connecting to SOCKS5 proxy: %s", strerror(errno));
        return -6;
    }

    // 4. SOCKS5 Method Negotiation: [VER=5, NMETHODS=1, METHOD=0x00 (No Auth)]
    uint8_t greeting[3] = { 0x05, 0x01, 0x00 };
    if (write_n_bytes(sock, greeting, sizeof(greeting)) != 0) {
        close(sock);
        return -7;
    }

    uint8_t method_reply[2];
    if (read_n_bytes(sock, method_reply, sizeof(method_reply)) != 0 ||
        method_reply[0] != 0x05 || method_reply[1] != 0x00) {
        close(sock);
        snprintf(client->status.last_error, sizeof(client->status.last_error), "SOCKS5 method negotiation rejected");
        return -8;
    }

    // 5. SOCKS5 Connect Request with ATYP 0x03 (Domain Name)
    // Layout: [VER: 1B] [CMD: 1B] [RSV: 1B] [ATYP: 1B] [LEN: 1B] [DOMAIN: LEN] [PORT: 2B (BE)]
    size_t req_len = 4 + 1 + host_len + 2;
    uint8_t *req = (uint8_t *)malloc(req_len);
    if (!req) {
        close(sock);
        return -9;
    }

    req[0] = 0x05; // VER: 5
    req[1] = 0x01; // CMD: CONNECT (1)
    req[2] = 0x00; // RSV: 0
    req[3] = 0x03; // ATYP: Domain Name (enforces Tor handles the onion resolution)
    req[4] = (uint8_t)host_len;
    memcpy(req + 5, onion_host, host_len);
    req[5 + host_len] = (uint8_t)(port >> 8);
    req[5 + host_len + 1] = (uint8_t)(port & 0xFF);

    if (write_n_bytes(sock, req, req_len) != 0) {
        free(req);
        close(sock);
        return -10;
    }
    free(req);

    // 6. SOCKS5 Response Header: [VER: 1B] [REP: 1B] [RSV: 1B] [ATYP: 1B]
    uint8_t resp_hdr[4];
    if (read_n_bytes(sock, resp_hdr, sizeof(resp_hdr)) != 0) {
        close(sock);
        return -11;
    }

    if (resp_hdr[0] != 0x05 || resp_hdr[1] != 0x00) {
        close(sock);
        snprintf(client->status.last_error, sizeof(client->status.last_error),
                 "SOCKS5 connection refused by Tor with status 0x%02X", resp_hdr[1]);
        return -12;
    }

    // 7. Dynamic Variable-Length BND.ADDR Parsing (Do not assume fixed 10 bytes)
    switch (resp_hdr[3]) {
    case 0x01: { // IPv4: 4 bytes addr + 2 bytes port
        uint8_t bnd_ipv4[6];
        if (read_n_bytes(sock, bnd_ipv4, sizeof(bnd_ipv4)) != 0) {
            close(sock);
            return -13;
        }
        break;
    }
    case 0x03: { // Domain Name: 1 byte len + domain bytes + 2 bytes port
        uint8_t bnd_len;
        if (read_n_bytes(sock, &bnd_len, 1) != 0) {
            close(sock);
            return -13;
        }
        uint8_t *bnd_domain = (uint8_t *)malloc(bnd_len + 2);
        if (!bnd_domain) {
            close(sock);
            return -14;
        }
        if (read_n_bytes(sock, bnd_domain, bnd_len + 2) != 0) {
            free(bnd_domain);
            close(sock);
            return -13;
        }
        free(bnd_domain);
        break;
    }
    case 0x04: { // IPv6: 16 bytes addr + 2 bytes port
        uint8_t bnd_ipv6[18];
        if (read_n_bytes(sock, bnd_ipv6, sizeof(bnd_ipv6)) != 0) {
            close(sock);
            return -13;
        }
        break;
    }
    default:
        close(sock);
        snprintf(client->status.last_error, sizeof(client->status.last_error),
                 "Unsupported SOCKS5 ATYP in response: 0x%02X", resp_hdr[3]);
        return -15;
    }

    *stream_fd = sock;
    return 0;
}

int pqveil_tor_get_status(pqveil_tor_client_t *client, pqveil_tor_status_t *status)
{
    if (!client || !status) return -1;
    memcpy(status, &client->status, sizeof(pqveil_tor_status_t));
    return 0;
}

void pqveil_tor_destroy(pqveil_tor_client_t *client)
{
    if (client) {
        if (client->control_socket_fd >= 0) {
            close(client->control_socket_fd);
            client->control_socket_fd = -1;
        }
        client->status.is_running = false;
        client->status.circuit_established = false;
    }
}

