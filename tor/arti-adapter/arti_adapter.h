/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil Tor Transport – Arti Adapter Interface
 *
 * Provides an isolated, version-pinned transport abstraction over
 * the Tor / Arti network for Android and Linux environments.
 */

#ifndef PQVEIL_TOR_ARTI_ADAPTER_H
#define PQVEIL_TOR_ARTI_ADAPTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PQVEIL_ONION_ADDR_MAX_LEN 128
#define PQVEIL_SOCKS5_DEFAULT_PORT 9050

typedef int (*pqveil_socket_protect_fn)(int socket_fd, void *user_data);

typedef struct {
    char socks_host[64];
    uint16_t socks_port;
    char tor_data_dir[256];
    bool isolate_streams;
    pqveil_socket_protect_fn protect_fn;
    void *protect_user_data;
} pqveil_tor_config_t;

typedef struct {
    uint8_t bootstrap_percent;
    bool circuit_established;
    bool is_running;
    char last_error[128];
} pqveil_tor_status_t;

typedef struct {
    pqveil_tor_config_t config;
    pqveil_tor_status_t status;
    int control_socket_fd;
} pqveil_tor_client_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes the Tor client adapter configuration.
 */
int pqveil_tor_init(pqveil_tor_client_t *client, const pqveil_tor_config_t *config);

/**
 * Monitors Tor bootstrap progress until circuit establishment.
 * Invokes optional progress callback.
 */
typedef void (*pqveil_tor_bootstrap_cb)(uint8_t percentage, const char *status_msg, void *user_data);
int pqveil_tor_bootstrap(pqveil_tor_client_t *client, pqveil_tor_bootstrap_cb cb, void *user_data);

/**
 * Connects to a remote v3 .onion endpoint through the SOCKS5 proxy.
 * Uses ATYP 0x03 (Domain Name) to prevent local DNS leakage.
 * Invokes protect_fn on the socket to prevent VPN routing loops.
 */
int pqveil_tor_connect_onion(
    pqveil_tor_client_t *client,
    const char *onion_host,
    uint16_t port,
    int *stream_fd
);

/**
 * Queries current bootstrap and circuit status.
 */
int pqveil_tor_get_status(pqveil_tor_client_t *client, pqveil_tor_status_t *status);

/**
 * Gracefully shuts down active circuits and closes connections.
 */
void pqveil_tor_destroy(pqveil_tor_client_t *client);

#ifdef __cplusplus
}
#endif

#endif /* PQVEIL_TOR_ARTI_ADAPTER_H */

