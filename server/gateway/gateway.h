/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil Remote Server Gateway Header
 */

#ifndef PQVEIL_SERVER_GATEWAY_H
#define PQVEIL_SERVER_GATEWAY_H

#include <stdint.h>
#include <stdbool.h>
#include "handshake.h"

typedef struct {
    uint8_t server_identity_pk[PQVEIL_DSA_PUBLIC_KEY_BYTES];
    uint8_t server_identity_sk[PQVEIL_DSA_SECRET_KEY_BYTES];
    uint8_t authorized_client_pk[PQVEIL_DSA_PUBLIC_KEY_BYTES];
    int listen_port;
} pqveil_gateway_config_t;

int pqveil_gateway_init(pqveil_gateway_config_t *config, int port);

/**
 * Executes a single complete server-side handshake on an active socket descriptor.
 * Derives session keys upon successful mutual post-quantum authentication.
 */
int pqveil_gateway_handle_client(
    int client_fd,
    const pqveil_gateway_config_t *config,
    pqveil_session_keys_t *session_keys
);

#endif /* PQVEIL_SERVER_GATEWAY_H */

