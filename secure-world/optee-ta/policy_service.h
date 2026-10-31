/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil TA – Policy and Sealed Identity Service Header
 */

#ifndef PQVEIL_POLICY_SERVICE_H
#define PQVEIL_POLICY_SERVICE_H

#include <tee_internal_api.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

TEE_Result policy_service_init(void);
void policy_service_destroy(void);

bool policy_service_is_provisioned(void);
uint64_t policy_service_get_counter(void);

TEE_Result policy_service_provision(uint8_t *pk_out, uint32_t *pk_size);

TEE_Result policy_service_sign_transcript(const uint8_t hash[32],
                                          uint8_t *sig_out,
                                          uint32_t *sig_size);

TEE_Result policy_service_decaps(const uint8_t *ciphertext,
                                 uint8_t *shared_secret_out);

TEE_Result policy_service_sign_health(const uint8_t *nonce,
                                      uint32_t flags,
                                      uint8_t *report_out,
                                      uint32_t *report_size);

TEE_Result policy_service_load_policy(const uint8_t *blob, uint32_t size);

#endif /* PQVEIL_POLICY_SERVICE_H */

