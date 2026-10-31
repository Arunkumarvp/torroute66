// SPDX-License-Identifier: BSD-2-Clause
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "dsa.h"

int main(void) {
    printf("[*] Running Core Crypto ML-DSA-65 Unit Tests...\n");

    uint8_t seed[PQVEIL_DSA_SEED_BYTES];
    memset(seed, 0x99, sizeof(seed));

    uint8_t pk[PQVEIL_DSA_PUBLIC_KEY_BYTES];
    uint8_t sk[PQVEIL_DSA_SECRET_KEY_BYTES];

    // 1. Key generation from seed
    int ret = pqveil_dsa_keypair_from_seed(pk, sk, seed);
    assert(ret == 0);
    printf("    [+] pqveil_dsa_keypair_from_seed: SUCCESS\n");

    // 2. Signing
    const char *test_msg = "PQVeil handshake transcript verification test vector 2026";
    size_t msg_len = strlen(test_msg);
    uint8_t sig[PQVEIL_DSA_SIGNATURE_BYTES];
    size_t sig_len = 0;

    ret = pqveil_dsa_sign(sig, &sig_len, (const uint8_t *)test_msg, msg_len, sk);
    assert(ret == 0);
    assert(sig_len == PQVEIL_DSA_SIGNATURE_BYTES);
    printf("    [+] pqveil_dsa_sign: SUCCESS (sig_len=%zu)\n", sig_len);

    // 3. Verification
    ret = pqveil_dsa_verify(sig, sig_len, (const uint8_t *)test_msg, msg_len, pk);
    assert(ret == 0);
    printf("    [+] pqveil_dsa_verify valid signature: SUCCESS\n");

    // 4. Verification with corrupted message must fail
    const char *corrupted_msg = "Corrupted transcript verification test vector 2026";
    ret = pqveil_dsa_verify(sig, sig_len, (const uint8_t *)corrupted_msg, strlen(corrupted_msg), pk);
    assert(ret != 0);
    printf("    [+] pqveil_dsa_verify invalid message rejected: SUCCESS\n");

    printf("[PASS] ML-DSA-65 Core Tests Completed Successfully.\n");
    return 0;
}

