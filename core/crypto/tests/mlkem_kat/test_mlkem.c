// SPDX-License-Identifier: BSD-2-Clause
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "kem.h"

int main(void) {
    printf("[*] Running Core Crypto ML-KEM-768 Unit Tests...\n");

    uint8_t seed[PQVEIL_KEM_SEED_BYTES];
    memset(seed, 0x42, sizeof(seed));

    uint8_t pk[PQVEIL_KEM_PUBLIC_KEY_BYTES];
    uint8_t sk[PQVEIL_KEM_SECRET_KEY_BYTES];

    // 1. Key generation from seed
    int ret = pqveil_kem_keypair_from_seed(pk, sk, seed);
    assert(ret == 0);
    printf("    [+] pqveil_kem_keypair_from_seed: SUCCESS\n");

    // 2. Encapsulation
    uint8_t ct[PQVEIL_KEM_CIPHERTEXT_BYTES];
    uint8_t ss_enc[PQVEIL_KEM_SHARED_SECRET_BYTES];
    ret = pqveil_kem_encaps(ct, ss_enc, pk);
    assert(ret == 0);
    printf("    [+] pqveil_kem_encaps: SUCCESS\n");

    // 3. Decapsulation
    uint8_t ss_dec[PQVEIL_KEM_SHARED_SECRET_BYTES];
    ret = pqveil_kem_decaps(ss_dec, ct, sk);
    assert(ret == 0);
    printf("    [+] pqveil_kem_decaps: SUCCESS\n");

    // 4. Verify shared secret match
    assert(memcmp(ss_enc, ss_dec, PQVEIL_KEM_SHARED_SECRET_BYTES) == 0);
    printf("    [+] Shared secrets match: SUCCESS\n");

    printf("[PASS] ML-KEM-768 Core Tests Completed Successfully.\n");
    return 0;
}

