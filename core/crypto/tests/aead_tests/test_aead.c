// SPDX-License-Identifier: BSD-2-Clause
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "aead.h"

int main(void) {
    printf("[*] Running Core Crypto AEAD, X25519 & HKDF Unit Tests...\n");

    // 1. X25519 Test
    uint8_t priv_a[32], pub_a[32];
    uint8_t priv_b[32], pub_b[32];
    pqveil_x25519_keypair(pub_a, priv_a);
    pqveil_x25519_keypair(pub_b, priv_b);

    uint8_t ss_ab[32], ss_ba[32];
    assert(pqveil_x25519_scalarmult(ss_ab, priv_a, pub_b) == 0);
    assert(pqveil_x25519_scalarmult(ss_ba, priv_b, pub_a) == 0);
    assert(memcmp(ss_ab, ss_ba, 32) == 0);
    printf("    [+] X25519 Diffie-Hellman key agreement: SUCCESS\n");

    // Reject low order public key
    uint8_t zero_pk[32] = {0};
    uint8_t ss_zero[32];
    assert(pqveil_x25519_scalarmult(ss_zero, priv_a, zero_pk) != 0);
    printf("    [+] X25519 low-order point rejection: SUCCESS\n");

    // 2. HKDF-SHA3-256 Test
    uint8_t ikm[64];
    memset(ikm, 0x11, sizeof(ikm));
    uint8_t okm[64];
    assert(pqveil_hkdf_sha3_256(ikm, sizeof(ikm), (const uint8_t *)"salt", 4, (const uint8_t *)"info", 4, okm, sizeof(okm)) == 0);
    printf("    [+] HKDF-SHA3-256 key derivation: SUCCESS\n");

    // 3. ChaCha20-Poly1305 AEAD Test
    uint8_t key[32] = {0x42};
    uint8_t nonce[12] = {0x07};
    const char *plaintext = "PQVeil tunnel packet payload 2026";
    size_t pt_len = strlen(plaintext);
    uint8_t ciphertext[128];
    uint8_t tag[16];

    assert(pqveil_aead_seal(ciphertext, tag, (const uint8_t *)plaintext, pt_len, NULL, 0, nonce, key) == 0);
    printf("    [+] ChaCha20-Poly1305 seal: SUCCESS\n");

    uint8_t decrypted[128];
    assert(pqveil_aead_open(decrypted, ciphertext, pt_len, tag, NULL, 0, nonce, key) == 0);
    assert(memcmp(decrypted, plaintext, pt_len) == 0);
    printf("    [+] ChaCha20-Poly1305 open & tag verify: SUCCESS\n");

    // Tampered tag must fail
    tag[0] ^= 0x01;
    assert(pqveil_aead_open(decrypted, ciphertext, pt_len, tag, NULL, 0, nonce, key) != 0);
    printf("    [+] ChaCha20-Poly1305 tampered tag rejection: SUCCESS\n");

    printf("[PASS] AEAD, X25519 & HKDF Core Tests Completed Successfully.\n");
    return 0;
}

