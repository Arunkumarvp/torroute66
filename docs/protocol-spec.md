# PQVeil Mobile Protocol Specification (`usepqc` v1)

## 1. Handshake Overview
The `usepqc` protocol runs inside a Tor SOCKS5 TCP stream connected to a v3 onion service. It provides mutual post-quantum authentication and forward-secret session key establishment.

### Cryptographic Primitives
- **Classical Ephemeral Key Exchange:** X25519 (RFC 7748)
- **Post-Quantum Ephemeral KEM:** ML-KEM-768 (NIST FIPS 203)
- **Identity Authentication:** ML-DSA-65 (NIST FIPS 204)
- **Key Derivation Function:** HKDF-SHA3-256 (RFC 5869 with SHA3-256)
- **Authenticated Encryption:** ChaCha20-Poly1305 (RFC 8439)

## 2. Message Flow

```text
Client (Mobile / Controller)                               Remote Gateway (Server)
      |                                                                 |
      | 1. ClientHello:                                                 |
      |    version (2B) || X25519_pk (32B) || MLKEM768_pk (1184B)       |
      | --------------------------------------------------------------> |
      |                                                                 |
      |                                              2. ServerHello:    |
      |                                                 X25519_pk (32B) |
      |                                           MLKEM768_ct (1088B)   |
      |                                          MLDSA65_sig (3309B)    |
      | <-------------------------------------------------------------- |
      |                                                                 |
 3. Client Verification & Sign:                                         |
    - Verify Server MLDSA65_sig over Transcript 1                       |
    - Sign Transcript 2 with Client MLDSA65 Identity Key                |
      (delegated to Android Keystore or OP-TEE TA)                      |
      |                                                                 |
      | 4. ClientAuth:                                                  |
      |    MLDSA65_sig (3309B)                                          |
      | --------------------------------------------------------------> |
      |                                                                 |
 5. Key Derivation:                                                     |
    - IKM = X25519_ss (32B) || MLKEM768_ss (32B)                        |
    - PRK = HKDF-Extract(salt = TranscriptHash, IKM)                    |
    - K_c2s || K_s2c = HKDF-Expand(PRK, "PQVeil usepqc v1", 64B)        |
      |                                                                 |
      | <============ Authenticated Tunnel Established ===============> |
```

## 3. Transcript Hash Structure
- `Transcript 1` = `ClientHello` || `ServerHello[pub_keys || ciphertext]`
- `Transcript 2` = `Transcript 1` || `ServerHello[sig]`
- Domain separation tag: `"PQVeil v1 handshake"`

## 4. Transport Framing
Data packets are encapsulated in length-prefixed records:
- `Length` (2 bytes, big-endian)
- `Payload`: ChaCha20-Poly1305 ciphertext
- `Tag`: 16-byte Poly1305 authenticator
- 96-bit nonce constructed from monotonic 64-bit sequence counter.

