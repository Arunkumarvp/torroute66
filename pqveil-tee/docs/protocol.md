# PQVeil-TEE Protocol Specification: `usepqc`

## 1. Overview
`usepqc` is a hybrid post-quantum VPN handshake and transport framing protocol designed to operate over Tor TCP circuits to a v3 .onion hidden service.

## 2. Handshake Phase

```text
Client (Normal World)                  Server (Onion Endpoint)
       |                                          |
       | ------ ClientHello --------------------> |
       |   - Ephemeral X25519 Pub (32 B)          |
       |   - Ephemeral ML-KEM-768 Pub (1184 B)    |
       |                                          |
       | <----- ServerHello --------------------- |
       |   - Ephemeral X25519 Pub (32 B)          |
       |   - ML-KEM-768 Ciphertext (1088 B)       |
       |   - ML-DSA-65 Signature over transcript  |
       |                                          |
  [TA: SIGN_TRANSCRIPT]                           |
       | ------ ClientAuth ---------------------> |
       |   - ML-DSA-65 Signature (3309 B)         |
       |                                          |
```

### Key Derivation
$$\text{IKM} = \text{X25519\_SS} \parallel \text{ML-KEM-768\_SS}$$
$$\text{PRK} = \text{HKDF-Extract}(\text{Salt} = \text{TranscriptHash}, \text{IKM})$$
$$K_{\text{c2s}} \parallel K_{\text{s2c}} = \text{HKDF-Expand}(\text{PRK}, \text{"PQVeil usepqc v1"}, 64)$$

## 3. Data Transport Phase
- Records are framed over TCP with a 4-byte big-endian length prefix.
- Payload encrypted with ChaCha20-Poly1305 (256-bit key, 96-bit nonce derived from monotonic 64-bit sequence counter).
- Re-keying occurs after every $2^{24}$ packets or 1 hour of traffic.

