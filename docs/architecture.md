# PQVeil Mobile & TEE System Architecture

## 1. Overview & Research Objective
**PQVeil Mobile** is an Android VPN client providing a post-quantum authenticated tunnel over Tor onion transport, driven by a hybrid key-protection architecture.

The project evaluates a critical comparative research question:
> **What are the security, latency, and resource trade-offs of isolating long-term Post-Quantum identity operations (ML-DSA-65) inside an ARM TrustZone OP-TEE Trusted Application (TA) compared to Android Keystore hardware-backed storage (TEE / StrongBox)?**

## 2. Environments & Boundaries

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ANDROID MOBILE ENVIRONMENT                      │
│                                                                        │
│   ┌──────────────────────────────────────────────────────────────┐    │
│   │ Kotlin / Jetpack Compose UI (Dashboard, Settings, Logs)       │    │
│   └───────────────────────────────┬──────────────────────────────┘    │
│                                   │                                    │
│   ┌───────────────────────────────▼──────────────────────────────┐    │
│   │ Android Platform Integration Layer                           │    │
│   │  - VpnService (TUN interface, protect() tunnel socket)       │    │
│   │  - Foreground Service (DATA_SYNC / SPECIAL_USE lifecycle)     │    │
│   │  - Android Keystore Wrapper (KeyInfo security level audit)    │    │
│   └───────────────────────────────┬──────────────────────────────┘    │
│                                   │ JNI (zero-secret boundary)         │
│   ┌───────────────────────────────▼──────────────────────────────┐    │
│   │ Rust Security Controller (`libpqveil_controller.so`)         │    │
│   │  - Session Manager & State Machine                           │    │
│   │  - Packet Processing & Userspace TCP/IP Stack                │    │
│   │  - Backend Abstraction (Android Keystore vs OP-TEE TEE Client)│    │
│   │  - Arti Tor SOCKS5 Onion Transport Adapter                   │    │
│   │  - Post-Quantum Crypto Engine (ML-KEM-768, ML-DSA-65, X25519)│    │
│   └──────────────────────────────────────────────────────────────┘    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Tor Circuit (SOCKS5 / Onion v3)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     REMOTE PQVEIL GATEWAY (Linux)                      │
│   - v3 Onion Service Listener                                          │
│   - usepqc Server Handshake Termination (ML-DSA-65 Auth)               │
│   - Length-Prefixed ChaCha20-Poly1305 Decapsulation                    │
│   - TUN Interface & Outbound Internet Egress                           │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│                 RESEARCH BACKEND: QEMU / OP-TEE (TrustZone)            │
│   - OP-TEE OS & `/dev/tee0` Client API                                 │
│   - PQVeil TA (UUID: `b3a4e5f6-7c8d-4a2b-9e0f-1d2c3b4a5e6f`)          │
│   - Sealed ML-DSA-65 & ML-KEM-768 Seeds                                │
│   - Monotonic Counter & Anti-Rollback Policy Engine                    │
└────────────────────────────────────────────────────────────────────────┘
```

## 3. Technology Ownership

| Layer | Language | Responsibility |
|---|---|---|
| **Android Interface** | Kotlin / Jetpack Compose | Mobile application UI, dashboard, connection toggles |
| **Android Integration** | Kotlin | `VpnService`, TUN routing, service lifecycle, `protect()` |
| **Security Controller** | Rust | Core state machine, packet handling, orchestration |
| **Cryptography** | C / Rust | FIPS 203 ML-KEM-768, FIPS 204 ML-DSA-65, X25519, HKDF-SHA3-256 |
| **Key Backends** | Kotlin / C / Rust | Android Keystore (production) vs OP-TEE TA (research) |
| **Tor Transport** | Rust (Arti) | SOCKS5 stream multiplexing & onion connectivity |
| **Remote Gateway** | Rust | Tunnel endpoint termination & TCP egress |
| **Formal Model** | TLA+ | State machine, non-exfiltration, fail-closed invariants |

