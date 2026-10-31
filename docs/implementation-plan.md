# PQVeil Mobile – 16-Week Implementation Roadmap

| Phase | Timeline | Primary Objective | Key Deliverables | Completion Gate |
|---|---|---|---|---|
| **0. Architecture Freeze** | Week 1 | Architecture, protocol spec, threat model & security invariants | `docs/` specifications, TLA+ invariants | All subsystem interfaces frozen |
| **1. Android Foundation** | Weeks 2–3 | Android Kotlin/Compose app + native Rust JNI bridge | APK skeleton, Dashboard UI, JNI bindings | APK installs, JNI calls work, lifecycle stable |
| **2. Key Management** | Week 4 | Android Keystore & hardware security level audit | AES-256-GCM wrapping, StrongBox/TEE detection | Wrapping round-trip passes, KeyInfo verified |
| **3. PQC Engine** | Weeks 5–6 | Standardized ML-KEM-768 & ML-DSA-65 algorithms | C/Rust PQC libraries, KAT runner | All NIST ACVP vectors pass |
| **4. Remote Protocol** | Weeks 7–8 | Direct client-server `usepqc` handshake (pre-Tor) | Handshake state machine, session key derivation | Both sides derive identical keys, replays rejected |
| **5. Tor Integration** | Weeks 9–10 | Arti onion transport adapter for Android | Arti AArch64 build, SOCKS5 client | Handshake runs end-to-end over .onion service |
| **6. Android VPN** | Weeks 11–12 | TUN interface & userspace TCP/IP packet forwarding | `VpnService`, socket `protect()`, DNS handling | Full bidirectional TCP over Tor, fail-closed drop |
| **7. OP-TEE Integration** | Week 13 | Connect OP-TEE TA backend to mobile abstraction | `SecureKeyBackend` dual support (Keystore/TA) | Same app works with either backend |
| **8. Security Testing** | Week 14 | Attack simulation, failure tests & leak validation | Penetration suite, crash recovery scripts | Zero DNS/IP leaks, replays fail safely |
| **9. Optimization** | Week 15 | Performance benchmarks & resource profiling | Latency benchmarks, RAM/CPU/battery metrics | Comparative research data collected |
| **10. Release & Report** | Week 16 | Final signed APK, gateway binary & research report | Production APK, Linux gateway, evaluation paper | Complete reproducible artifact package |

