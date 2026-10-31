# PQVeil Mobile – Threat Model & Security Boundaries

## 1. Scope
This threat model covers the Android mobile client running `PQVeil`, the remote gateway terminating the post-quantum onion tunnel, and the underlying cryptographic key management options (Android Keystore vs OP-TEE TA).

## 2. Threat Classification & Mitigations

| Threat Vector | Adversary Profile | Impact | Mitigation Strategy |
|---|---|---|---|
| **Harvest-Now-Decrypt-Later (HNDL)** | Passive Nation-State eavesdropper recording Tor & mobile egress. | Quantum decryption of recorded traffic once CRQC emerges. | **Hybrid Ephemeral Handshake:** X25519 ECDH + FIPS 203 ML-KEM-768. Compromise of discrete logs does not reveal session traffic. |
| **Malicious Tor Exit / Relay** | Rogue Tor node operator or compromised relay. | Eavesdropping, packet injection, traffic correlation. | **v3 Onion Service Routing:** Client connects directly to server's `.onion` address. No exit nodes are traversed. Endpoints mutually authenticate. |
| **Host Application Tampering (Root)** | Malicious app with root privilege on Android userland. | Private key exfiltration and identity forgery. | **Key Isolation:**<br>1. *Android Keystore*: StrongBox / TEE AES-256-GCM wrapped seeds with `KeyInfo` security-level gating.<br>2. *OP-TEE TA*: Identity seeds never leave secure world. TA only exports signatures (`SIGN_TRANSCRIPT`). |
| **VPN Socket Loop** | Tor sockets caught in client's own default TUN route. | Complete network deadlock or crash. | Mandatory invocation of `VpnService.protect(socketFd)` on all Tor and controller network sockets before connecting. |
| **State Replay / Policy Rollback** | Adversary restores old sealed policy storage. | Downgrade to obsolete network rules. | Monotonic policy counter enforced in hardware RPMB / OP-TEE secure storage. Counter must strictly increase. |
| **DNS & IPv6 Leaks** | Misconfigured resolver or unrouted IPv6 stack on cellular. | Real client IP or browsing activity disclosed to ISP. | System-wide TUN captures `0.0.0.0/0` and `::/0`. All DNS queries intercepted and routed through Tor `DNSPort`. Non-routed UDP/IPv6 is dropped fail-closed. |
| **Side-Channel & Fault Injection** | Physical attacker measuring EM or cache latency. | Leakage of lattice secrets. | Constant-time implementations of ML-KEM and ML-DSA (PQClean / FIPS parameter sets). Marked out of scope for v1 hardware fault attacks. |

