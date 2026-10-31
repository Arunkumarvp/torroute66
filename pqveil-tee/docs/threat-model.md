# PQVeil-TEE Threat Model & Security Analysis

## 1. Scope & System Model
PQVeil-TEE isolates post-quantum identity operations (ML-DSA-65 signing, ML-KEM-768 decapsulation, monotonic policy checks) inside an ARM TrustZone OP-TEE Trusted Application (TA). The normal-world OS (Kali Linux) executes the controller, user application, Tor daemon, and transparent proxy rules.

## 2. Adversary Model & Capabilities

| Adversary Class | Capabilities | Mitigations in PQVeil-TEE |
|---|---|---|
| **Network Observer (Harvest-Now-Decrypt-Later)** | Passively records link traffic; later obtains cryptanalytically relevant quantum computer (CRQC). | **Hybrid X25519 + ML-KEM-768 key exchange**; secrecy preserved even if discrete logs are broken. |
| **Malicious Tor Exit / Relay** | Eavesdrops or tampers with exit traffic. | **Direct v3 Onion Service endpoint**. No exit nodes are traversed; endpoints authenticate cryptographically. |
| **Normal-World OS Compromise (Root)** | Attacker gains kernel/root in normal world, inspects memory, alters firewall, sends arbitrary SMC calls. | **Key Non-Exfiltration**: Identity seeds never leave secure world. Private keys cannot be extracted. Once compromise ends, adversary cannot forge signatures. |
| **Rogue Local Process** | Attempts to open `/dev/tee0` to misuse the TA. | Device file permissions (`chmod 0600 /dev/tee0`), SELinux/BPF-LSM policy limiting access strictly to the controller binary. |
| **Storage Rollback / State Replay** | Replaces sealed storage with old snapshots to downgrade policy rules. | **Monotonic counter enforcement** in TA. On hardware with RPMB (Replay Protected Memory Block), physical replay protection is active. |
| **Side-Channel & Fault Injection** | EM probes, cache timing, clock glitching. | Out of scope for v1 (documented; constant-time algorithm implementations used to minimize timing leaks). |

## 3. Trust Boundaries
- **Trusted Computing Base (TCB):** ARM TrustZone, OP-TEE OS core, PQVeil TA binary, Secure Storage / RPMB.
- **Untrusted:** Normal-world Linux kernel, Tor process, controller daemon, external network.

