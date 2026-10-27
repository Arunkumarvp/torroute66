# PQVeil-TEE

**A post-quantum VPN-over-Tor client whose long-term identity keys live inside an OP-TEE Trusted Application.**

Status: learning / research project · Target: QEMU Armv8 (`qemu_v8`) first, physical TrustZone board later

---

## 1. Research question

> What does it cost (latency, memory, complexity) and what does it gain (key non-exfiltration under normal-world compromise) to move post-quantum identity operations into an OP-TEE Trusted Application?

Everything else in the project (VPN, Tor, nftables) exists to give that question a realistic setting. If scope gets tight, cut networking features, not the TA and its evaluation.

## 2. Security claim

**Claim:** If the normal-world OS (Kali Linux) is fully compromised, an attacker can *use* the device's identity key only while the compromise lasts. They cannot *extract* it, and they cannot forge policy or health statements after the compromise ends.

**What this does not claim:**
- The normal-world kernel, VPN process and Tor process are not protected by OP-TEE.
- Session keys derived in the normal world are exposed if the normal world is compromised.
- Physical attacks, fault injection and TA side channels are out of scope for v1 (documented, not defended).

## 3. Threat model

| Adversary | Capability | Defended? |
|---|---|---|
| Network observer / harvest-now-decrypt-later | Records traffic, later has a quantum computer | Yes: hybrid X25519 + ML-KEM-768 |
| Malicious Tor exit / relay | Sees or tampers with exit traffic | Yes: onion service endpoint, no exit |
| Remote attacker with root in normal world | Calls the TA, reads normal-world memory, edits nftables | Partly: cannot extract identity key; can misuse it during compromise |
| Rogue local process | Opens the TEE device and calls the TA | Yes: caller checks and device access policy |
| Storage rollback | Restores old sealed state | Documented only on QEMU (no RPMB); defended with RPMB hardware |
| Physical / side-channel / fault injection | Probes or glitches hardware | No (out of scope for v1) |

## 4. Architecture

```
NORMAL WORLD (Kali Linux)                       SECURE WORLD (OP-TEE)
┌─────────────────────────────────┐            ┌──────────────────────────────┐
│ Rust controller                 │            │ PQVeil Trusted Application   │
│  - starts/monitors services     │  TEE       │  - sealed 64-byte KEM seed   │
│  - tee_client.rs  ──────────────┼──Client───▶│  - sealed ML-DSA-65 seed     │
│  - health.rs (Tor control port) │  API       │  - sign_transcript           │
│                                 │            │  - decaps                    │
│ usepqc handshake (C)            │            │  - sign_health_report        │
│  - ephemeral X25519             │            │  - policy verify / seal      │
│  - ML-KEM-768 encaps            │            │  - monotonic counter state   │
│  - HKDF-SHA3-256                │            └──────────────────────────────┘
│  - ChaCha20-Poly1305 data path  │
│                                 │
│ Tor (SocksPort/TransPort/DNS)   │
│ nftables fail-closed policy     │
└─────────────────────────────────┘
```

### 4.1 Crypto split

| Operation | Location | Why |
|---|---|---|
| ML-DSA-65 identity signing (handshake transcript, health report) | **TA** | Long-term key must never leave the secure world |
| ML-KEM-768 static decapsulation (if used) | **TA** | Same reason |
| Ephemeral X25519 + ML-KEM-768 session handshake | Normal world | Forward secrecy; ephemeral keys are low value |
| HKDF-SHA3-256, ChaCha20-Poly1305 data path | Normal world | Per-packet SMC calls would be far too slow |
| Policy verification and sealed policy state | **TA** | Integrity of the fail-closed rules |

**Seed-based key storage:** the TA stores only the 64-byte ML-KEM seed and the ML-DSA seed, and regenerates expanded keys on demand. ML-KEM-768 expanded decapsulation keys are 2400 bytes and ML-DSA-65 secret keys are 4032 bytes, so regeneration lowers secure-RAM pressure and shrinks the sealed object.

### 4.2 TA command interface (draft)

| Command | In | Out | Notes |
|---|---|---|---|
| `GET_STATUS` | none | version, counter, storage mode | Harmless first command for bring-up |
| `PROVISION` | none | ML-DSA-65 public key | One-time; seeds generated with `TEE_GenerateRandom` |
| `SIGN_TRANSCRIPT` | transcript hash | signature (3309 B) | Domain-separated: `"PQVeil v1 handshake"` |
| `DECAPS` | KEM ciphertext (1088 B) | 32-byte shared secret | Only if a static KEM key is used |
| `SIGN_HEALTH` | nonce, tunnel/Tor state flags | signed report | Remote endpoint verifies |
| `LOAD_POLICY` | signed policy blob | ok / reject | Version must be greater than stored counter |

Rules for every command: copy all input out of shared memory *before* validating it (avoid double-fetch/TOCTOU), check `TEE_Param` types and sizes, never return key material, zeroize buffers on every exit path.

## 5. Handshake: `usepqc`

1. Client generates ephemeral X25519 key and ML-KEM-768 keypair, sends both public keys.
2. Server returns X25519 public key and ML-KEM ciphertext, plus an ML-DSA-65 signature over the transcript.
3. Client verifies the server signature (against a pinned key or the onion identity binding).
4. Client calls the TA's `SIGN_TRANSCRIPT` to prove its own identity.
5. Both sides derive keys: `HKDF-SHA3-256(salt = transcript hash, ikm = x25519_ss || mlkem_ss, info = "PQVeil usepqc v1")`, split into client-to-server and server-to-client keys.
6. Data flows as ChaCha20-Poly1305 records with per-direction counters and periodic rekeying.

Implementation notes:
- Reject X25519 low-order points (libsodium `crypto_scalarmult` returns an error).
- Inside the TA use a compact constant-time ML-KEM/ML-DSA implementation (for example mlkem-native or PQClean), not liboqs. Take randomness from `TEE_GenerateRandom`.
- Set `TA_STACK_SIZE` and `TA_DATA_SIZE` in `user_ta_header_defines.h` for ML-DSA signing's stack use, and measure the actual peak.
- Normal-world side can use liboqs + libsodium + OpenSSL for the first version.
- Note that OpenSSL 3.5+'s `X25519MLKEM768` TLS group covers key exchange only. Authentication is a separate design decision, which is why PQVeil uses its own signed transcript.

## 6. Network design

### 6.1 Topology: tunnel inside Tor to an onion service

- VPN endpoint runs as a **v3 onion service**: no exit node, and the onion address authenticates the server.
- Tor carries TCP only, so the tunnel is **TCP-framed** (length-prefixed records), not UDP/WireGuard-style. Expect a TCP-over-TCP cost; measure it.
- The PQ handshake runs end to end inside the Tor circuit, so post-quantum protection does not depend on Tor's classical circuit crypto.

### 6.2 Client connection

Connect through Tor's SOCKS5 proxy (`127.0.0.1:9050`) sending the hostname to Tor (ATYP `0x03`) so no local DNS lookup occurs. Parse the SOCKS reply by its ATYP rather than assuming a fixed length.

### 6.3 System-wide fail-closed routing

```
# /etc/tor/torrc
SocksPort 9050 IsolateSOCKSAuth
TransPort 9040
DNSPort 5353
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 10.192.0.0/10
ControlPort 9051
CookieAuthentication 1
```

```
table inet torroute {
  chain out {
    type nat hook output priority -100;
    meta skuid "debian-tor" return
    oifname "lo" return
    udp dport 53 redirect to :5353
    tcp flags syn redirect to :9040
  }
  chain filter {
    type filter hook output priority 0; policy drop;
    meta skuid "debian-tor" accept
    oifname "lo" accept
  }
}
```

Design requirements:
- Default **drop** policy, loaded before the controller starts, so nothing leaks at boot or if Tor dies.
- Block or handle IPv6 explicitly; no DNS outside Tor's `DNSPort`.
- Tor Browser alone only protects the browser; system-wide protection needs the transparent proxy rules above.

### 6.4 Health checks

Use the Tor control port (`GETINFO status/bootstrap-phase`, `status/circuit-established`) rather than an external website. Feed the result into the TA's `SIGN_HEALTH` so the remote end receives a signed statement.

## 7. Normal-world access control

Any process that can open `/dev/tee0` can call the TA. Mitigate with:
- TA-side caller checks (client login method and identity where the platform provides it).
- A BPF-LSM or SELinux rule so only the controller binary may open the TEE device.
- Rate limiting and bounded input sizes on TA commands.

## 8. Repository layout

```
pqveil-tee/
├── README.md
├── docs/
│   ├── threat-model.md
│   ├── protocol.md
│   └── evaluation.md
├── host/rust-controller/
│   └── src/{main.rs, tee_client.rs, vpn.rs, tor.rs, health.rs}
├── ta/pqveil_ta/
│   ├── user_ta_header_defines.h
│   ├── ta_entry.c
│   ├── crypto_service.c
│   ├── policy_service.c
│   └── sub.mk
├── usepqc/                  # C handshake library (normal world)
├── network/
│   ├── torrc
│   ├── nftables-policy.conf
│   └── routing-tests.sh
├── formal/
│   └── PQVeilTA.tla         # TA state machine + fail-closed invariants
└── tests/
    ├── kat/                 # NIST ACVP known-answer tests
    ├── ta_fuzz/
    ├── network_failure/
    └── interop/
```

Alternative: write the TA in Rust using the Teaclave TrustZone SDK instead of C. Decide after the C baseline works.

## 9. Milestones

1. **Platform:** build OP-TEE for `qemu_v8`, boot it, run the hello-world TA, confirm the Linux TEE device and client library work.
2. **Minimal TA:** `GET_STATUS` called from the Rust controller.
3. **Sealed state:** store a seed in OP-TEE secure storage; record whether storage is REE-FS or RPMB-backed.
4. **PQ in the TA:** ML-KEM-768 and ML-DSA-65 passing NIST known-answer tests inside the TA; measure heap and stack peaks.
5. **`usepqc` handshake:** hybrid handshake in C with signing and decapsulation delegated to the TA.
6. **Tor transport:** TCP-framed tunnel to an onion endpoint, SOCKS5 client, nftables fail-closed rules.
7. **Hardening:** TA command fuzzing, shared-memory TOCTOU tests, caller checks, zeroization review.
8. **Formal model:** TLA+ spec of the TA state machine and the fail-closed property.
9. **Evaluation and write-up:** benchmarks, threat-model review, honest limitations.

## 10. Verification and testing

| Area | Method |
|---|---|
| Algorithm correctness | NIST ACVP known-answer tests for ML-KEM-768 and ML-DSA-65 |
| TA robustness | Fuzz command IDs, parameter types and sizes; double-fetch tests on shared memory |
| Side channels | Timing tests (dudect) on the TA implementations; document, don't claim, resistance |
| Network | Kill Tor mid-session, drop the tunnel, reboot, flip IPv6, attempt DNS leaks; verify zero egress |
| Policy integrity | Tamper with the policy blob, replay old versions, restart the TA |
| Storage | Restore an old sealed object; record behavior on REE-FS vs RPMB |
| Formal | TLA+ invariants: (1) no command returns key material, (2) no egress outside the tunnel, (3) policy version never decreases |

## 11. Evaluation metrics

- Handshake latency: TA-backed signing vs normal-world signing.
- SMC/TA invocation overhead per command.
- Secure-world peak heap and stack for ML-KEM-768 and ML-DSA-65.
- Sealed object size: seed-only vs expanded keys.
- Tunnel throughput and latency over Tor vs direct (TCP-over-TCP cost).
- Recovery time after Tor or tunnel failure.

## 12. Risks and open questions

- Does the chosen OP-TEE build expose any PQC primitives natively? Assume not and verify; plan to bring your own implementation.
- QEMU provides no RPMB and no real hardware root of trust, so rollback and attestation results are demonstrations, not guarantees.
- Constant-time behavior of third-party PQC code on the target cannot be assumed; test it.
- Remote attestation of the TA to the server needs a trust anchor; on QEMU this is simulated.
- Tor onion service performance may limit the tunnel; if so, document it rather than hide it.

## 13. Out of scope for v1

Protecting the normal-world kernel, running the whole data path in the TA, hardware fault-injection resistance, anonymity guarantees beyond Tor's own, and production hardening.

## 14. Deliverables

- Working QEMU demo: Rust controller, TA, hybrid handshake, Tor onion tunnel, fail-closed firewall.
- TLA+ specification with model-checked invariants.
- Benchmark report and threat-model document.
- Short write-up answering the research question in Section 1.