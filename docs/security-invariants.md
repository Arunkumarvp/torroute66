# PQVeil Mobile – Security Invariants & Acceptance Gates

These non-negotiable invariants govern the entire 16-week implementation. Any violation fails the build and test gates.

## Invariant 1: Key Non-Exfiltration
- **Rule:** Long-term private key seeds (ML-DSA-65) must never be transmitted across the JNI bridge, written to disk in unencrypted form, stored in UI state, or emitted to `logcat`.
- **Verification:** Binary inspection of JNI signatures; memory scrubbing with `zeroize`; static log scanning in CI.

## Invariant 2: Fail-Closed Network Egress
- **Rule:** If the Tor daemon crashes, Arti fails to bootstrap, or the VPN service is disconnected, all normal-world egress must be immediately dropped. Traffic must never fall back to an unencrypted or direct network connection.
- **Verification:** Synthetic `routing-tests.sh` and Android `VpnService` blackhole tests.

## Invariant 3: Anti-Loop Socket Protection
- **Rule:** Every underlying network socket created by the Tor client or Rust controller must be registered via `VpnService.protect(socketFd)` before connecting.
- **Verification:** Automated unit and instrumentation tests ensuring socket routing bypasses the TUN interface.

## Invariant 4: Monotonic Policy & State Counter
- **Rule:** Monotonic policy version counters must never decrease. Replayed state snapshots must be rejected with an explicit security fault.
- **Verification:** TLA+ model checking of `PQVeilTA.tla` and automated rollback test harness.

## Invariant 5: No Homegrown Cryptographic Primitives
- **Rule:** Cryptographic algorithms (ML-KEM-768 FIPS 203, ML-DSA-65 FIPS 204, X25519, ChaCha20-Poly1305) must use vetted, audited reference implementations (e.g., PQClean, liboqs, RustCrypto). Custom polynomial arithmetic or lattice operations are forbidden.
- **Verification:** NIST ACVP Known-Answer Tests (KAT) verified against standard vectors.

