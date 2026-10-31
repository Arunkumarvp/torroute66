# PQVeil-TEE Performance & Security Evaluation Plan

## 1. Metrics to Evaluate

1. **SMC & TA Invocation Overhead:**
   - Round-trip invocation cost between normal world and OP-TEE for `GET_STATUS`, `SIGN_TRANSCRIPT`, and `DECAPS`.
   - Baseline measurement via Linux `perf` and OP-TEE benchmark framework (`CFG_TEE_BENCHMARK=y`).

2. **Memory Footprint in Secure World:**
   - Stack watermark during ML-DSA-65 signing (target: verify $\le 16$ KB actual peak).
   - Heap utilization with seed-based storage (64 bytes) vs expanded key storage ($>6$ KB).

3. **Handshake Latency Breakdown:**
   - Ephemeral X25519 generation + ECDH.
   - ML-KEM-768 encaps / decaps.
   - ML-DSA-65 signing inside TA vs normal world software baseline.
   - Tor circuit round-trip time (RTT) to v3 onion endpoint.

4. **Network Throughput & TCP-over-TCP Penalty:**
   - iperf3 throughput through transparent proxy (`torroute`) vs direct Tor SOCKS5 vs raw TCP.
   - Jitter and tail latency under packet loss.

5. **Fail-Closed Resilience:**
   - Time to zero-egress upon SIGKILL to the Tor daemon.
   - Verification of zero external DNS leaks across 10,000 synthetic queries.

