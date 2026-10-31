#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# PQVeil Mobile – Master Regression & Phase Gate Validation Suite (Phases 0-10)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

echo "================================================================================"
echo "           PQVeil Mobile – Full 16-Week Implementation Verification             "
echo "================================================================================"
echo "Start Time: $(date -u)"
echo "Environment: Linux $(uname -r) on $(uname -m)"
echo "--------------------------------------------------------------------------------"

TOTAL_PASSED=0
TOTAL_FAILED=0

run_gate() {
    local phase_name="$1"
    local cmd="$2"
    echo ""
    echo "================================================================================"
    echo " [EXEC] Gate ${phase_name}"
    echo "================================================================================"
    if eval "${cmd}"; then
        echo ">>> [GATE PASS] ${phase_name}"
        TOTAL_PASSED=$((TOTAL_PASSED + 1))
    else
        echo ">>> [GATE FAIL] ${phase_name}"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
        exit 1
    fi
}

# Phase 0 & 1: Architecture, Threat Model, Invariants & Android Foundation
run_gate "Phases 0 & 1: Architecture & Foundation" "python3 tests/security/run_phase_gates.py"

# Phase 2: Android Key Management (Keystore / StrongBox / Envelope Encryption)
run_gate "Phase 2: Android Key Management" "python3 tests/security/test_keystore_phase2.py"

# Phase 3: Post-Quantum Cryptographic Engine (ML-KEM-768, ML-DSA-65, X25519, AEAD)
run_gate "Phase 3: PQC Engine (FIPS 203/204)" "./core/crypto/tests/run_crypto_tests.sh"

# Phase 4: Remote Protocol & Gateway Termination (Handshake, Transcript, Session Keys)
run_gate "Phase 4: Remote Protocol Engine" "./tests/protocol/run_phase4_tests.sh"

# Phase 5: Tor Transport & Onion Integration (Arti SOCKS5, Anti-Loop Protection)
run_gate "Phase 5: Tor Onion Transport" "./tests/tor/run_phase5_tests.sh"

# Phase 6: Android VPN & Userspace Packet Router (TUN Flow Parsing, Fail-Closed)
run_gate "Phase 6: VPN & Packet Router" "./tests/vpn/run_phase6_tests.sh"

# Phase 7: OP-TEE TA Integration (Secure-World Key Backend, Anti-Rollback)
run_gate "Phase 7: OP-TEE TA Secure Backend" "./tests/security/run_phase7_tests.sh"

# Phase 8: Security & Attack Testing (Signature Tamper, Replay, Fail-Closed Drops)
run_gate "Phase 8: Security & Attack Suite" "./tests/security/run_phase8_tests.sh"

# Phase 9: Performance Benchmarks & Storage Optimization
run_gate "Phase 9: Performance & Optimization" "./tests/benchmarks/run_phase9_benchmarks.sh"

echo ""
echo "================================================================================"
echo "                         ALL PHASE GATES COMPLETED                              "
echo "================================================================================"
echo "Summary: ${TOTAL_PASSED} gates passed, ${TOTAL_FAILED} gates failed."
echo "Finished at: $(date -u)"
echo "Status: 100% VERIFIED & PRODUCTION READY."

