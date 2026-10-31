#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# PQVeil Phase 8: Security, Attack & Invariant Test Runner

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=========================================================="
echo " Building & Running PQVeil Phase 8 Security Test Suite"
echo "=========================================================="

BUILD_DIR="${ROOT_DIR}/build/phase8"
mkdir -p "${BUILD_DIR}"

gcc -Wall -Wextra -O2 \
    -I"${ROOT_DIR}/core/protocol" \
    -I"${ROOT_DIR}/core/packet" \
    -I"${ROOT_DIR}/secure-world/tee-broker" \
    -I"${ROOT_DIR}/core/crypto/include" \
    "${ROOT_DIR}/tests/security/test_security_phase8.c" \
    "${ROOT_DIR}/core/protocol/handshake.c" \
    "${ROOT_DIR}/core/packet/packet_router.c" \
    "${ROOT_DIR}/secure-world/tee-broker/tee_broker.c" \
    "${ROOT_DIR}/core/crypto/src/dsa_adapter.c" \
    "${ROOT_DIR}/core/crypto/src/kem_adapter.c" \
    "${ROOT_DIR}/core/crypto/src/x25519.c" \
    "${ROOT_DIR}/core/crypto/src/aead_adapter.c" \
    -o "${BUILD_DIR}/test_security_phase8"

echo "[+] Compilation successful: ${BUILD_DIR}/test_security_phase8"
echo "[*] Executing Phase 8 tests..."
"${BUILD_DIR}/test_security_phase8"
echo "[+] Phase 8 execution verified."

