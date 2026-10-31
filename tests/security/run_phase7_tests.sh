#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# PQVeil Phase 7: OP-TEE TA Integration Test Runner

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=========================================================="
echo " Building & Running PQVeil Phase 7 OP-TEE Suite"
echo "=========================================================="

BUILD_DIR="${ROOT_DIR}/build/phase7"
mkdir -p "${BUILD_DIR}"

gcc -Wall -Wextra -O2 \
    -I"${ROOT_DIR}/secure-world/tee-broker" \
    -I"${ROOT_DIR}/core/crypto/include" \
    "${ROOT_DIR}/tests/security/test_optee_phase7.c" \
    "${ROOT_DIR}/secure-world/tee-broker/tee_broker.c" \
    "${ROOT_DIR}/core/crypto/src/dsa_adapter.c" \
    "${ROOT_DIR}/core/crypto/src/kem_adapter.c" \
    -o "${BUILD_DIR}/test_optee_phase7"

echo "[+] Compilation successful: ${BUILD_DIR}/test_optee_phase7"
echo "[*] Executing Phase 7 tests..."
"${BUILD_DIR}/test_optee_phase7"
echo "[+] Phase 7 execution verified."

