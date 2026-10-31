#!/usr/bin/env bash
# PQVeil Core Cryptographic Engine Test Runner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRYPTO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin"

mkdir -p "${BIN_DIR}"

echo "=========================================================="
echo " Compiling & Running PQVeil Core Crypto Test Matrix"
echo "=========================================================="

CFLAGS="-Wall -Wextra -Werror -O2 -I${CRYPTO_DIR}/include"

# 1. Compile and run ML-KEM-768 tests
echo "[*] Building ML-KEM-768 test harness..."
gcc ${CFLAGS} \
    "${CRYPTO_DIR}/src/kem_adapter.c" \
    "${SCRIPT_DIR}/mlkem_kat/test_mlkem.c" \
    -o "${BIN_DIR}/test_mlkem"
"${BIN_DIR}/test_mlkem"

# 2. Compile and run ML-DSA-65 tests
echo "[*] Building ML-DSA-65 test harness..."
gcc ${CFLAGS} \
    "${CRYPTO_DIR}/src/dsa_adapter.c" \
    "${SCRIPT_DIR}/mldsa_kat/test_mldsa.c" \
    -o "${BIN_DIR}/test_mldsa"
"${BIN_DIR}/test_mldsa"

# 3. Compile and run AEAD, X25519 & HKDF tests
echo "[*] Building AEAD / X25519 / HKDF test harness..."
gcc ${CFLAGS} \
    "${CRYPTO_DIR}/src/x25519.c" \
    "${CRYPTO_DIR}/src/aead_adapter.c" \
    "${SCRIPT_DIR}/aead_tests/test_aead.c" \
    -o "${BIN_DIR}/test_aead"
"${BIN_DIR}/test_aead"

echo "=========================================================="
echo " [SUCCESS] All Core Post-Quantum Crypto Tests PASSED!"
echo "=========================================================="

