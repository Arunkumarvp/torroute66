#!/usr/bin/env bash
# PQVeil Phase 5 Tor Integration Test Runner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin"

mkdir -p "${BIN_DIR}"

echo "=========================================================="
echo " Compiling & Running PQVeil Phase 5 Tor Integration Suite"
echo "=========================================================="

CFLAGS="-Wall -Wextra -Werror -O2 \
    -I${ROOT_DIR}/core/crypto/include \
    -I${ROOT_DIR}/core/protocol \
    -I${ROOT_DIR}/server/gateway \
    -I${ROOT_DIR}/tor/arti-adapter"

gcc ${CFLAGS} \
    "${ROOT_DIR}/core/crypto/src/kem_adapter.c" \
    "${ROOT_DIR}/core/crypto/src/dsa_adapter.c" \
    "${ROOT_DIR}/core/crypto/src/x25519.c" \
    "${ROOT_DIR}/core/crypto/src/aead_adapter.c" \
    "${ROOT_DIR}/core/protocol/handshake.c" \
    "${ROOT_DIR}/server/gateway/gateway.c" \
    "${ROOT_DIR}/tor/arti-adapter/arti_adapter.c" \
    "${SCRIPT_DIR}/test_tor_phase5.c" \
    -lpthread \
    -o "${BIN_DIR}/test_tor_phase5"

"${BIN_DIR}/test_tor_phase5"

