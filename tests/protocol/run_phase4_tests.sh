#!/usr/bin/env bash
# PQVeil Phase 4 Remote Protocol & Gateway Test Runner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin"

mkdir -p "${BIN_DIR}"

echo "=========================================================="
echo " Compiling & Running PQVeil Phase 4 Protocol Suite"
echo "=========================================================="

CFLAGS="-Wall -Wextra -Werror -O2 \
    -I${ROOT_DIR}/core/crypto/include \
    -I${ROOT_DIR}/core/protocol \
    -I${ROOT_DIR}/server/gateway"

gcc ${CFLAGS} \
    "${ROOT_DIR}/core/crypto/src/kem_adapter.c" \
    "${ROOT_DIR}/core/crypto/src/dsa_adapter.c" \
    "${ROOT_DIR}/core/crypto/src/x25519.c" \
    "${ROOT_DIR}/core/crypto/src/aead_adapter.c" \
    "${ROOT_DIR}/core/protocol/handshake.c" \
    "${ROOT_DIR}/server/gateway/gateway.c" \
    "${SCRIPT_DIR}/test_protocol_phase4.c" \
    -o "${BIN_DIR}/test_protocol_phase4"

"${BIN_DIR}/test_protocol_phase4"

