#!/usr/bin/env bash
# PQVeil Phase 6 VPN & Packet Routing Test Runner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BIN_DIR="${SCRIPT_DIR}/bin"

mkdir -p "${BIN_DIR}"

echo "=========================================================="
echo " Compiling & Running PQVeil Phase 6 VPN & Routing Suite"
echo "=========================================================="

CFLAGS="-Wall -Wextra -Werror -O2 \
    -I${ROOT_DIR}/core/packet"

gcc ${CFLAGS} \
    "${ROOT_DIR}/core/packet/packet_router.c" \
    "${SCRIPT_DIR}/test_vpn_phase6.c" \
    -o "${BIN_DIR}/test_vpn_phase6"

"${BIN_DIR}/test_vpn_phase6"

