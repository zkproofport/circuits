#!/bin/bash
# Every dojang_playground fixture: the two accepted ones from the fixture
# wallet's real GIWA Sepolia issuances (one legacy, one EIP-1559), and the
# signed-but-never-sent transactions the acceptance run must refuse.
#
#   scripts/dojang-playground/make-fixtures.sh
#
# Needs circuits/.env.development (PRIVATE_KEY, GIWA_SEPOLIA_RPC_URL).
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT="$(cd "$SCRIPT_DIR/../.." && pwd)/dojang-playground"
GEN="$SCRIPT_DIR/generate-prover-toml.js"
VECTORS="$CIRCUIT/test-vectors"
mkdir -p "$VECTORS"

node "$GEN" --action --tx legacy --out "$CIRCUIT/Prover.toml"
node "$GEN" --tx eip1559 --out "$CIRCUIT/Prover.no-action.toml"

node "$GEN" --local short-scalar --out "$VECTORS/short_scalar.toml"
for v in wrong-contract wrong-selector extra-calldata wrong-chain no-chain type-1 other-signer; do
  node "$GEN" --local "$v" --out "$VECTORS/tx_${v//-/_}.toml"
done
node "$GEN" --tx eip1559 --tx-length-delta 1 --out "$VECTORS/tx_length_overstated.toml"
