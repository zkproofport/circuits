#!/bin/bash
# Both giwa_attestation fixtures, from the recorded GIWA Sepolia attestation.
#
# Prover.toml is gitignored across this repository ("private inputs"), so a
# fresh checkout has none. Rather than leaving each session to rediscover which
# transaction to use and which fields the circuit now wants, that knowledge
# lives in generate-prover-toml.js and this is the one command that applies it:
#
#   scripts/giwa-poc/make-fixtures.sh
#
# Needs circuits/.env.development (the attested wallet's key) and the GIWA
# Sepolia RPC. The acceptance run calls this itself when the fixtures are
# missing.
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GEN="$SCRIPT_DIR/generate-prover-toml.js"

node "$GEN" --action --out "$CIRCUITS_ROOT/giwa-attestation/Prover.toml"
echo ""
node "$GEN" --out "$CIRCUITS_ROOT/giwa-attestation/Prover.no-action.toml"
