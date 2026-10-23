#!/bin/bash
# Fixtures for coinbase_app_attest_poc.
#
#   scripts/coinbase-app-attest-poc/make-fixtures.sh
#
# The Coinbase half reuses the existing flow: coinbase-attestation/Prover.toml,
# built from Base by proofport-ai/scripts/gen-prover-toml.ts (run here when the
# file is missing; it needs proofport-ai's node_modules and .env.test). The
# App Attest half is synthetic -- see generate-prover-toml.js for how it
# differs from a device's.
#
# The wallet key is ATTESTATION_KEY from proofport-ai/.env.test, the key
# gen-prover-toml.ts signs with. It goes to the generator through the
# environment and is never printed.
set -eu

REPO=$(git rev-parse --show-superproject-working-tree)
REPO=${REPO:-$(git rev-parse --show-toplevel)}
CIRCUITS="$REPO/circuits"
COINBASE_TOML="$CIRCUITS/coinbase-attestation/Prover.toml"
ENV_FILE="$REPO/proofport-ai/.env.test"

[ -f "$ENV_FILE" ] || { echo "$ENV_FILE is missing: no wallet key for the Coinbase fixture" >&2; exit 1; }

if [ ! -f "$COINBASE_TOML" ]; then
  echo "coinbase-attestation/Prover.toml missing -- building it with proofport-ai/scripts/gen-prover-toml.ts"
  (cd "$REPO/proofport-ai" && npx tsx scripts/gen-prover-toml.ts)
  [ -f "$COINBASE_TOML" ] || { echo "gen-prover-toml.ts did not write $COINBASE_TOML" >&2; exit 1; }
fi

ATTESTED_WALLET_KEY=$(grep -E '^ATTESTATION_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"'"'")
[ -n "$ATTESTED_WALLET_KEY" ] || { echo "ATTESTATION_KEY missing from $ENV_FILE" >&2; exit 1; }
export ATTESTED_WALLET_KEY

node "$CIRCUITS/scripts/coinbase-app-attest-poc/generate-prover-toml.js" \
  --coinbase "$COINBASE_TOML" \
  --out-dir "$CIRCUITS/coinbase-app-attest-poc"
