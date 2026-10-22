#!/bin/bash
# Fixtures for coinbase_eas_storage_poc, from Base mainnet.
#
#   scripts/coinbase-eas-storage-poc/make-fixtures.sh
#
# Needs circuits/.env.production (BASE_RPC_URL), and the key of a wallet
# holding a live Coinbase KYC attestation on Base. Unless ATTESTED_WALLET_KEY
# is already set, it is read from proofport-ai/.env.test
# (E2E_ATTESTATION_WALLET_KEY) -- the wallet the e2e suites already use.
#
# The storage proof is for a recent block: a fixture is only reproducible
# while the RPC still serves that block's state, so regenerate rather than
# keep old ones.
set -eu

REPO=$(git rev-parse --show-superproject-working-tree)
REPO=${REPO:-$(git rev-parse --show-toplevel)}
GEN="$REPO/circuits/scripts/coinbase-eas-storage-poc/generate-prover-toml.js"
CIRCUIT="$REPO/circuits/coinbase-eas-storage-poc"

if [ -z "${ATTESTED_WALLET_KEY:-}" ]; then
  ENV_FILE="$REPO/proofport-ai/.env.test"
  [ -f "$ENV_FILE" ] || { echo "ATTESTED_WALLET_KEY unset and $ENV_FILE missing" >&2; exit 1; }
  ATTESTED_WALLET_KEY=$(grep -E '^E2E_ATTESTATION_WALLET_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"')
  [ -n "$ATTESTED_WALLET_KEY" ] || { echo "E2E_ATTESTATION_WALLET_KEY missing from $ENV_FILE" >&2; exit 1; }
fi
export ATTESTED_WALLET_KEY

node "$GEN" --action --out "$CIRCUIT/Prover.toml"
node "$GEN" --out "$CIRCUIT/Prover.no-action.toml"
