#!/bin/bash
# Fixtures for coinbase_snapshot_poc, from the newest snapshot.
#
#   scripts/coinbase-snapshot/make-fixtures.sh
#
# Builds a snapshot first when none exists (needs circuits/.env.production,
# BASE_RPC_URL). The wallet key is ATTESTED_WALLET_KEY, or else
# E2E_ATTESTATION_WALLET_KEY from proofport-ai/.env.test -- the wallet the e2e
# suites already use, which holds a live Coinbase KYC attestation on Base.
set -eu

REPO=$(git rev-parse --show-superproject-working-tree)
REPO=${REPO:-$(git rev-parse --show-toplevel)}
SCRIPTS="$REPO/circuits/scripts/coinbase-snapshot"
CIRCUIT="$REPO/circuits/coinbase-snapshot-poc"

if [ -z "${ATTESTED_WALLET_KEY:-}" ]; then
  ENV_FILE="$REPO/proofport-ai/.env.test"
  [ -f "$ENV_FILE" ] || { echo "ATTESTED_WALLET_KEY unset and $ENV_FILE missing" >&2; exit 1; }
  ATTESTED_WALLET_KEY=$(grep -E '^E2E_ATTESTATION_WALLET_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"')
  [ -n "$ATTESTED_WALLET_KEY" ] || { echo "E2E_ATTESTATION_WALLET_KEY missing from $ENV_FILE" >&2; exit 1; }
fi
export ATTESTED_WALLET_KEY

ls "$CIRCUIT"/snapshots/[0-9]*.json > /dev/null 2>&1 || node "$SCRIPTS/build-snapshot.js"

mkdir -p "$CIRCUIT/test-vectors"
node "$SCRIPTS/generate-prover-toml.js" --action --out "$CIRCUIT/Prover.toml"
node "$SCRIPTS/generate-prover-toml.js" --out "$CIRCUIT/Prover.no-action.toml"
node "$SCRIPTS/generate-prover-toml.js" --not-member --out "$CIRCUIT/test-vectors/not_member.toml"
