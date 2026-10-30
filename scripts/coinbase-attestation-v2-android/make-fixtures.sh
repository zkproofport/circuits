#!/bin/bash
# Fixtures for coinbase_attestation v2's Android package, and the
# synthetic-anchors copy they run in.
#
#   scripts/coinbase-attestation-v2-android/make-fixtures.sh rkp|factory|country-rkp|country-factory
#     rkp      coinbase-attestation-v2-android (Remote Key Provisioning chain)
#     factory  coinbase-attestation-v2-android-factory (factory chain + Play
#              Integrity verdict)
#     country-rkp / country-factory
#              coinbase-country-attestation-v2-android(-factory): the same
#              signers for coinbase_country_attestation v2 (real attestCountry
#              transaction from coinbase-country-attestation/Prover.toml, the
#              227-byte statement, the country list)
#
# 1. Rebuilds circuits/coinbase-attestation-v2-android-synthetic-anchors/
#    (scripts/statement-signer/make-synthetic-anchors.sh): identical except
#    statement-signer's Google root (-> the synthetic root, anchors.js) and
#    the iPhone/server anchors, which this package does not use.
# 2. Writes the fixtures (generate-prover-toml.js).
#
# The Coinbase half is the iOS package's: coinbase-attestation/Prover.toml
# (real, from Base) and the wallet key from proofport-ai/.env.test
# (ATTESTATION_KEY) or ATTESTED_WALLET_KEY in the environment, never printed.
set -eu
# A NODE_OPTIONS that preloads a file which no longer exists (a terminal
# wrapper's temporary preload, 2026-10-28) makes every `node` here crash
# before running; these scripts need none.
unset NODE_OPTIONS

CIRCUITS=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
REPO=$(git -C "$CIRCUITS" rev-parse --show-superproject-working-tree)
SIGNER="${1:-}"
shift || true
# Anything after the signer goes to the generator (factory only):
#   --device-statement <dir> | --device-capture <dir>   (see generate-prover-toml.js)
CIRCUIT_ID=coinbase_attestation
COINBASE_TOML="$CIRCUITS/coinbase-attestation/Prover.toml"
case "$SIGNER" in
  rkp) PKG_DIR=coinbase-attestation-v2-android ;;
  factory) PKG_DIR=coinbase-attestation-v2-android-factory ;;
  country-rkp) PKG_DIR=coinbase-country-attestation-v2-android ;;
  country-factory) PKG_DIR=coinbase-country-attestation-v2-android-factory ;;
  *) echo "usage: $0 rkp|factory|country-rkp|country-factory (got '$SIGNER')" >&2; exit 1 ;;
esac
case "$SIGNER" in
  country-*)
    CIRCUIT_ID=coinbase_country_attestation
    COINBASE_TOML="$CIRCUITS/coinbase-country-attestation/Prover.toml"
    SIGNER=${SIGNER#country-}
    ;;
esac
KYC_TOML="$CIRCUITS/coinbase-attestation/Prover.toml"
REAL="$CIRCUITS/$PKG_DIR"
SYN="$CIRCUITS/$PKG_DIR-synthetic-anchors"
HERE="$CIRCUITS/scripts/coinbase-attestation-v2-android"
ENV_FILE="${REPO:+$REPO/proofport-ai/.env.test}"

if [ -z "${ATTESTED_WALLET_KEY:-}" ] && [ ! -f "$ENV_FILE" ]; then
  echo "no wallet key for the Coinbase fixture: set ATTESTED_WALLET_KEY or provide proofport-ai/.env.test" >&2; exit 1
fi
if [ ! -f "$COINBASE_TOML" ] || [ ! -f "$KYC_TOML" ]; then
  [ -n "$REPO" ] || { echo "$COINBASE_TOML is missing and there is no parent repository to build it from" >&2; exit 1; }
  echo "coinbase-attestation/Prover.toml missing -- building it with proofport-ai/scripts/gen-prover-toml.ts"
  (cd "$REPO/proofport-ai" && npx tsx scripts/gen-prover-toml.ts)
  [ -f "$COINBASE_TOML" ] || { echo "gen-prover-toml.ts did not write $COINBASE_TOML" >&2; exit 1; }
fi

"$CIRCUITS/scripts/statement-signer/make-synthetic-anchors.sh" "$PKG_DIR"

if [ -z "${ATTESTED_WALLET_KEY:-}" ]; then
  ATTESTED_WALLET_KEY=$(grep -E '^ATTESTATION_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"'"'")
  [ -n "$ATTESTED_WALLET_KEY" ] || { echo "ATTESTATION_KEY missing from $ENV_FILE" >&2; exit 1; }
fi
export ATTESTED_WALLET_KEY

rm -rf "$REAL/test-vectors"
env -u NODE_OPTIONS node "$HERE/generate-prover-toml.js" \
  --circuit "$CIRCUIT_ID" \
  --coinbase "$COINBASE_TOML" \
  --kyc-coinbase "$KYC_TOML" \
  --signer "$SIGNER" "$@" \
  --synthetic-dir "$SYN" \
  --real-dir "$REAL"
