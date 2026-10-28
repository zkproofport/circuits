#!/bin/bash
# Fixtures for coinbase_attestation_v2, and the synthetic-anchors copy they run in.
#
#   scripts/coinbase-attestation-v2/make-fixtures.sh
#
# 1. Rebuilds circuits/coinbase-attestation-v2-synthetic-anchors/ (and the
#    statement-signer library copy it uses) from the CURRENT source with
#    scripts/statement-signer/make-synthetic-anchors.sh: identical except the
#    library's apple_ca.nr (Apple's CA 1 -> the SYNTHETIC CA) and server_key.nr
#    (-> the INSECURE test key), both from anchors.js. Compiled, vk written.
# 2. Writes the fixtures (generate-prover-toml.js): every acceptance and
#    refusal case into the copy, and the real_* cases into the real circuit's
#    test-vectors/.
#
# The Coinbase half reuses the existing flow: coinbase-attestation/Prover.toml,
# built from Base by proofport-ai/scripts/gen-prover-toml.ts (run here when the
# file is missing; it needs proofport-ai's node_modules and .env.test).
# The wallet key is ATTESTATION_KEY from proofport-ai/.env.test, or
# ATTESTED_WALLET_KEY already in the environment (a checkout of circuits
# outside the parent repository, e.g. a git worktree, has no proofport-ai
# next to it). It goes to the generator through the environment and is never
# printed.
set -eu
# A NODE_OPTIONS that preloads a file which no longer exists (a terminal
# wrapper's temporary preload, 2026-10-28) makes every `node` here crash
# before running; these scripts need none.
unset NODE_OPTIONS

# The circuits repository's own root, wherever it is checked out; the parent
# (for proofport-ai) only when circuits sits in it as a submodule.
CIRCUITS=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
REPO=$(git -C "$CIRCUITS" rev-parse --show-superproject-working-tree)
REAL="$CIRCUITS/coinbase-attestation-v2"
SYN="$CIRCUITS/coinbase-attestation-v2-synthetic-anchors"
HERE="$CIRCUITS/scripts/coinbase-attestation-v2"
COINBASE_TOML="$CIRCUITS/coinbase-attestation/Prover.toml"
ENV_FILE="${REPO:+$REPO/proofport-ai/.env.test}"

if [ -z "${ATTESTED_WALLET_KEY:-}" ] && [ ! -f "$ENV_FILE" ]; then
  echo "no wallet key for the Coinbase fixture: set ATTESTED_WALLET_KEY or provide proofport-ai/.env.test" >&2; exit 1
fi

if [ ! -f "$COINBASE_TOML" ]; then
  [ -n "$REPO" ] || { echo "$COINBASE_TOML is missing and there is no parent repository to build it from" >&2; exit 1; }
  echo "coinbase-attestation/Prover.toml missing -- building it with proofport-ai/scripts/gen-prover-toml.ts"
  (cd "$REPO/proofport-ai" && npx tsx scripts/gen-prover-toml.ts)
  [ -f "$COINBASE_TOML" ] || { echo "gen-prover-toml.ts did not write $COINBASE_TOML" >&2; exit 1; }
fi

# ---- 1. the synthetic-anchors copy -------------------------------------------
"$CIRCUITS/scripts/statement-signer/make-synthetic-anchors.sh" coinbase-attestation-v2

# ---- 2. fixtures -------------------------------------------------------------
if [ -z "${ATTESTED_WALLET_KEY:-}" ]; then
  ATTESTED_WALLET_KEY=$(grep -E '^ATTESTATION_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"'"'")
  [ -n "$ATTESTED_WALLET_KEY" ] || { echo "ATTESTATION_KEY missing from $ENV_FILE" >&2; exit 1; }
fi
export ATTESTED_WALLET_KEY

rm -rf "$REAL/test-vectors"
env -u NODE_OPTIONS node "$HERE/generate-prover-toml.js" \
  --coinbase "$COINBASE_TOML" \
  --synthetic-dir "$SYN" \
  --real-dir "$REAL"
