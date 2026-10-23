#!/bin/bash
# Fixtures for coinbase_attestation_v2, and the synthetic-anchors copy they run in.
#
#   scripts/coinbase-attestation-v2/make-fixtures.sh
#
# 1. Rebuilds circuits/coinbase-attestation-v2-synthetic-anchors/ from the
#    circuit's CURRENT source: identical except src/apple_root.nr (Apple's root
#    -> SYNTHETIC_ROOT) and src/server_key.nr (-> the INSECURE test key), both
#    from anchors.js. It refuses to continue if any other file differs. The
#    copy is a sibling so the ../deps and ../app-attest-libs paths resolve; it
#    is gitignored. Then compiles it and writes its vk (bb write_vk -t evm),
#    which the acceptance run's proof step needs.
# 2. Writes the fixtures (generate-prover-toml.js): every acceptance and
#    refusal case into the copy, and the real_* cases into the real circuit's
#    test-vectors/.
#
# The Coinbase half reuses the existing flow: coinbase-attestation/Prover.toml,
# built from Base by proofport-ai/scripts/gen-prover-toml.ts (run here when the
# file is missing; it needs proofport-ai's node_modules and .env.test).
# The wallet key is ATTESTATION_KEY from proofport-ai/.env.test. It goes to the
# generator through the environment and is never printed.
set -eu

REPO=$(git rev-parse --show-superproject-working-tree)
REPO=${REPO:-$(git rev-parse --show-toplevel)}
CIRCUITS="$REPO/circuits"
REAL="$CIRCUITS/coinbase-attestation-v2"
SYN="$CIRCUITS/coinbase-attestation-v2-synthetic-anchors"
HERE="$CIRCUITS/scripts/coinbase-attestation-v2"
COINBASE_TOML="$CIRCUITS/coinbase-attestation/Prover.toml"
ENV_FILE="$REPO/proofport-ai/.env.test"

[ -f "$ENV_FILE" ] || { echo "$ENV_FILE is missing: no wallet key for the Coinbase fixture" >&2; exit 1; }

if [ ! -f "$COINBASE_TOML" ]; then
  echo "coinbase-attestation/Prover.toml missing -- building it with proofport-ai/scripts/gen-prover-toml.ts"
  (cd "$REPO/proofport-ai" && npx tsx scripts/gen-prover-toml.ts)
  [ -f "$COINBASE_TOML" ] || { echo "gen-prover-toml.ts did not write $COINBASE_TOML" >&2; exit 1; }
fi

# ---- 1. the synthetic-anchors copy -------------------------------------------
rm -rf "$SYN"
mkdir -p "$SYN/target/vk"
cp -R "$REAL/Nargo.toml" "$REAL/src" "$SYN/"
node -e '
  const a = require(process.argv[1]);
  const [syn] = process.argv.slice(2);
  const r = a.syntheticRoot();
  a.writeAppleRoot(Buffer.concat([r.x, r.y]), syn + "/src/apple_root.nr");
  const s = a.testServerKey();
  a.writeServerKey(Buffer.concat([s.x, s.y]), syn + "/src/server_key.nr");
' "$HERE/anchors.js" "$SYN"
# Only the two anchor files may differ; anything else would mean the cases
# test a circuit other than the one shipped.
DIFFS=$(diff -rq "$REAL/src" "$SYN/src" | sed 's#.*/src/\([^ ]*\) and.*#\1#' | sort | tr '\n' ' ')
case "$DIFFS" in
  "apple_root.nr "|"apple_root.nr server_key.nr ") ;;
  *) echo "synthetic-anchors copy differs from the circuit in: $DIFFS" >&2; exit 1 ;;
esac
diff -q "$REAL/Nargo.toml" "$SYN/Nargo.toml" > /dev/null
echo "synthetic-anchors copy: differs only in ${DIFFS}"

(cd "$SYN" && nargo compile > "$SYN/compile.log" 2>&1) || { tail -20 "$SYN/compile.log" >&2; exit 1; }
bb write_vk -b "$SYN/target/coinbase_attestation_v2.json" -o "$SYN/target/vk" -t evm > "$SYN/write_vk.log" 2>&1 \
  || { tail -20 "$SYN/write_vk.log" >&2; exit 1; }
[ -s "$SYN/target/vk/vk" ] || { echo "bb write_vk wrote no vk for the synthetic copy" >&2; exit 1; }

# ---- 2. fixtures -------------------------------------------------------------
ATTESTED_WALLET_KEY=$(grep -E '^ATTESTATION_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2- | tr -d '"'"'")
[ -n "$ATTESTED_WALLET_KEY" ] || { echo "ATTESTATION_KEY missing from $ENV_FILE" >&2; exit 1; }
export ATTESTED_WALLET_KEY

rm -rf "$REAL/test-vectors"
node "$HERE/generate-prover-toml.js" \
  --coinbase "$COINBASE_TOML" \
  --synthetic-dir "$SYN" \
  --real-dir "$REAL"
