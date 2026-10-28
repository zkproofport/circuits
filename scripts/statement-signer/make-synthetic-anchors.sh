#!/bin/bash
# A circuit that verifies statements through ../statement-signer, rebuilt
# against SYNTHETIC trust anchors, so fixtures can sign for both kinds.
#
#   scripts/statement-signer/make-synthetic-anchors.sh <circuit-dir>
#   e.g. coinbase-attestation-v2, oidc-domain-attestation
#
# No fixture can hold an Apple-signed credential certificate for our App ID
# together with that device's key, nor the Cloud KMS key's private half. So
# every accepting case, and every refusal that needs something re-signed,
# runs in a copy whose anchors the generators hold:
#
#   statement-signer-synthetic-anchors/   the library, with src/apple_ca.nr ->
#                                         the SYNTHETIC CA and src/server_key.nr
#                                         -> the INSECURE test key (anchors.js);
#                                         nothing else may differ
#   <circuit-dir>-synthetic-anchors/      the circuit, identical except its
#                                         Nargo.toml names the library copy
#
# Both are siblings of the originals so ../deps and ../app-attest-libs
# resolve, and both are gitignored. The copy is compiled and its vk written
# (bb write_vk -t evm), which the acceptance runs' proof steps need.
#
# Runs nargo and bb from toolchain.env's set, like scripts/build.sh.
set -eu

[ $# -eq 1 ] || { echo "usage: $0 <circuit-dir>" >&2; exit 1; }
CIRCUITS=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
NAME="$1"
REAL="$CIRCUITS/$NAME"
SYN="$CIRCUITS/$NAME-synthetic-anchors"
LIB="$CIRCUITS/statement-signer"
SYN_LIB="$CIRCUITS/statement-signer-synthetic-anchors"
ANCHORS="$CIRCUITS/scripts/statement-signer/anchors.js"

[ -f "$REAL/Nargo.toml" ] || { echo "$REAL is not a circuit" >&2; exit 1; }
grep -q '^statement_signer = { path = "../statement-signer" }$' "$REAL/Nargo.toml" \
  || { echo "$NAME/Nargo.toml does not depend on ../statement-signer" >&2; exit 1; }

# ---- the library copy ---------------------------------------------------------
rm -rf "$SYN_LIB"
mkdir -p "$SYN_LIB"
cp -R "$LIB/Nargo.toml" "$LIB/src" "$SYN_LIB/"
env -u NODE_OPTIONS node -e '
  const a = require(process.argv[1]);
  const [lib] = process.argv.slice(2);
  const c = a.syntheticCa();
  a.writeAppleCa(Buffer.concat([c.x, c.y]), lib + "/src/apple_ca.nr");
  const s = a.testServerKey();
  a.writeServerKey(Buffer.concat([s.x, s.y]), lib + "/src/server_key.nr");
' "$ANCHORS" "$SYN_LIB"
DIFFS=$(diff -rq "$LIB/src" "$SYN_LIB/src" | sed 's#.*/src/\([^ ]*\) and.*#\1#' | sort | tr '\n' ' ' || true)
case "$DIFFS" in
  "apple_ca.nr "|"apple_ca.nr server_key.nr ") ;;
  *) echo "synthetic-anchors library differs from statement-signer in: $DIFFS" >&2; exit 1 ;;
esac
diff -q "$LIB/Nargo.toml" "$SYN_LIB/Nargo.toml" > /dev/null

# ---- the circuit copy ---------------------------------------------------------
rm -rf "$SYN"
mkdir -p "$SYN/target/vk"
cp -R "$REAL/Nargo.toml" "$REAL/src" "$SYN/"
sed -i.bak 's#^statement_signer = { path = "../statement-signer" }$#statement_signer = { path = "../statement-signer-synthetic-anchors" }#' "$SYN/Nargo.toml"
rm -f "$SYN/Nargo.toml.bak"
diff -rq "$REAL/src" "$SYN/src" > /dev/null || { echo "synthetic-anchors copy of $NAME has different sources" >&2; exit 1; }
NARGO_DIFF=$(diff "$REAL/Nargo.toml" "$SYN/Nargo.toml" | grep -c '^[<>]' || true)
[ "$NARGO_DIFF" = 2 ] && grep -q 'statement-signer-synthetic-anchors' "$SYN/Nargo.toml" \
  || { echo "synthetic-anchors Nargo.toml of $NAME differs by more than the library path" >&2; exit 1; }
echo "synthetic-anchors copy: $NAME-synthetic-anchors (library: ${DIFFS}replaced)"

(cd "$SYN" && nargo compile > "$SYN/compile.log" 2>&1) || { tail -20 "$SYN/compile.log" >&2; exit 1; }
PKG=$(grep -m1 '^name' "$SYN/Nargo.toml" | sed 's/.*= *"\(.*\)"/\1/')
bb write_vk -b "$SYN/target/$PKG.json" -o "$SYN/target/vk" -t evm > "$SYN/write_vk.log" 2>&1 \
  || { tail -20 "$SYN/write_vk.log" >&2; exit 1; }
[ -s "$SYN/target/vk/vk" ] || { echo "bb write_vk wrote no vk for $NAME-synthetic-anchors" >&2; exit 1; }
