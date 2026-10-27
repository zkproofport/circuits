#!/bin/bash
# What coinbase_attestation_v2 costs with Apple's App Attest intermediate
# (CA 1) PINNED instead of verified against Apple's root, and where its gates
# go. Gates only: `bb gates` and the dyadic size are deterministic, so this is
# safe on a loaded machine (no timing).
#
#   scripts/coinbase-attestation-v2/measure-pinned-intermediate.sh [jobs]   (default 6 parallel compiles)
#
# The probe is _probes/coinbase-attestation-v2/pinned-intermediate/. Its
# main.nr has WITH_* / APP_BRANCH globals; this script copies the probe once
# per switch into _probes/coinbase-attestation-v2/pinned-intermediate-variants/
# (gitignored), flips that one global to false, compiles, and prints for each:
#   circuit_size   `bb gates` circuit_size
#   saved          full probe minus this variant: what removing that part saves
#   dyadic         2^k, k = the first field of `bb write_vk -t evm`'s vk
#                  (log2 of the dyadic circuit size; v2's committed vk reads 21,
#                  v1's 19, matching their .srs files)
# Each variant is the WHOLE circuit minus one part, so lookup tables are shared
# as they are in the real circuit and "saved" is the real marginal cost.
set -eu

JOBS=${1:-6}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROBE="$CIRCUITS/_probes/coinbase-attestation-v2/pinned-intermediate"
VARIANTS="$CIRCUITS/_probes/coinbase-attestation-v2/pinned-intermediate-variants"

# shellcheck disable=SC1091
. "$CIRCUITS/toolchain.env"
[ "$(bb --version)" = "$BB_VERSION" ] || { echo "bb is $(bb --version), toolchain.env pins $BB_VERSION" >&2; exit 1; }
[ "$(nargo --version | sed -n 's/^nargo version = //p')" = "$NARGO_VERSION" ] || { echo "nargo is not $NARGO_VERSION" >&2; exit 1; }

SWITCHES="full PINNED APP_BRANCH WITH_APP WITH_CRED_SHA256 WITH_CRED_P384 WITH_CRED_DER WITH_ATT_AUTH_DATA WITH_ASSERTION_DIGEST WITH_CLIENT_DATA_CHECK WITH_P256 WITH_REQUEST_SIG WITH_COINBASE_TX WITH_NULLIFIER"

rm -rf "$VARIANTS"
mkdir -p "$VARIANTS"
for sw in $SWITCHES; do
  d="$VARIANTS/$sw"
  mkdir -p "$d"
  cp -R "$PROBE/src" "$d/src"
  # One directory deeper than the probe, so path dependencies get one more ../
  sed 's#path = "\.\./#path = "../../#' "$PROBE/Nargo.toml" > "$d/Nargo.toml"
  if [ "$sw" != full ]; then
    n=$(grep -c "^global $sw: bool = true;\$" "$d/src/main.nr" || true)
    [ "$n" = 1 ] || { echo "switch $sw not found exactly once in the probe's main.nr" >&2; exit 1; }
    sed -i.bak "s/^global $sw: bool = true;\$/global $sw: bool = false;/" "$d/src/main.nr"
    rm "$d/src/main.nr.bak"
    grep -q "^global $sw: bool = false;\$" "$d/src/main.nr" || { echo "switch $sw did not flip" >&2; exit 1; }
  fi
done

measure_one() {
  local d="$1"
  local json="$d/target/probe_pinned_intermediate.json"
  (cd "$d" && nargo compile > "$d/compile.out" 2>&1) || { echo "$(basename "$d"): nargo compile failed, see $d/compile.out" >&2; return 1; }
  bb gates -b "$json" > "$d/gates.out" 2>/dev/null
  bb write_vk -b "$json" -o "$d/vk" -t evm > "$d/vk.out" 2>&1 || { echo "$(basename "$d"): bb write_vk failed, see $d/vk.out" >&2; return 1; }
}
export -f measure_one

for sw in $SWITCHES; do echo "$VARIANTS/$sw"; done | xargs -P "$JOBS" -I{} bash -c 'measure_one "$@"' _ {}

field() { sed -n "s/.*\"$2\": *\([0-9]*\).*/\1/p" "$VARIANTS/$1/gates.out" | head -1; }
log2dyadic() { od -An -tu1 -j31 -N1 "$VARIANTS/$1/vk/vk" | tr -d ' '; }

FULL=$(field full circuit_size)
echo ""
echo "pinned-intermediate probe, bb gates ($BB_VERSION, nargo $NARGO_VERSION); 2^20 = 1048576"
printf '  %-26s %12s %12s %10s %8s\n' "variant (switch off)" "circuit_size" "acir_opcodes" "saved" "dyadic"
for sw in $SWITCHES; do
  g=$(field "$sw" circuit_size)
  o=$(field "$sw" acir_opcodes)
  printf '  %-26s %12s %12s %10s %8s\n' "$sw" "$g" "$o" "$((FULL - g))" "2^$(log2dyadic "$sw")"
done
V2_JSON="$CIRCUITS/coinbase-attestation-v2/target/coinbase_attestation_v2.json"
if [ -f "$V2_JSON" ]; then
  printf '  %-26s %12s   (the PINNED row must match this)\n' "v2 itself" "$(bb gates -b "$V2_JSON" 2>/dev/null | sed -n 's/.*"circuit_size": *\([0-9]*\).*/\1/p' | head -1)"
fi
