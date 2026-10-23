#!/bin/bash
# Trust-anchor root probes: gates for Merkle membership (keccak256 and
# Poseidon2, depth 2/4/8) and for the merged app / server branch, then the
# merged branch's acceptance and refusal fixtures, and one real proof per
# accepted kind under the same vk.
#
#   scripts/coinbase-app-attest-poc/measure-trust-anchor.sh
#
# Needs: the pinned toolchain (toolchain.env), node, and scripts/node_modules
# (npm install in circuits/scripts). All keys are synthetic. Proof outputs go
# to a temporary directory and are removed.
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROBES="$CIRCUITS/_probes/coinbase-app-attest-poc"
BRANCH="$PROBES/trust-anchor-branch"

# shellcheck disable=SC1091
. "$CIRCUITS/toolchain.env"
[ "$(bb --version)" = "$BB_VERSION" ] || { echo "bb is $(bb --version), toolchain.env pins $BB_VERSION" >&2; exit 1; }
[ "$(nargo --version | sed -n 's/^nargo version = //p')" = "$NARGO_VERSION" ] || { echo "nargo is not $NARGO_VERSION" >&2; exit 1; }

gates() { bb gates -b "$1" 2>/dev/null | sed -n 's/.*"circuit_size": *\([0-9]*\).*/\1/p' | head -1; }
opcodes() { bb gates -b "$1" 2>/dev/null | sed -n 's/.*"acir_opcodes": *\([0-9]*\).*/\1/p' | head -1; }

echo "trust-anchor-lib tests"
(cd "$PROBES/trust-anchor-lib" && nargo test 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'tests? (passed|failed)|FAIL') \
  || { echo "trust-anchor-lib tests failed" >&2; exit 1; }

echo ""
echo "bb gates ($BB_VERSION, nargo $NARGO_VERSION)"
printf '  %-34s %12s %12s\n' "probe" "circuit_size" "acir_opcodes"
for p in anchor-keccak-d2 anchor-keccak-d4 anchor-keccak-d8 anchor-poseidon2-d2 anchor-poseidon2-d4 anchor-poseidon2-d8 \
         trust-anchor-branch p384-verify cert-der-sha p256-assertion; do
  (cd "$PROBES/$p" && nargo compile > /dev/null 2>&1) || { echo "probe $p does not compile" >&2; exit 1; }
  json="$PROBES/$p/target/probe_$(echo "$p" | tr - _).json"
  printf '  %-34s %12s %12s\n' "$p" "$(gates "$json")" "$(opcodes "$json")"
done

echo ""
echo "fixtures (synthetic keys)"
mkdir -p "$BRANCH/target"
node "$SCRIPT_DIR/generate-trust-anchor-fixtures.js" --probes "$PROBES"

echo ""
echo "acceptance: nargo execute per fixture"
FAILED=0
CASES=$(node -e 'for (const c of require(process.argv[1])) console.log(c.name + "\t" + (c.expect ?? ""))' "$BRANCH/target/cases.json")
while IFS=$'\t' read -r name expect; do
  set +e
  out=$(cd "$BRANCH" && nargo execute -p "Prover.$name.toml" "w_$name" 2>&1)
  rc=$?
  set -e
  if [ -z "$expect" ]; then
    if [ $rc -eq 0 ]; then printf '  %-42s accepted\n' "$name"; else printf '  %-42s WRONG: refused\n%s\n' "$name" "$out"; FAILED=1; fi
  else
    if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qF "$expect"; then
      printf '  %-42s refused: %s\n' "$name" "$expect"
    elif [ $rc -ne 0 ]; then
      printf '  %-42s WRONG REASON (wanted "%s"):\n%s\n' "$name" "$expect" "$(printf '%s' "$out" | grep -iE 'error|failed|assert' | head -3)"; FAILED=1
    else
      printf '  %-42s WRONG: accepted (wanted "%s")\n' "$name" "$expect"; FAILED=1
    fi
  fi
done <<< "$CASES"
[ $FAILED -eq 0 ] || { echo "acceptance FAILED" >&2; exit 1; }

echo ""
echo "one vk, a proof per accepted kind (bb -t evm)"
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
JSON="$BRANCH/target/probe_trust_anchor_branch.json"
bb write_vk -b "$JSON" -o "$OUT/vk" -t evm > "$OUT/vk.log" 2>&1 || { cat "$OUT/vk.log"; exit 1; }
for name in accept_app accept_server; do
  mkdir -p "$OUT/$name"
  /usr/bin/time -l bb prove -b "$JSON" -w "$BRANCH/target/w_$name.gz" -k "$OUT/vk/vk" -o "$OUT/$name" -t evm > "$OUT/$name.log" 2>&1 \
    || { tail -5 "$OUT/$name.log"; exit 1; }
  real=$(awk '/ real /{print $1}' "$OUT/$name.log" | tail -1)
  rss=$(awk '/maximum resident set size/{printf "%.2f", $1/1024/1024/1024}' "$OUT/$name.log")
  bb verify -p "$OUT/$name/proof" -i "$OUT/$name/public_inputs" -k "$OUT/vk/vk" -t evm > /dev/null 2>&1 \
    && v=verified || { echo "  $name: bb verify FAILED"; exit 1; }
  printf '  %-16s prove %6s s  peak RSS %s GiB  proof %s B  public inputs %s B  %s\n' "$name" "$real" "$rss" \
    "$(wc -c < "$OUT/$name/proof" | tr -d ' ')" "$(wc -c < "$OUT/$name/public_inputs" | tr -d ' ')" "$v"
done
cmp -s "$OUT/accept_app/public_inputs" "$OUT/accept_server/public_inputs" \
  && echo "  public inputs of the two kinds are byte-identical" \
  || { echo "  public inputs of the two kinds DIFFER" >&2; exit 1; }
