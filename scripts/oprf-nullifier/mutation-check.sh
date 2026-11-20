#!/bin/bash
# Each guard in oprf-nullifier-libs is what its tests depend on: remove or
# weaken it in a copy, and `nargo test` on the copy must FAIL. A mutation the
# tests do not notice is reported as SURVIVED and fails the run.
#
#   scripts/oprf-nullifier/mutation-check.sh [case-regex]
#
# The copy is oprf-nullifier-libs-mutant/ (gitignored, beside the original so
# ../deps resolves) and is removed on exit; the original is never edited.
# Every replacement must match its text exactly once, or the case fails
# rather than testing an unchanged copy.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck disable=SC1091
. "$CIRCUITS/scripts/lib/toolchain.sh"
LIB="$CIRCUITS/oprf-nullifier-libs"
MUT="$CIRCUITS/oprf-nullifier-libs-mutant"
ONLY="${1:-}"
[ ! -e "$MUT" ] || { echo "$MUT exists; remove it (a previous run was interrupted)" >&2; exit 1; }
trap 'rm -rf "$MUT"' EXIT
LOGS=$(mktemp -d "${TMPDIR:-/tmp}/oprf-mutation.XXXXXX")

# name ~ exact text in src/lib.nr ~ replacement
CASES=$(cat <<'CASES_END'
key hash assert removed~    assert(key_hash(public_key) == oprf_key_hash, "OPRF key hash mismatch");~    let _ = oprf_key_hash;
nullifier assert removed~    assert(derived == nullifier, "Nullifier mismatch");~    let _ = (derived, nullifier);
public key not checked on curve or subgroup~BabyJubJubPointInSubgroup::new(answer.public_key_x, answer.public_key_y)~BabyJubJubPointInSubgroup::new_unchecked(answer.public_key_x, answer.public_key_y)
public key checked on curve only~BabyJubJubPointInSubgroup::new(answer.public_key_x, answer.public_key_y)~BabyJubJubPointInSubgroup::from_point_unchecked(BabyJubJubPoint::new(answer.public_key_x, answer.public_key_y))
response not checked on curve~BabyJubJubPoint::new(answer.response_x, answer.response_y)~BabyJubJubPoint::new_unchecked(answer.response_x, answer.response_y)
domain and scope swapped in the query~oprf_query(address_field(address), domain, scope)~oprf_query(address_field(address), scope, domain)
address read little-endian~        acc = acc * 256 + address[i] as Field;~        acc = acc * 256 + address[19 - i] as Field;
address left out of the query~oprf_query(address_field(address), domain, scope)~oprf_query(0, domain, scope)
query DS replaced by the output DS~    permutation::t4([DS_QUERY, address, domain, scope])[1]~    permutation::t4([DS_OUT, address, domain, scope])[1]
query read from state[0]~    permutation::t4([DS_QUERY, address, domain, scope])[1]~    permutation::t4([DS_QUERY, address, domain, scope])[0]
key hash over (y, x)~    permutation::t3([DS_KEY, public_key.x(), public_key.y()])[1]~    permutation::t3([DS_KEY, public_key.y(), public_key.x()])[1]
output DS replaced by the query DS~        DS_DLOG,\n        DS_OUT,~        DS_DLOG,\n        DS_QUERY,
CASES_END
)

PASSED=0
FAILED=0
while IFS= read -r c; do
  [ -n "$c" ] || continue
  IFS='~' read -r name from to <<< "$c"
  if [ -n "$ONLY" ] && ! echo "$name" | grep -Eq "$ONLY"; then continue; fi
  rm -rf "$MUT"; mkdir -p "$MUT"
  cp -R "$LIB/Nargo.toml" "$LIB/src" "$MUT/"
  if ! FROM="$from" TO="$to" python3 -I - "$MUT/src/lib.nr" <<'PY'
import os, sys
p = sys.argv[1]
src = open(p).read()
f = os.environ["FROM"].replace("\\n", "\n")
t = os.environ["TO"].replace("\\n", "\n")
n = src.count(f)
if n != 1:
    sys.exit(f"text occurs {n} times, need exactly 1: {f!r}")
open(p, "w").write(src.replace(f, t))
PY
  then
    echo "  FAILED   $name: mutation not applied"; FAILED=$((FAILED + 1)); continue
  fi
  log="$LOGS/$(echo "$name" | tr ' ' '_').log"
  ( cd "$MUT" && "$NARGO_BIN" test > "$log" 2>&1 )
  if grep -q "tests\? failed" "$log"; then
    caught=$(grep -o "Testing tests::[a-z_0-9]* \.\.\. .*FAIL" "$log" | sed 's/Testing tests::\([a-z_0-9]*\).*/\1/' | tr '\n' ' ')
    echo "  ok       $name -> caught by: $caught"
    PASSED=$((PASSED + 1))
  elif grep -q "tests passed" "$log"; then
    echo "  FAILED   $name: SURVIVED (every test still passes)"; FAILED=$((FAILED + 1))
  else
    echo "  FAILED   $name: the mutant did not compile or ran no tests (see $log)"; FAILED=$((FAILED + 1))
  fi
done <<< "$CASES"
echo ""
echo "  $PASSED caught, $FAILED failed   (logs in $LOGS)"
[ "$FAILED" -eq 0 ]
