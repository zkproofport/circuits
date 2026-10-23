#!/bin/bash
# Prove that a refusal in the acceptance run is caused by the assert it names.
#
#   scripts/coinbase-app-attest-poc/mutation-check.sh
#
# For each (assert message, refusal fixture) pair below: copy the circuit to a
# sibling directory, delete the ONE source line carrying that message, and
# run the fixture. The mutant must ACCEPT it -- otherwise something else was
# doing the refusing and the acceptance case proves nothing about this assert.
# The original source is never edited; the copy is removed on exit.
#
# Needs the fixtures (scripts/coinbase-app-attest-poc/make-fixtures.sh).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(cd "$SCRIPT_DIR/../.." && pwd)"
POC="$CIRCUITS/coinbase-app-attest-poc"
# Siblings, so the circuit's ../deps and ../coinbase-libs paths still resolve.
# The library is copied too (as its own sibling) because half the asserts
# live there.
MUTANT="$CIRCUITS/coinbase-app-attest-poc-mutant"
MUTANT_LIB="$CIRCUITS/app-attest-libs-mutant"

CASES=(
  "clientData wallet is not the proven wallet|client_wallet_mismatch"
  "clientData says the attestation is revoked|client_revoked"
  "clientData does not bind this request|client_other_request"
  "clientData does not bind this scope|client_other_scope"
  "clientData timestamp is not the public timestamp|timestamp_changed"
  "clientData names another EAS schema|client_other_schema"
  "Assertion is not for this app|assertion_wrong_rpid"
  "Assertion counter is zero|assertion_counter_zero"
)

[ -f "$POC/test-vectors/client_revoked.toml" ] || { echo "fixtures missing: run scripts/coinbase-app-attest-poc/make-fixtures.sh" >&2; exit 1; }
for d in "$MUTANT" "$MUTANT_LIB"; do
  [ ! -e "$d" ] || { echo "$d exists; remove it (a previous run was interrupted)" >&2; exit 1; }
done
trap 'rm -rf "$MUTANT" "$MUTANT_LIB"' EXIT

PASSED=0
FAILED=0
for c in "${CASES[@]}"; do
  msg="${c%%|*}"
  vector="${c##*|}"
  rm -rf "$MUTANT" "$MUTANT_LIB"
  mkdir -p "$MUTANT" "$MUTANT_LIB"
  cp -R "$POC/Nargo.toml" "$POC/src" "$POC/test-vectors" "$MUTANT/"
  cp -R "$CIRCUITS/app-attest-libs/Nargo.toml" "$CIRCUITS/app-attest-libs/src" "$MUTANT_LIB/"
  sed -i.bak 's#"../app-attest-libs"#"../app-attest-libs-mutant"#' "$MUTANT/Nargo.toml"
  grep -q 'app-attest-libs-mutant' "$MUTANT/Nargo.toml" || { echo "could not point the mutant at its library copy" >&2; exit 1; }

  # Exactly one line may carry the message, and exactly one line must go.
  hits=$(grep -rlF "\"$msg\"" "$MUTANT/src" "$MUTANT_LIB/src")
  count=$(grep -rcF "\"$msg\"" "$MUTANT/src" "$MUTANT_LIB/src" | awk -F: '{s+=$2} END {print s}')
  if [ "$count" != 1 ]; then
    echo "  FAILED   $msg: found on $count lines, need exactly 1"
    FAILED=$((FAILED + 1))
    continue
  fi
  before=$(wc -l < "$hits")
  grep -vF "\"$msg\"" "$hits" > "$hits.new" && mv "$hits.new" "$hits"
  after=$(wc -l < "$hits")
  if [ $((before - after)) != 1 ]; then
    echo "  FAILED   $msg: the deletion removed $((before - after)) lines"
    FAILED=$((FAILED + 1))
    continue
  fi

  if (cd "$MUTANT" && nargo execute w --prover-name "test-vectors/$vector" > "$MUTANT/run.log" 2>&1); then
    echo "  ok       without \"$msg\", $vector is ACCEPTED -- that assert is what refuses it"
    PASSED=$((PASSED + 1))
  else
    echo "  FAILED   without \"$msg\", $vector is still refused:"
    grep -m1 "Assertion failed\|error" "$MUTANT/run.log" | sed 's/^/           /'
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "  $PASSED caught, $FAILED not"
exit $([ "$FAILED" -eq 0 ] && echo 0 || echo 1)
