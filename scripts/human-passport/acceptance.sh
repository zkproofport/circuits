#!/bin/bash
# Acceptance run for human_passport_score. Called by scripts/build.sh through
# human-passport-score/scripts/post-build.sh, after the circuit is compiled.
#
# 1. The full circuit: two accepted fixtures (EIP-712 action mode and
#    signal-hash mode) and every case in test-vectors/cases.tsv. A case that
#    must be refused passes only when it is refused FOR THE STATED REASON;
#    refused for another reason is a failure, because it would hide the guard
#    being gone.
# 2. real-issuer-check: the same issuer library run on a real Base issuance
#    (real issuer signature, real data) -- accepted -- and two derivations of
#    it -- refused.
# 3. One real proof of the action fixture, verified.
#
# Fixtures are gitignored; when missing they are regenerated (network needed).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CIRCUIT_DIR="$CIRCUITS_ROOT/human-passport-score"
REAL_DIR="$CIRCUITS_ROOT/human-passport-real-issuer-check"
VECTORS="$CIRCUIT_DIR/test-vectors"
CIRCUIT_JSON="$CIRCUIT_DIR/target/human_passport_score.json"
LOGS="$VECTORS/logs"

cd "$CIRCUIT_DIR"
if [ ! -f Prover.toml ] || [ ! -f "$VECTORS/no_action.toml" ] || [ ! -f "$VECTORS/cases.tsv" ] \
   || [ ! -f "$REAL_DIR/test-vectors/cases.tsv" ]; then
  echo "  fixtures missing -- regenerating"
  mkdir -p "$VECTORS"
  if ! node "$SCRIPT_DIR/generate-fixtures.js" > "$VECTORS/regenerate.log" 2>&1; then
    echo "  FAILED   could not regenerate fixtures:"
    sed 's/^/           /' "$VECTORS/regenerate.log"
    exit 1
  fi
fi
mkdir -p "$LOGS"

PASSED=0
FAILED=0

run_case() {   # dir name prover expected("ACCEPT" or a reason)
  local dir="$1" name="$2" prover="$3" expected="$4"
  # nargo replaces anything after a dot in --prover-name with ".toml", so a
  # dotted name silently runs ANOTHER fixture. Refuse it, and refuse a name
  # whose file is missing, instead of letting nargo pick one.
  case "$(basename "$prover")" in
    *.*) echo "  FAILED   $name  (fixture name '$prover' has a dot)"; FAILED=$((FAILED + 1)); return ;;
  esac
  if [ ! -f "$dir/$prover.toml" ]; then
    echo "  FAILED   $name  (no fixture $dir/$prover.toml)"; FAILED=$((FAILED + 1)); return
  fi
  local log="$LOGS/${name}.log"
  if (cd "$dir" && nargo execute "witness_${name}" --prover-name "$prover") > "$log" 2>&1; then
    if [ "$expected" = ACCEPT ]; then
      echo "  ok       $name  (accepted)"; PASSED=$((PASSED + 1))
    else
      echo "  FAILED   $name  (ACCEPTED; must be refused: $expected)"; FAILED=$((FAILED + 1))
    fi
  else
    if [ "$expected" = ACCEPT ]; then
      echo "  FAILED   $name  (refused; must be accepted)"
      grep -m3 -E 'error|Failed|failed' "$log" | sed 's/^/           /'
      FAILED=$((FAILED + 1))
    elif grep -qF "$expected" "$log"; then
      echo "  ok       $name  -> refused: $expected"; PASSED=$((PASSED + 1))
    else
      echo "  FAILED   $name  (refused, but not for: $expected)"
      grep -m3 -E 'error|Failed|failed' "$log" | sed 's/^/           /'
      FAILED=$((FAILED + 1))
    fi
  fi
}

echo ""
echo "Acceptance run: human_passport_score"
echo ""
echo "Full circuit (real score data, test issuer + test wallet):"
run_case "$CIRCUIT_DIR" action    Prover            ACCEPT
run_case "$CIRCUIT_DIR" no_action test-vectors/no_action ACCEPT
while IFS=$'\t' read -r name expected; do
  [ -n "$name" ] || continue
  run_case "$CIRCUIT_DIR" "$name" "test-vectors/$name" "$expected"
done < "$VECTORS/cases.tsv"

echo ""
echo "Real Base issuance, real issuer signature (real-issuer-check):"
while IFS=$'\t' read -r name expected; do
  [ -n "$name" ] || continue
  run_case "$REAL_DIR" "$name" "test-vectors/$name" "$expected"
done < "$REAL_DIR/test-vectors/cases.tsv"

echo ""
echo "Proof (action mode):"
mkdir -p ./target/proof
if cp ./target/witness_action.gz ./target/proof/witness.gz 2>/dev/null \
   && bb prove -b "$CIRCUIT_JSON" -w ./target/proof/witness.gz -k ./target/vk/vk -o ./target/proof -t evm > "$LOGS/prove.log" 2>&1 \
   && bb verify -p ./target/proof/proof -i ./target/proof/public_inputs -k ./target/vk/vk -t evm >> "$LOGS/prove.log" 2>&1; then
  echo "  ok       proved and verified ($(wc -c < ./target/proof/proof | tr -d ' ') bytes proof, $(wc -c < ./target/proof/public_inputs | tr -d ' ') bytes public inputs)"
  PASSED=$((PASSED + 1))
else
  echo "  FAILED   prove/verify"
  tail -12 "$LOGS/prove.log" | sed 's/^/           /'
  FAILED=$((FAILED + 1))
fi

echo ""
echo "  $PASSED passed, $FAILED failed"
echo ""
[ "$FAILED" -eq 0 ]
