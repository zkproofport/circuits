#!/bin/bash
# The cases that must run against the REAL circuit, Apple's CA 1 pinned.
#
#   scripts/coinbase-attestation-v2/real-anchors-check.sh
#
# Every other case runs in the synthetic-anchors copy (make-fixtures.sh), so
# this is what shows the shipped constants are the ones intended:
#   real_apple_chain     A real credential certificate (zkPassport's app) signed
#                        by "Apple App Attestation CA 1". The P-384 check must
#                        PASS in this circuit, and the proof must stop at the
#                        App ID -- the only check that real chain cannot meet.
#   real_synthetic_ca    A chain under the synthetic CA: refused, not Apple's.
#   real_server_action   A server-kind statement signed by the TEST key:
#                        accepted while server_key.nr pins the test key,
#                        refused once the real key is in.
#
# Needs the circuit compiled (scripts/build.sh) and the fixtures
# (make-fixtures.sh writes them into coinbase-attestation-v2/test-vectors/).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(cd "$SCRIPT_DIR/../.." && pwd)"
REAL="$CIRCUITS/coinbase-attestation-v2"
VECTORS="$REAL/test-vectors"

for f in real_apple_chain real_synthetic_ca real_server_action; do
  [ -f "$VECTORS/$f.toml" ] || { echo "$VECTORS/$f.toml missing: run scripts/coinbase-attestation-v2/make-fixtures.sh" >&2; exit 1; }
done

cd "$REAL"
PASSED=0
FAILED=0
run() {
  local name="$1" expect="$2"
  if nargo execute "witness_$name" --prover-name "test-vectors/$name" > "$VECTORS/$name.log" 2>&1; then
    if [ "$expect" = accept ]; then
      echo "  ok       $name accepted"; PASSED=$((PASSED + 1))
    else
      echo "  FAILED   $name accepted; wanted: $expect"; FAILED=$((FAILED + 1))
    fi
  elif [ "$expect" != accept ] && grep -q "$expect" "$VECTORS/$name.log"; then
    echo "  ok       $name  -> refused: $expect"; PASSED=$((PASSED + 1))
  else
    echo "  FAILED   $name  (wanted: $expect)"
    sed -n '1,12p' "$VECTORS/$name.log" | sed 's/^/           /'
    FAILED=$((FAILED + 1))
  fi
}

echo ""
echo "Real circuit (Apple's CA 1 and server_key.nr as committed):"
run real_apple_chain "Credential certificate is for another app"
run real_synthetic_ca "Credential certificate is not signed by the App Attest intermediate"
if node "$SCRIPT_DIR/set-server-key.js" --show | grep -q "INSECURE TEST KEY"; then
  run real_server_action accept
  echo "  NOTE     server_key.nr pins the INSECURE test key; mainnet deploys are refused"
else
  run real_server_action "Statement signature is invalid"
fi
echo ""
echo "  $PASSED passed, $FAILED failed"
exit $([ "$FAILED" -eq 0 ] && echo 0 || echo 1)
