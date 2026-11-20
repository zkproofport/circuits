#!/bin/bash
# Acceptance run for the v1 Coinbase circuits (coinbase_attestation,
# coinbase_country_attestation), which publish the OPRF nullifier but sign
# only a signal hash (no EIP-712 branch, so scripts/action-circuit-acceptance.sh
# does not apply). Called by scripts/build.sh through each circuit's
# scripts/post-build.sh.
#
#   scripts/oprf-nullifier/v1-acceptance.sh coinbase-attestation|coinbase-country-attestation
#
# 1. The fixture. <circuit>/Prover.toml is a REAL Coinbase attestation written
#    by proofport-ai/scripts/gen-prover-toml.ts (built here when missing; it
#    needs the parent repository's proofport-ai with node_modules and
#    .env.test). That generator still writes the keccak nullifier's shape, so
#    `oprf.js convert` rewrites the file for the OPRF nullifier: scope
#    keccak256("proofport") mod p, the domain and the nodes' answer from the
#    circuit id's local test key (no network). Converting twice gives the same
#    file.
# 2. The fixture accepted, and the OPRF refusals
#    (scripts/oprf-nullifier/acceptance-cases.sh).
# 3. A proof of the fixture into target/proof (proof, public_inputs,
#    proof.hex), verified -- what build.sh does for a circuit without a hook,
#    and what scripts/verify-onchain.sh <circuit> local reads.
set -u
unset NODE_OPTIONS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck disable=SC1091
. "$CIRCUITS_ROOT/scripts/lib/toolchain.sh"

CIRCUIT_REL="${1:-}"
case "$CIRCUIT_REL" in
  coinbase-attestation) OPRF_ID=coinbase_attestation ;;
  coinbase-country-attestation) OPRF_ID=coinbase_country_attestation ;;
  *) echo "Unknown circuit '$CIRCUIT_REL'. Known: coinbase-attestation, coinbase-country-attestation." >&2; exit 1 ;;
esac
# Domain and scope swapped is refused by the OPRF check itself (no statement
# binds the scope in v1).
OPRF_SWAP_REFUSAL="Challenge verification failed"
# What proofport-ai/scripts/gen-prover-toml.ts signs and scopes with.
SCOPE_STRING=proofport

CIRCUIT_DIR="$CIRCUITS_ROOT/$CIRCUIT_REL"
CIRCUIT_NAME=$(grep -m1 '^name' "$CIRCUIT_DIR/Nargo.toml" | sed 's/.*= *"\(.*\)"/\1/')
CIRCUIT_JSON="$CIRCUIT_DIR/target/${CIRCUIT_NAME}.json"
VECTORS="$CIRCUIT_DIR/test-vectors"
cd "$CIRCUIT_DIR"
mkdir -p "$VECTORS"

if [ ! -f Prover.toml ]; then
  REPO=$(git -C "$CIRCUITS_ROOT" rev-parse --show-superproject-working-tree)
  if [ -z "$REPO" ] || [ ! -f "$REPO/proofport-ai/.env.test" ]; then
    echo "  SKIPPED  acceptance run: no Prover.toml, and no proofport-ai/.env.test to build one"
    exit 0
  fi
  echo "  Prover.toml missing -- building it with proofport-ai/scripts/gen-prover-toml.ts"
  (cd "$REPO/proofport-ai" && npx tsx scripts/gen-prover-toml.ts) > "$VECTORS/regenerate.log" 2>&1 \
    || { echo "  FAILED   gen-prover-toml.ts"; sed -n '1,12p' "$VECTORS/regenerate.log"; exit 1; }
fi
node "$SCRIPT_DIR/oprf.js" convert Prover.toml "$OPRF_ID" "$SCOPE_STRING" > "$VECTORS/convert.log" 2>&1 \
  || { echo "  FAILED   could not convert Prover.toml for the OPRF nullifier"; sed -n '1,12p' "$VECTORS/convert.log"; exit 1; }

PASSED=0
FAILED=0
accept() {
  local name="$1" prover="$2"
  if nargo execute "witness_${name}" --prover-name "$prover" > "$VECTORS/${name}.log" 2>&1; then
    echo "  ok       $name"; PASSED=$((PASSED + 1))
  else
    echo "  FAILED   $name  (expected the circuit to accept it)"
    sed -n '1,12p' "$VECTORS/${name}.log" | sed 's/^/           /'; FAILED=$((FAILED + 1))
  fi
}
refuse() {
  local name="$1" prover="$2" expected="$3"
  if nargo execute "witness_${name}" --prover-name "$prover" > "$VECTORS/${name}.log" 2>&1; then
    echo "  FAILED   $name  (the circuit ACCEPTED something it must refuse)"; FAILED=$((FAILED + 1))
  elif grep -q "$expected" "$VECTORS/${name}.log"; then
    echo "  ok       $name  -> refused: $expected"; PASSED=$((PASSED + 1))
  else
    echo "  FAILED   $name  (refused, but not for the stated reason)"
    echo "           wanted: $expected"
    sed -n '1,12p' "$VECTORS/${name}.log" | sed 's/^/           /'; FAILED=$((FAILED + 1))
  fi
}

echo ""
echo "Acceptance run: $CIRCUIT_NAME"
echo ""
echo "Accepted (real Coinbase attestation):"
accept "action" "Prover"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/acceptance-cases.sh"
oprf_cases

echo ""
echo "Proof:"
mkdir -p ./target/proof
PROVE_T0=$(python3 -c 'import time; print(time.time())')
if cp ./target/witness_action.gz ./target/proof/witness.gz 2>/dev/null \
   && bb prove -b "$CIRCUIT_JSON" -w ./target/proof/witness.gz -k ./target/vk/vk -o ./target/proof -t evm > "$VECTORS/prove.log" 2>&1 \
   && PROVE_S=$(python3 -c "import time; print(f'{time.time() - $PROVE_T0:.1f}')") \
   && bb verify -p ./target/proof/proof -i ./target/proof/public_inputs -k ./target/vk/vk -t evm >> "$VECTORS/prove.log" 2>&1; then
  echo "0x$(xxd -p ./target/proof/proof | tr -d '\n')" > ./target/proof/proof.hex
  echo "  ok       proved in ${PROVE_S} s and verified ($(wc -c < ./target/proof/proof | tr -d ' ') bytes proof, $(( $(wc -c < ./target/proof/public_inputs) / 32 )) public inputs)"
  PASSED=$((PASSED + 1))
else
  echo "  FAILED   prove/verify"
  tail -12 "$VECTORS/prove.log" | sed 's/^/           /'; FAILED=$((FAILED + 1))
fi

echo ""
echo "  $PASSED passed, $FAILED failed"
echo ""
[ "$FAILED" -eq 0 ]
