# The OPRF nullifier's acceptance cases, shared by every circuit that
# publishes it (oprf-nullifier-libs). Sourced by
# scripts/action-circuit-acceptance.sh and scripts/oprf-nullifier/v1-acceptance.sh
# after they define accept/refuse, with the circuit directory as the current
# directory, Prover.toml the accepted fixture, its witness already written as
# target/witness_action.gz, and OPRF_ID / OPRF_SWAP_REFUSAL / VECTORS /
# PASSED / FAILED set. OPRF_SWAP_REFUSAL names the assert that refuses domain
# and scope swapped: the OPRF's own ("Challenge verification failed"), or, in
# a circuit whose signed statement binds the scope (Coinbase v2), the
# statement's -- which runs first.
#
# scripts/oprf-nullifier/oprf.js derives each case from the accepted fixture,
# changing ONE thing, and recomputes OPRF answers with the circuit id's local
# test key (no network).

oprf_case() {
  node "$(dirname "${BASH_SOURCE[0]}")/oprf.js" tamper Prover.toml "$VECTORS/oprf_$1.toml" "$OPRF_ID" "$1" > "$VECTORS/oprf_$1.gen.log" 2>&1 \
    || { echo "  FAILED   oprf_$1  (could not derive the fixture)"; sed -n '1,6p' "$VECTORS/oprf_$1.gen.log" | sed 's/^/           /'; FAILED=$((FAILED + 1)); return 1; }
}

oprf_cases() {
  [ -n "${OPRF_ID:-}" ] || { echo "  FAILED   OPRF cases: OPRF_ID is not set for this circuit"; FAILED=$((FAILED + 1)); return; }
  [ -n "${OPRF_SWAP_REFUSAL:-}" ] || { echo "  FAILED   OPRF cases: OPRF_SWAP_REFUSAL is not set for this circuit"; FAILED=$((FAILED + 1)); return; }
  echo ""
  echo "OPRF nullifier ($OPRF_ID, local test key):"
  oprf_case nullifier_plus_one   && refuse "oprf_nullifier_plus_one"   "test-vectors/oprf_nullifier_plus_one"   "Nullifier mismatch"
  oprf_case key_hash_plus_one    && refuse "oprf_key_hash_plus_one"    "test-vectors/oprf_key_hash_plus_one"    "OPRF key hash mismatch"
  oprf_case domain_scope_swapped && refuse "oprf_domain_scope_swapped" "test-vectors/oprf_domain_scope_swapped" "$OPRF_SWAP_REFUSAL"
  oprf_case other_wallet_answer  && refuse "oprf_other_wallet_answer"  "test-vectors/oprf_other_wallet_answer"  "Challenge verification failed"
  oprf_case other_circuit_answer && refuse "oprf_other_circuit_answer" "test-vectors/oprf_other_circuit_answer" "OPRF key hash mismatch"
  # Accepted by the circuit, on purpose: any key holder can answer
  # consistently. What refuses it is the verifier pinning this proof type's
  # key hash -- so the key hash it publishes must differ from the accepted
  # fixture's.
  if oprf_case other_circuit_key; then
    accept "oprf_other_circuit_key" "test-vectors/oprf_other_circuit_key"
    if [ "$(grep -m1 '^oprf_key_hash' Prover.toml)" = "$(grep -m1 '^oprf_key_hash' "$VECTORS/oprf_other_circuit_key.toml")" ]; then
      echo "  FAILED   oprf_other_circuit_key publishes the accepted fixture's key hash"; FAILED=$((FAILED + 1))
    else
      echo "  ok       oprf_other_circuit_key  (publishes another key hash: a verifier pinning this one refuses it)"; PASSED=$((PASSED + 1))
    fi
  fi
  # scope written as scope + p -- the same Field, another 256-bit number:
  # nargo refuses an input at or above p rather than reducing it.
  oprf_case scope_plus_p && refuse "oprf_scope_plus_p" "test-vectors/oprf_scope_plus_p" "exceeds field modulus"
}
