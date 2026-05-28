#!/bin/bash
# mdl_kr_ownership — acceptance tests.
#
# Predicate under test: selective disclosure (disclose_flags + owner_commit)
# plus the canonical CX integrity + nullifier checks. No age or region.
#
# 16 PASS cases for every disclose_flags value (0x00..0x0F) + 9 FAIL cases
# covering each circuit assertion in isolation (integrity, nullifier,
# owner_commit recomputation, anonymous-mode discipline, mdl_commit
# binding, public-input tamper).
#
# Fixtures + per-case logs are written to test-vectors/ (gitignored).
# SKIP_POST_BUILD=1 is set when calling build.sh recursively.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_DIR="$(dirname "$SCRIPT_DIR")"
CIRCUIT_NAME=$(basename "$CIRCUIT_DIR")
MDL_DIR="$(dirname "$CIRCUIT_DIR")"
CIRCUITS_ROOT="$(dirname "$MDL_DIR")"
TARGET_REL="$(basename "$MDL_DIR")/$CIRCUIT_NAME"
GEN="$MDL_DIR/scripts/gen.mjs"
BUILD="$CIRCUITS_ROOT/scripts/build.sh"
FIXTURE_DIR="$CIRCUIT_DIR/test-vectors"

mkdir -p "$FIXTURE_DIR"
cd "$CIRCUIT_DIR"

FAILED=0
PASSED_COUNT=0
FAILED_COUNT=0

run_case() {
  local name="$1"
  local expect="$2"
  shift 2

  echo ""
  echo "  ── CASE $name  (expect=$expect)"

  if ! node "$GEN" --circuit ownership "$@" >"$FIXTURE_DIR/${name}.gen.log" 2>&1; then
    echo "     gen.mjs failed"
    sed 's/^/       /' "$FIXTURE_DIR/${name}.gen.log" | head -5
    FAILED=1
    return
  fi
  cp Prover.toml "$FIXTURE_DIR/Prover.${name}.toml"

  if SKIP_POST_BUILD=1 bash "$BUILD" "$TARGET_REL" >"$FIXTURE_DIR/${name}.build.log" 2>&1; then
    if [ "$expect" = "PASS" ]; then
      echo "     PASS  proof generated + verified"
      PASSED_COUNT=$((PASSED_COUNT + 1))
    else
      echo "     UNEXPECTED PASS  (this case must have failed)"
      FAILED=1
    fi
  else
    if [ "$expect" = "FAIL" ]; then
      local rejected
      rejected=$(grep -E "Failed assertion|assert\(.*\"" "$FIXTURE_DIR/${name}.build.log" | head -1 | tr -s ' ')
      echo "     EXPECTED FAIL  ${rejected:-circuit rejected as designed}"
      FAILED_COUNT=$((FAILED_COUNT + 1))
    else
      echo "     UNEXPECTED FAIL"
      tail -3 "$FIXTURE_DIR/${name}.build.log" | sed 's/^/       /'
      FAILED=1
    fi
  fi
}

echo ""
echo "mdl_kr_ownership — acceptance tests"
echo ""

# ─────────────────────────────────────────────────────────────────────────
# Group A — every disclose_flags value 0x00..0x0F PASSes with a correctly
# recomputed owner_commit (and zero owner_commit when flags == 0).
# ─────────────────────────────────────────────────────────────────────────
echo "  Group A — disclose_flags coverage"
for hex in 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F; do
  run_case "A_flags_0x${hex}" PASS --flags "0x${hex}"
done

# ─────────────────────────────────────────────────────────────────────────
# Group B — single-assertion tamper paths (each FAIL traces to one assert).
# ─────────────────────────────────────────────────────────────────────────
echo ""
echo "  Group B — single-assertion tamper"
run_case "B_corrupt_integrity"    FAIL --flags 0x0F --corrupt-integrity
run_case "B_corrupt_nullifier"    FAIL --flags 0x0F --corrupt-nullifier
run_case "B_corrupt_owner_commit" FAIL --flags 0x0F --corrupt-owner-commit
run_case "B_anon_with_nonzero"    FAIL --flags 0x00 --anon-with-nonzero
run_case "B_nonanon_with_zero"    FAIL --flags 0x0F --nonanon-with-zero
run_case "B_corrupt_birth"        FAIL --flags 0x0F --corrupt-birth
run_case "B_corrupt_address"      FAIL --flags 0x0F --corrupt-address
run_case "B_corrupt_signal_hash"  FAIL --flags 0x0F --corrupt-signal-hash
run_case "B_corrupt_scope"        FAIL --flags 0x0F --corrupt-scope

# ─────────────────────────────────────────────────────────────────────────
# Restore the canonical (flags=0x0F) Prover.toml and rebuild so the
# expected-fail cases above don't leave target/*.sol deleted.
# ─────────────────────────────────────────────────────────────────────────
cp "$FIXTURE_DIR/Prover.A_flags_0x0F.toml" Prover.toml
echo ""
echo "  Re-running build with flags=0x0F Prover.toml to regenerate verifier..."
if ! SKIP_POST_BUILD=1 bash "$BUILD" "$TARGET_REL" >"$FIXTURE_DIR/final_rebuild.log" 2>&1; then
  echo "  ✗ Final rebuild failed"
  tail -8 "$FIXTURE_DIR/final_rebuild.log" | sed 's/^/    /'
  exit 1
fi

echo ""
echo "  Fixtures saved: $FIXTURE_DIR/"
echo "  Summary: PASS=$PASSED_COUNT, FAIL=$FAILED_COUNT"
echo ""

if [ "$FAILED" -ne 0 ]; then
  echo "  ✗ Acceptance tests FAILED — see logs above"
  exit 1
fi

echo "  ✓ All acceptance cases passed + Solidity verifier regenerated"
