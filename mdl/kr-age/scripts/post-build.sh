#!/bin/bash
# mdl_kr_age — acceptance tests.
#
# Predicate under test: current_year - birth_year >= age_threshold,
# always anonymous. Demo subject birth_year = 1985, so in 2026 the
# subject is 41. Boundary cases verified for both threshold and
# current_year, and every other circuit assertion exercised via a
# single-line tamper.
#
# Fixtures + per-case logs are written to test-vectors/ (gitignored).
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

  if ! node "$GEN" --circuit age "$@" >"$FIXTURE_DIR/${name}.gen.log" 2>&1; then
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
echo "mdl_kr_age — acceptance tests"
echo ""

# ─────────────────────────────────────────────────────────────────────────
# Group A — age threshold boundaries (current_year=2026, birth_year=1985).
# ─────────────────────────────────────────────────────────────────────────
echo "  Group A — age threshold boundaries (current_year=2026)"
run_case "A_eq_threshold"      PASS --age-threshold 41
run_case "A_below_threshold"   PASS --age-threshold 40
run_case "A_min_threshold"     PASS --age-threshold 1
run_case "A_above_threshold"   FAIL --age-threshold 42
run_case "A_far_above"         FAIL --age-threshold 100

# ─────────────────────────────────────────────────────────────────────────
# Group B — current_year boundaries (subject ages with calendar).
# ─────────────────────────────────────────────────────────────────────────
echo ""
echo "  Group B — current_year boundaries"
run_case "B_year_2030_age_45_eq"  PASS --current-year 2030 --age-threshold 45
run_case "B_year_2030_age_46_fail" FAIL --current-year 2030 --age-threshold 46
run_case "B_year_before_birth"    FAIL --year-before-birth

# ─────────────────────────────────────────────────────────────────────────
# Group C — single-assertion tamper paths.
# ─────────────────────────────────────────────────────────────────────────
echo ""
echo "  Group C — single-assertion tamper"
run_case "C_corrupt_integrity"   FAIL --age-threshold 41 --corrupt-integrity
run_case "C_corrupt_nullifier"   FAIL --age-threshold 41 --corrupt-nullifier
run_case "C_corrupt_birth"       FAIL --age-threshold 41 --corrupt-birth
run_case "C_corrupt_address"     FAIL --age-threshold 41 --corrupt-address
run_case "C_corrupt_signal_hash" FAIL --age-threshold 41 --corrupt-signal-hash
run_case "C_corrupt_scope"       FAIL --age-threshold 41 --corrupt-scope

# ─────────────────────────────────────────────────────────────────────────
# Restore the canonical PASS case and rebuild so target/*.sol survives.
# ─────────────────────────────────────────────────────────────────────────
cp "$FIXTURE_DIR/Prover.A_eq_threshold.toml" Prover.toml
echo ""
echo "  Re-running build with canonical Prover.toml to regenerate verifier..."
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
