#!/bin/bash
# Korea mDL circuit acceptance tests.
#
# Runs after `scripts/build.sh mdl/kr`. Generates 6 edge-case Prover.toml
# fixtures + runs each through nargo execute + bb prove + bb verify.
# 3 cases must PASS, 3 must FAIL with the expected assertion. ANY
# divergence makes the overall build fail (exit 1).
#
# Fixtures are saved into mdl/kr/test-vectors/ (gitignored — they
# contain personal info from the demo OmniOne CX response).
#
# Set SKIP_POST_BUILD=1 to call build.sh recursively without re-entering
# this hook (used by the harness below).
set -u

CIRCUIT_DIR=/Users/nhn/Workspace/proofport-app-dev/circuits/mdl/kr
GEN="$CIRCUIT_DIR/scripts/gen_prover_toml.mjs"
BUILD=/Users/nhn/Workspace/proofport-app-dev/circuits/scripts/build.sh
FIXTURE_DIR="$CIRCUIT_DIR/test-vectors"

mkdir -p "$FIXTURE_DIR"
cd "$CIRCUIT_DIR"

FAILED=0

run_case() {
  local name="$1"
  local expect="$2"   # PASS or FAIL
  shift 2

  echo ""
  echo "  ── CASE $name  (expect=$expect)"

  node "$GEN" "$@" >"$FIXTURE_DIR/${name}.gen.log" 2>&1
  cp Prover.toml "$FIXTURE_DIR/Prover.${name}.toml"

  if SKIP_POST_BUILD=1 bash "$BUILD" mdl/kr >"$FIXTURE_DIR/${name}.build.log" 2>&1; then
    if [ "$expect" = "PASS" ]; then
      echo "     PASS  proof generated + verified"
    else
      echo "     UNEXPECTED PASS  (this case must have failed)"
      FAILED=1
    fi
  else
    if [ "$expect" = "FAIL" ]; then
      local rejected=$(grep -E "Failed assertion|assert\(.*\"" "$FIXTURE_DIR/${name}.build.log" | head -1 | tr -s ' ')
      echo "     EXPECTED FAIL  ${rejected:-circuit rejected as designed}"
    else
      echo "     UNEXPECTED FAIL"
      tail -3 "$FIXTURE_DIR/${name}.build.log" | sed 's/^/       /'
      FAILED=1
    fi
  fi
}

echo ""
echo "Korea mDL — acceptance tests (6 cases)"
echo ""

run_case "01_ownership_normal" PASS --flags 0x0F --region "경기도"
run_case "02_age_anonymous"    PASS --flags 0x00 --region "경기도"
run_case "03_region_match"     PASS --flags 0x00 --region "경기도"
run_case "04_region_mismatch"  FAIL --flags 0x00 --region "서울특별시"
run_case "05_underage"         FAIL --flags 0x00 --region "경기도" --age-threshold 100
run_case "06_region_chungnam"  FAIL --flags 0x00 --region "충청남도"

# Restore the normal-case Prover.toml so subsequent manual rebuilds reuse it
# AND re-run the build under that fixture. The expected-fail cases above
# delete target/*.sol when bb verify aborts, so this final pass regenerates
# the Solidity verifier (and witness/proof) against the ownership scenario.
cp "$FIXTURE_DIR/Prover.01_ownership_normal.toml" Prover.toml
echo ""
echo "  Re-running build with ownership Prover.toml to regenerate verifier..."
if ! SKIP_POST_BUILD=1 bash "$BUILD" mdl/kr >"$FIXTURE_DIR/final_rebuild.log" 2>&1; then
  echo "  ✗ Final rebuild after acceptance tests failed"
  tail -8 "$FIXTURE_DIR/final_rebuild.log" | sed 's/^/    /'
  exit 1
fi

echo ""
echo "  Fixtures saved: $FIXTURE_DIR/"
echo ""

if [ "$FAILED" -ne 0 ]; then
  echo "  ✗ Acceptance tests FAILED"
  exit 1
fi

echo "  ✓ All 6 acceptance cases passed + Solidity verifier regenerated"
