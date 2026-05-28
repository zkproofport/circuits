#!/bin/bash
# mdl_kr_region — acceptance tests.
#
# Predicate under test: keccak(first whitespace-separated token of
# address, zero-padded to 64 bytes) == public region_code, always
# anonymous. The token extractor must skip leading whitespace, stop at
# the next whitespace or zero byte, and reject empty addresses.
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

  if ! node "$GEN" --circuit region "$@" >"$FIXTURE_DIR/${name}.gen.log" 2>&1; then
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

TAB=$(printf '\t')

echo ""
echo "mdl_kr_region — acceptance tests"
echo ""

# ─────────────────────────────────────────────────────────────────────────
# Group A — happy path + mismatch across all major si/do.
# ─────────────────────────────────────────────────────────────────────────
echo "  Group A — region match / mismatch"
run_case "A_match_gyeonggi"      PASS --region "경기도"
run_case "A_mismatch_seoul"      FAIL --region "서울특별시"
run_case "A_mismatch_chungnam"   FAIL --region "충청남도"
run_case "A_mismatch_incheon"    FAIL --region "인천광역시"

# ─────────────────────────────────────────────────────────────────────────
# Group B — address normalisation (the circuit must do the trimming).
# ─────────────────────────────────────────────────────────────────────────
echo ""
echo "  Group B — address normalisation"
run_case "B_leading_space"       PASS --region "경기도" --address-override " 경기도 파주시 교하로 100"
run_case "B_multi_leading_space" PASS --region "경기도" --address-override "   경기도 파주시 교하로 100"
run_case "B_leading_tab"         PASS --region "경기도" --address-override "${TAB}경기도 파주시 교하로 100"
run_case "B_tab_separator"       PASS --region "경기도" --address-override "경기도${TAB}파주시 교하로 100"
run_case "B_empty_address"       FAIL --region "경기도" --address-override ""
run_case "B_no_whitespace"       FAIL --region "경기도" --address-override "경기도파주시교하로100"

# ─────────────────────────────────────────────────────────────────────────
# Group C — single-assertion tamper paths.
# ─────────────────────────────────────────────────────────────────────────
echo ""
echo "  Group C — single-assertion tamper"
run_case "C_corrupt_integrity"   FAIL --region "경기도" --corrupt-integrity
run_case "C_corrupt_nullifier"   FAIL --region "경기도" --corrupt-nullifier
run_case "C_corrupt_address"     FAIL --region "경기도" --corrupt-address
run_case "C_corrupt_birth"       FAIL --region "경기도" --corrupt-birth
run_case "C_corrupt_signal_hash" FAIL --region "경기도" --corrupt-signal-hash
run_case "C_corrupt_scope"       FAIL --region "경기도" --corrupt-scope

# ─────────────────────────────────────────────────────────────────────────
# Restore canonical PASS case + rebuild so target/*.sol survives.
# ─────────────────────────────────────────────────────────────────────────
cp "$FIXTURE_DIR/Prover.A_match_gyeonggi.toml" Prover.toml
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
