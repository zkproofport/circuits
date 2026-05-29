#!/bin/bash
# mdl_kr_region — acceptance tests (v4).
#
# Predicate under test: keccak(first whitespace-separated token of
# address, zero-padded to 64 bytes) == public region_code, always
# anonymous.
#
# Groups:
#   A — happy path + mismatch across all major si/do.
#   B — address normalisation (the circuit must do the trimming).
#   C — single-assertion tamper paths.
#       NOTE: C_corrupt_integrity and C_corrupt_signal_hash are REMOVED in v4
#       because cx_integrity_root and signal_hash are no longer circuit inputs.
#   D — nullifier determinism regression guards (v4 addition).
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
echo "mdl_kr_region — acceptance tests (v4)"
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
#
# NOTE (v4): C_corrupt_integrity and C_corrupt_signal_hash are REMOVED
# because cx_integrity_root and signal_hash are no longer circuit inputs
# (commented out pending RAON RP registration / HS256 secret provisioning).
# ─────────────────────────────────────────────────────────────────────────
echo ""
echo "  Group C — single-assertion tamper"
run_case "C_corrupt_nullifier"   FAIL --region "경기도" --corrupt-nullifier
# C_corrupt_address: flips byte 200, well past the first token that
# extract_region_token reads (Korean si/do is ~9 bytes). In v4 there is
# no mdl_commit binding address to the nullifier, so this is an expected
# PASS. Left here as documentation of v4 behavior change.
run_case "C_corrupt_address_deep_noop" PASS --region "경기도" --corrupt-address
# C_corrupt_address_token: flips byte 0, corrupting the first character of
# the first token. extract_region_token reads this byte, so the region hash
# changes and the proof fails with "Region mismatch".
run_case "C_corrupt_address_token" FAIL --region "경기도" --corrupt-address-token
run_case "C_corrupt_scope"       FAIL --region "경기도" --corrupt-scope

# ─────────────────────────────────────────────────────────────────────────
# Group D — nullifier determinism regression guards (v4 addition).
# ─────────────────────────────────────────────────────────────────────────
echo ""
echo "  Group D — nullifier determinism (v4 regression guards)"

# D1: Re-login determinism — same ci, different --signal-hash-hex (INERT).
echo ""
echo "  ── CASE D1_relogin_determinism"
node "$GEN" --circuit region --region "경기도" \
  --signal-hash-hex "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  >"$FIXTURE_DIR/D1_run1.gen.log" 2>&1
NF1=$(grep '^nullifier_value' Prover.toml || true)

node "$GEN" --circuit region --region "경기도" \
  --signal-hash-hex "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  >"$FIXTURE_DIR/D1_run2.gen.log" 2>&1
NF2=$(grep '^nullifier_value' Prover.toml || true)

if [ "$NF1" = "$NF2" ]; then
  echo "     PASS  nullifier identical across different signal_hash (INERT as designed)"
  PASSED_COUNT=$((PASSED_COUNT + 1))
else
  echo "     UNEXPECTED FAIL  nullifier_value differed between runs:"
  echo "       run1: $NF1"
  echo "       run2: $NF2"
  FAILED=1
fi

# D2: Scope isolation — same ci, different scope → nullifiers differ.
echo ""
echo "  ── CASE D2_scope_isolation"
node "$GEN" --circuit region --region "경기도" --scope "scope:alpha" \
  >"$FIXTURE_DIR/D2_alpha.gen.log" 2>&1
NF_ALPHA=$(grep '^nullifier_value' Prover.toml || true)
node "$GEN" --circuit region --region "경기도" --scope "scope:beta" \
  >"$FIXTURE_DIR/D2_beta.gen.log" 2>&1
NF_BETA=$(grep '^nullifier_value' Prover.toml || true)

if [ "$NF_ALPHA" != "$NF_BETA" ]; then
  echo "     PASS  nullifiers differ across scopes as expected"
  PASSED_COUNT=$((PASSED_COUNT + 1))
else
  echo "     UNEXPECTED FAIL  nullifiers are identical across different scopes"
  FAILED=1
fi

# D3: Different user (ci mutated) — same scope → nullifiers differ.
echo ""
echo "  ── CASE D3_different_user"
node "$GEN" --circuit region --region "경기도" \
  >"$FIXTURE_DIR/D3_user1.gen.log" 2>&1
NF_USER1=$(grep '^nullifier_value' Prover.toml || true)
node "$GEN" --circuit region --region "경기도" --corrupt-ci \
  >"$FIXTURE_DIR/D3_user2.gen.log" 2>&1
NF_USER2=$(grep '^nullifier_value' Prover.toml || true)

if [ "$NF_USER1" != "$NF_USER2" ]; then
  echo "     PASS  nullifiers differ across different users (ci) as expected"
  PASSED_COUNT=$((PASSED_COUNT + 1))
else
  echo "     UNEXPECTED FAIL  nullifiers are identical for different users"
  FAILED=1
fi

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
