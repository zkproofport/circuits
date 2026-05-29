#!/bin/bash
# mdl_kr_ownership — acceptance tests (v4).
#
# Predicate under test: selective disclosure (disclose_flags + owner_commit)
# plus the canonical nullifier check (v4: keccak(keccak(ci) || scope)).
#
# Groups:
#   A — every disclose_flags value 0x00..0x0F PASSes with a correctly
#       recomputed owner_commit (zero when flags == 0).
#   B — single-assertion tamper paths (FAIL).
#       NOTE: B_corrupt_integrity and B_corrupt_signal_hash are REMOVED in v4
#       because cx_integrity_root and signal_hash are no longer circuit inputs.
#   C — off-circuit owner_commit hash matching.
#   D — nullifier determinism regression guards (v4 addition).
#       D1: re-login determinism — same ci, different --signal-hash-hex (INERT
#           in v4) → nullifier_value MUST be byte-identical. Proves that
#           signal_hash variation has no effect now (regression guard for the
#           OIDC-style design).
#       D2: scope isolation — same ci, different scope → nullifiers MUST differ.
#       D3: different user — different ci, same scope → nullifiers MUST differ.
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
echo "mdl_kr_ownership — acceptance tests (v4)"
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
#
# NOTE (v4): B_corrupt_integrity and B_corrupt_signal_hash are REMOVED
# because cx_integrity_root and signal_hash are no longer circuit inputs
# (commented out pending RAON RP registration / HS256 secret provisioning).
# ─────────────────────────────────────────────────────────────────────────
echo ""
echo "  Group B — single-assertion tamper"
run_case "B_corrupt_nullifier"    FAIL --flags 0x0F --corrupt-nullifier
run_case "B_corrupt_owner_commit" FAIL --flags 0x0F --corrupt-owner-commit
run_case "B_anon_with_nonzero"    FAIL --flags 0x00 --anon-with-nonzero
run_case "B_nonanon_with_zero"    FAIL --flags 0x0F --nonanon-with-zero
run_case "B_corrupt_birth"        FAIL --flags 0x0F --corrupt-birth
run_case "B_corrupt_scope"        FAIL --flags 0x0F --corrupt-scope

# ─────────────────────────────────────────────────────────────────────────
# Group C — off-circuit owner_commit matching.
# ─────────────────────────────────────────────────────────────────────────
echo ""
echo "  Group C — owner_commit hash matching"
run_case "C_wrong_name_flag_set"     FAIL --flags 0x01 --expected-name "다른사람"
run_case "C_wrong_birth_flag_set"    FAIL --flags 0x02 --expected-birth "20000101"
run_case "C_wrong_sex_flag_set"      FAIL --flags 0x04 --expected-sex "X"
run_case "C_wrong_telno_flag_set"    FAIL --flags 0x08 --expected-telno "01099999999"
run_case "C_wrong_name_but_flag_off" PASS --flags 0x02 --expected-name "다른사람"
run_case "C_all_match_flags_full"    PASS --flags 0x0F

# ─────────────────────────────────────────────────────────────────────────
# Group D — nullifier determinism regression guards (v4 addition).
# ─────────────────────────────────────────────────────────────────────────
echo ""
echo "  Group D — nullifier determinism (v4 regression guards)"

# D1: Re-login determinism.
# Run gen.mjs twice with same ci but different --signal-hash-hex (INERT in v4).
# Assert that the two Prover.toml files have identical nullifier_value lines,
# proving signal_hash variation has zero effect on the v4 nullifier.
echo ""
echo "  ── CASE D1_relogin_determinism"
node "$GEN" --circuit ownership --flags 0x00 \
  --signal-hash-hex "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  >"$FIXTURE_DIR/D1_run1.gen.log" 2>&1
NF1=$(grep '^nullifier_value' Prover.toml || true)
cp Prover.toml "$FIXTURE_DIR/Prover.D1_run1.toml"

node "$GEN" --circuit ownership --flags 0x00 \
  --signal-hash-hex "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  >"$FIXTURE_DIR/D1_run2.gen.log" 2>&1
NF2=$(grep '^nullifier_value' Prover.toml || true)
cp Prover.toml "$FIXTURE_DIR/Prover.D1_run2.toml"

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
node "$GEN" --circuit ownership --flags 0x00 --scope "scope:alpha" \
  >"$FIXTURE_DIR/D2_alpha.gen.log" 2>&1
NF_ALPHA=$(grep '^nullifier_value' Prover.toml || true)
node "$GEN" --circuit ownership --flags 0x00 --scope "scope:beta" \
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
node "$GEN" --circuit ownership --flags 0x00 \
  >"$FIXTURE_DIR/D3_user1.gen.log" 2>&1
NF_USER1=$(grep '^nullifier_value' Prover.toml || true)
node "$GEN" --circuit ownership --flags 0x00 --corrupt-ci \
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
