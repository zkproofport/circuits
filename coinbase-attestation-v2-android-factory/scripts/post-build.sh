#!/bin/bash
# coinbase_attestation v2, ANDROID FACTORY package -- acceptance run.
# scripts/build.sh looks for a hook at exactly <circuit>/scripts/post-build.sh.
#   1. the Android key attestation library's tests (real Google chains) and
#      statement-signer's;
#   2. the synthetic-anchors copy and every fixture, rebuilt from this
#      circuit's current source (make-fixtures.sh);
#   3. the shared acceptance run against that copy (real Coinbase attestation);
#   4. the cases that must run against this circuit's real anchors (Google's
#      Key Attestation CA1).
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS="$(cd "$HERE/.." && pwd)"
SCRIPTS="$CIRCUITS/scripts"
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT
for lib in android-key-attestation play-integrity statement-signer; do
  if (cd "$CIRCUITS/$lib" && nargo test > "$LOG" 2>&1); then
    echo "  $lib Noir tests: $(grep -E 'tests passed' "$LOG" | tail -1 | sed 's/^.*\] //')"
  else
    grep -E "FAIL|failed" "$LOG" | sed 's/^/  /'
    echo "  nargo test failed in $lib" >&2
    exit 1
  fi
done
echo ""
echo "Synthetic-anchors copy and fixtures:"
"$SCRIPTS/coinbase-attestation-v2-android/make-fixtures.sh" factory > "$LOG" 2>&1 || { tail -20 "$LOG" >&2; exit 1; }
grep -E "synthetic-anchors copy:" "$LOG" | sed 's/^/  /'
"$SCRIPTS/action-circuit-acceptance.sh" coinbase-attestation-v2-android-factory-synthetic-anchors

echo "Real circuit (Google's RSA root and our Play key as committed):"
cd "$HERE"
FAILED=0
real_refuse() {
  local name="$1" expected="$2"
  if nargo execute "witness_${name}" --prover-name "test-vectors/${name}" > "test-vectors/${name}.log" 2>&1; then
    echo "  FAILED   $name  (the circuit ACCEPTED something it must refuse)"; FAILED=$((FAILED + 1))
  elif grep -qF "$expected" "test-vectors/${name}.log"; then
    echo "  ok       $name  -> $expected"
  else
    echo "  FAILED   $name  (refused, but not for the stated reason; wanted: $expected)"
    grep -m1 "error:" "test-vectors/${name}.log" | sed 's/^/           got:    /'
    FAILED=$((FAILED + 1))
  fi
}
real_refuse real_synthetic_root          "RSA root is not Google's"
real_refuse real_google_factory_chain_other_app  "Key belongs to another app"
if [ -f test-vectors/real_device_debug_build.toml ]; then
  real_refuse real_device_debug_build "App is signed with another certificate"
fi
if [ -f test-vectors/real_device.toml ]; then
  if nargo execute witness_real_device --prover-name test-vectors/real_device > test-vectors/real_device.log 2>&1; then
    echo "  ok       real_device"
  else
    echo "  FAILED   real_device (expected the circuit to accept it)"; FAILED=$((FAILED + 1))
  fi
fi
[ "$FAILED" -eq 0 ]
