#!/bin/bash
# scripts/build.sh looks for a hook at exactly <circuit>/scripts/post-build.sh.
#   1. the App Attest library's own tests (a real Apple root -> CA 1 ->
#      credential chain among them);
#   2. the synthetic-anchors copy and every fixture, rebuilt from this
#      circuit's current source (make-fixtures.sh);
#   3. the shared acceptance run against that copy;
#   4. the cases that must run against this circuit's real anchors.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$(cd "$HERE/../scripts" && pwd)"
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT
echo "App Attest library tests:"
if (cd "$HERE/../app-attest-libs" && nargo test > "$LOG" 2>&1); then
  grep -E "tests passed" "$LOG" | sed 's/^/  /'
else
  grep -E "FAIL|failed" "$LOG" | sed 's/^/  /'
  echo "  nargo test failed in app-attest-libs" >&2
  exit 1
fi
echo ""
echo "Synthetic-anchors copy and fixtures:"
"$SCRIPTS/coinbase-attestation-v2/make-fixtures.sh" > "$LOG" 2>&1 || { tail -20 "$LOG" >&2; exit 1; }
grep -E "synthetic-anchors copy:" "$LOG" | sed 's/^/  /'
"$SCRIPTS/action-circuit-acceptance.sh" coinbase-attestation-v2-synthetic-anchors
"$SCRIPTS/coinbase-attestation-v2/real-anchors-check.sh"
