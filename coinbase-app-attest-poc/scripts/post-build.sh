#!/bin/bash
# scripts/build.sh looks for a hook at exactly <circuit>/scripts/post-build.sh.
# First the App Attest library's own tests (they include a real Apple
# credential certificate), then the shared acceptance run.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
"$(cd "$HERE/../scripts" && pwd)/action-circuit-acceptance.sh" coinbase-app-attest-poc
