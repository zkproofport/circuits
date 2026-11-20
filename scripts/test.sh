#!/bin/bash
# Run `nargo test` with the pinned toolchain, for one or more Noir packages.
#
#   scripts/test.sh <package-dir> [<package-dir> ...]   e.g. scripts/test.sh oidc-libs deps/noir-bignum
#   scripts/test.sh --all                               every live package that has a #[test]
#
# --all walks the same packages scripts/check-deps.sh does (everything outside
# _archived-poc/, _probes/, lib/, node_modules/) plus every folder under deps/.
# nargo comes from scripts/lib/toolchain.sh, so the version toolchain.env
# pins is the one tested, whatever `nargo` is on PATH.
#
# Prints one line per package: tests passed / failed, and where the full log
# is. Logs go to a temporary folder outside the repository. Exits non-zero if
# any package fails, and names each one.
#
# NARGO_TEST_ARGS is passed through (for example "--skip-brillig-constraints-check"
# or a test-name filter); empty by default.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(dirname "$SCRIPT_DIR")"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/toolchain.sh"

[ $# -ge 1 ] || { echo "usage: $0 <package-dir> [...] | --all" >&2; exit 1; }

if [ "$1" = "--all" ]; then
  PKGS=$(cd "$CIRCUITS" && find . -name Nargo.toml \
      -not -path './_archived-poc/*' -not -path './_probes/*' -not -path './lib/*' \
      -not -path '*/node_modules/*' -not -path '*/target/*' -not -path '*/.git/*' \
    | sed 's|^\./||; s|/Nargo.toml$||' | sort | while read -r d; do
        if grep -rqs --include='*.nr' -E '#\[test' "$CIRCUITS/$d/src"; then echo "$d"; fi
      done)
else
  PKGS="$*"
fi

LOGS=$(mktemp -d "${TMPDIR:-/tmp}/circuits-nargo-test.XXXXXX")
echo "nargo $("$NARGO_BIN" --version | sed -n 's/^nargo version = //p') ($NARGO_BIN); logs in $LOGS"

# Differential tests that need a resolver. keccak256, sha256, sha512,
# poseidon and noir_base64 ship `oracle_test(s)` modules: fuzz tests that ask
# a Node reference implementation for the expected value through nargo's
# --oracle-resolver. They are not run here, and they are reported as NOT RUN,
# never as passed. Measured 2026-11-17 on this Mac: with each package's own
# server running, one keccak256 run left 16,334 sockets in TIME_WAIT -- the
# whole ephemeral port range (49152-65535) -- because nargo opens a connection
# per fuzz execution, and every later call failed with "Failed calling external
# resolver. client error (Connect)". --fuzz-max-executions did not lower that.
# Without a resolver they fail with "0 output values were provided as a
# foreign call result". Either way the failure says nothing about the library.
# A test counts as an oracle test only if its path names an oracle_test module
# AND it failed with one of those two messages.
ORACLE_FAIL='(0 output values were provided as a foreign call result|Failed calling external resolver)'

failed=""
for d in $PKGS; do
  dir="$CIRCUITS/$d"
  [ -f "$dir/Nargo.toml" ] || { echo "$d: not a Noir package" >&2; failed="$failed $d"; continue; }
  log="$LOGS/$(echo "$d" | tr '/' '_').log"
  # shellcheck disable=SC2086
  (cd "$dir" && "$NARGO_BIN" test ${NARGO_TEST_ARGS:-} > "$log" 2>&1)
  rc=$?
  clean=$(sed 's/\x1b\[[0-9;]*m//g' "$log")
  passed=$(printf '%s\n' "$clean" | grep -cE '^\[[^]]+\] Testing .* \.\.\. ok')
  fails=$(printf '%s\n' "$clean" | grep -cE '^\[[^]]+\] Testing .* \.\.\. FAIL')
  # A FAIL line, then its first message line: an oracle test only when both match.
  oracle=$(printf '%s\n' "$clean" | awk -v re="$ORACLE_FAIL" '
    /^\[[^]]+\] Testing .* \.\.\. FAIL/ { t = $0; next }
    t != "" { if (t ~ /oracle_test/ && $0 ~ re) n++; t = "" }
    END { print n + 0 }')
  other=$((fails - oracle))
  summary=$(printf '%s\n' "$clean" | grep -E '^\[[^]]+\] ([0-9]+ tests? (passed|failed)|No tests found)' | tail -1)
  note=""
  [ "$oracle" -gt 0 ] && note=", $oracle oracle tests NOT RUN (need --oracle-resolver)"
  if [ $rc -eq 0 ] || { [ "$other" -eq 0 ] && [ "$oracle" -gt 0 ] && [ "$passed" -gt 0 ]; }; then
    echo "PASS  $d: $passed passed, $other failed$note  ($summary)"
  else
    echo "FAIL  $d: $passed passed, $other failed$note, exit $rc  ($log)"
    failed="$failed $d"
  fi
done

if [ -n "$failed" ]; then
  echo "nargo test FAILED in:$failed"
  exit 1
fi
echo "nargo test passed in every package."
