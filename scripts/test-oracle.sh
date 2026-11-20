#!/bin/bash
# Run the oracle-backed differential tests of the vendored libraries that ship
# them, with the pinned nargo, each against its own reference server.
#
#   scripts/test-oracle.sh                      # all five below
#   scripts/test-oracle.sh keccak256 sha256     # some of them
#
# keccak256, sha256, sha512, poseidon and noir_base64 each carry an
# `oracle_test(s)` module: fuzz tests that ask a Node implementation of the same
# function for the expected answer through `nargo test --oracle-resolver`.
# scripts/test.sh cannot run them and reports them as NOT RUN. This script is
# what runs them, and CI runs it on Linux (.github/workflows/build-circuits.yml,
# job `oracle-tests`).
#
# Per package: install the server's locked dependencies (yarn, --frozen-lockfile),
# start the server the way the package's own scripts/run.sh starts it, but on a
# free port and with nargo from toolchain.env rather than PATH, wait until it
# accepts connections, run `nargo test`, and stop it. The packages whose
# upstream run.sh also runs `--force-brillig` get that second pass too.
#
# Not on macOS: nargo opens one connection per fuzz execution, and on
# 2026-11-17 one keccak256 run on a Mac left 16,334 sockets in TIME_WAIT -- the
# whole 49152-65535 ephemeral range -- after which every call, and unrelated
# downloads, failed with "client error (Connect)". Linux reuses loopback
# TIME_WAIT sockets for new outgoing connections. Run it on Linux: in CI, or
# in a Linux container.
#
# Needs: node, yarn (classic), python3, curl. Logs go to a temporary folder
# outside the repository; the last lines of a failing log are printed.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(dirname "$SCRIPT_DIR")"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/toolchain.sh"

ALL="keccak256 sha256 sha512 poseidon noir_base64"
PKGS="${*:-$ALL}"

if [ "$(uname -s)" = Darwin ] && [ "${ORACLE_TESTS_ON_MAC:-0}" != 1 ]; then
  echo "Refusing to run on macOS: the fuzz tests exhaust its ephemeral ports (see the header)." >&2
  echo "Run on Linux, or set ORACLE_TESTS_ON_MAC=1 to try anyway." >&2
  exit 1
fi
for tool in node yarn python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; exit 1; }
done

LOGS=$(mktemp -d "${TMPDIR:-/tmp}/circuits-oracle-test.XXXXXX")
echo "nargo $("$NARGO_BIN" --version | sed -n 's/^nargo version = //p') ($NARGO_BIN), node $(node --version), yarn $(yarn --version); logs in $LOGS"

SERVER_PID=""
stop_server() {
  # yarn starts node as a child: stop the whole tree, children first.
  local pid=$1 child
  for child in $(pgrep -P "$pid" 2>/dev/null); do stop_server "$child"; done
  kill "$pid" 2>/dev/null || true
}
trap '[ -n "$SERVER_PID" ] && stop_server "$SERVER_PID"' EXIT

failed=""
for pkg in $PKGS; do
  # How each package's own scripts/run.sh starts its server. An unknown name
  # is an error, not a guess.
  case "$pkg" in
    keccak256)   SERVER_DIR=deps/keccak256;             PORT_VAR=PORT;     BUILD="yarn build"; START="yarn start";            BRILLIG=1 ;;
    sha256)      SERVER_DIR=deps/sha256;                PORT_VAR=PORT;     BUILD="";           START="yarn start";            BRILLIG=1 ;;
    sha512)      SERVER_DIR=deps/sha512;                PORT_VAR=PORT;     BUILD="";           START="yarn dev";              BRILLIG=1 ;;
    poseidon)    SERVER_DIR=deps/poseidon;              PORT_VAR=PORT;     BUILD="yarn build"; START="yarn start";            BRILLIG=0 ;;
    noir_base64) SERVER_DIR=deps/noir_base64/fuzz_test; PORT_VAR=RPC_PORT; BUILD="";           START="yarn tsx rpc_server.ts"; BRILLIG=0 ;;
    *) echo "Unknown package '$pkg'. Known: $ALL." >&2; exit 1 ;;
  esac
  log="$LOGS/$pkg"

  if ! (cd "$CIRCUITS/$SERVER_DIR" && yarn install --frozen-lockfile --non-interactive > "$log.install" 2>&1); then
    echo "FAIL  $pkg: yarn install failed ($log.install)"; tail -20 "$log.install"; failed="$failed $pkg"; continue
  fi
  if [ -n "$BUILD" ] && ! (cd "$CIRCUITS/$SERVER_DIR" && $BUILD > "$log.build" 2>&1); then
    echo "FAIL  $pkg: server build failed ($log.build)"; tail -20 "$log.build"; failed="$failed $pkg"; continue
  fi

  port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
  # shellcheck disable=SC2086
  (cd "$CIRCUITS/$SERVER_DIR" && exec env "$PORT_VAR=$port" $START) > "$log.server" 2>&1 &
  SERVER_PID=$!
  if ! python3 - "$port" "$SERVER_PID" <<'PY'
import os, socket, sys, time
port, pid = int(sys.argv[1]), int(sys.argv[2])
for _ in range(1200):
    try:
        socket.create_connection(('127.0.0.1', port), timeout=1).close()
        sys.exit(0)
    except OSError:
        try:
            os.kill(pid, 0)
        except OSError:
            sys.exit(1)
        time.sleep(0.1)
sys.exit(1)
PY
  then
    echo "FAIL  $pkg: server did not start on port $port ($log.server)"; tail -20 "$log.server"
    stop_server "$SERVER_PID"; SERVER_PID=""; failed="$failed $pkg"; continue
  fi

  passes="default"
  [ "$BRILLIG" = 1 ] && passes="default force-brillig"
  for pass in $passes; do
    extra=""
    [ "$pass" = force-brillig ] && extra="--force-brillig"
    # shellcheck disable=SC2086
    "$NARGO_BIN" test --program-dir "$CIRCUITS/deps/$pkg" --oracle-resolver "http://127.0.0.1:$port" $extra > "$log.$pass" 2>&1
    rc=$?
    clean=$(sed 's/\x1b\[[0-9;]*m//g' "$log.$pass")
    passed=$(printf '%s\n' "$clean" | grep -cE '^\[[^]]+\] Testing .* \.\.\. ok')
    oracle=$(printf '%s\n' "$clean" | grep -E '^\[[^]]+\] Testing .* \.\.\. ok' | grep -c 'oracle_test')
    fails=$(printf '%s\n' "$clean" | grep -cE '^\[[^]]+\] Testing .* \.\.\. FAIL')
    if [ $rc -eq 0 ] && [ "$fails" -eq 0 ] && [ "$oracle" -gt 0 ]; then
      echo "PASS  $pkg ($pass): $passed passed, $oracle of them oracle tests"
    else
      echo "FAIL  $pkg ($pass): $passed passed ($oracle oracle), $fails failed, exit $rc ($log.$pass)"
      printf '%s\n' "$clean" | grep -A3 -E '\.\.\. FAIL' | head -40
      [ "$oracle" -gt 0 ] || echo "      (no oracle test passed: the resolver was not reached or the module is gone)"
      failed="$failed $pkg($pass)"
    fi
  done
  stop_server "$SERVER_PID"; SERVER_PID=""
done

if [ -n "$failed" ]; then
  echo "oracle tests FAILED in:$failed"
  exit 1
fi
echo "oracle tests passed in every package."
