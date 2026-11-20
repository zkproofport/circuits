# Resolve the nargo and bb that ../../toolchain.env pins, and put exactly
# those first on PATH. Source it; do not run it.
#
#   . "$CIRCUITS_DIR/scripts/lib/toolchain.sh"
#
# The binaries come from the versioned folders scripts/install-toolchain.sh
# fills, never from whatever `nargo` / `bb` the shell happens to find:
#
#   $HOME/.nargo/versions/<NARGO_VERSION>/nargo
#   $HOME/.bb/versions/<BB_VERSION>/bb
#
# Why not PATH: several toolchains are installed side by side on purpose (a
# toolchain move is built and measured while another session keeps proving
# with the previous set), and the global `nargo` / `~/.bb/bb` say nothing
# about which one a build was meant for. A missing folder is an error naming
# the install command, not a quiet fall back to PATH.
#
# Each binary is asked its version and must answer the pinned string.
# BB_ALLOW_VERSION_MISMATCH=1 skips all of this and uses PATH as it is, for
# deliberately comparing another build; whatever that produces is scratch.
#
# Sets NARGO_BIN and BB_BIN, and prepends their folders to PATH so child
# scripts (post-build hooks, acceptance runs) that call `nargo` / `bb` get
# the same pair.

_tc_circuits="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
. "$_tc_circuits/toolchain.env"
unset _tc_circuits

if [ "${BB_ALLOW_VERSION_MISMATCH:-0}" = "1" ]; then
    NARGO_BIN=$(command -v nargo || true)
    BB_BIN=$(command -v bb || true)
    echo "  [!] BB_ALLOW_VERSION_MISMATCH=1: using nargo/bb from PATH, not toolchain.env." >&2
    echo "      Whatever this produces is scratch. Do not commit it." >&2
else
    NARGO_BIN="$HOME/.nargo/versions/$NARGO_VERSION/nargo"
    BB_BIN="$HOME/.bb/versions/$BB_VERSION/bb"
    for _tc_bin in "$NARGO_BIN" "$BB_BIN"; do
        if [ ! -x "$_tc_bin" ]; then
            echo "Error: $_tc_bin is not installed (toolchain.env pins nargo $NARGO_VERSION, bb $BB_VERSION)." >&2
            echo "  Install the pinned pair: scripts/install-toolchain.sh" >&2
            return 1 2>/dev/null || exit 1
        fi
    done
    unset _tc_bin
    _tc_nargo_got=$("$NARGO_BIN" --version 2>/dev/null | sed -n 's/^nargo version = //p')
    _tc_bb_got=$("$BB_BIN" --version 2>/dev/null)
    if [ "$_tc_nargo_got" != "$NARGO_VERSION" ] || [ "$_tc_bb_got" != "$BB_VERSION" ]; then
        echo "Error: wrong toolchain in the versioned folders." >&2
        echo "  $NARGO_BIN answers '${_tc_nargo_got}', toolchain.env pins '$NARGO_VERSION'." >&2
        echo "  $BB_BIN answers '${_tc_bb_got}', toolchain.env pins '$BB_VERSION'." >&2
        echo "  The verification key can come out identical across bb versions while" >&2
        echo "  the PROOF format differs, so this refuses. Reinstall: scripts/install-toolchain.sh" >&2
        return 1 2>/dev/null || exit 1
    fi
    unset _tc_nargo_got _tc_bb_got
    PATH="$(dirname "$NARGO_BIN"):$(dirname "$BB_BIN"):$PATH"
    export PATH
fi
export NARGO_BIN BB_BIN
