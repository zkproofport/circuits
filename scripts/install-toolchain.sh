#!/bin/bash
# Install the nargo and bb that toolchain.env pins.
#
#   circuits/scripts/install-toolchain.sh
#
# nargo comes from noirup into ~/.nargo/bin. bb is the official release asset
# for this platform, unpacked into ~/.bb/versions/<BB_VERSION>/ and linked from
# ~/.bb/bb, so other versions can stay installed beside it. Put ~/.nargo/bin
# and ~/.bb on PATH.
#
# Ends by asking both binaries their version; a mismatch is a failure, not a
# warning.
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/../toolchain.env"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)   ASSET=barretenberg-arm64-darwin.tar.gz ;;
  Darwin-x86_64)  ASSET=barretenberg-amd64-darwin.tar.gz ;;
  Linux-x86_64)   ASSET=barretenberg-amd64-linux.tar.gz ;;
  Linux-aarch64)  ASSET=barretenberg-arm64-linux.tar.gz ;;
  *) echo "No bb release asset known for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

if ! command -v noirup >/dev/null 2>&1 && [ ! -x "$HOME/.nargo/bin/noirup" ]; then
  curl -fsSL https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
fi
"$HOME/.nargo/bin/noirup" --version "$NARGO_VERSION"

BB_DIR="$HOME/.bb/versions/$BB_VERSION"
if [ ! -x "$BB_DIR/bb" ]; then
  mkdir -p "$BB_DIR"
  curl -fsSL "https://github.com/AztecProtocol/aztec-packages/releases/download/v$BB_VERSION/$ASSET" | tar -xz -C "$BB_DIR"
fi
[ -x "$BB_DIR/bb" ] || { echo "bb missing after unpacking $ASSET into $BB_DIR" >&2; exit 1; }
# Replace an existing link or file at ~/.bb/bb; never touch other versions.
ln -sfn "$BB_DIR/bb" "$HOME/.bb/bb"

got_nargo=$("$HOME/.nargo/bin/nargo" --version | sed -n 's/^nargo version = //p')
got_bb=$("$HOME/.bb/bb" --version)
[ "$got_nargo" = "$NARGO_VERSION" ] || { echo "nargo is $got_nargo, expected $NARGO_VERSION" >&2; exit 1; }
[ "$got_bb" = "$BB_VERSION" ] || { echo "bb is $got_bb, expected $BB_VERSION" >&2; exit 1; }
echo "nargo $got_nargo, bb $got_bb"
