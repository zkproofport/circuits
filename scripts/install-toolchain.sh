#!/bin/bash
# Install the nargo and bb that toolchain.env pins, side by side with any
# other installed versions.
#
#   circuits/scripts/install-toolchain.sh                 # versioned folders only
#   circuits/scripts/install-toolchain.sh --make-default  # also make them the global nargo / ~/.bb/bb
#
# Both come from their official release assets for this platform:
#   nargo -> $HOME/.nargo/versions/<NARGO_VERSION>/   (noir-lang/noir release v<NARGO_VERSION>)
#   bb    -> $HOME/.bb/versions/<BB_VERSION>/         (AztecProtocol/aztec-packages release v<BB_VERSION>)
#
# The repository's scripts (scripts/lib/toolchain.sh, sourced by build.sh and
# the others) use exactly these folders, so a build never depends on what
# `nargo` or `bb` on PATH happens to be.
#
# Without --make-default nothing global changes: not the noirup-managed
# $HOME/.nargo/bin/nargo, not the $HOME/.bb/bb link. That is deliberate. A
# toolchain move is built and measured while other work keeps using the
# previous global set, and silently swapping the global binaries under it is
# how a session ends up proving with the wrong bb. --make-default runs
# `noirup --version <NARGO_VERSION>` and points $HOME/.bb/bb at the versioned
# bb; CI, which has no other user, passes it.
#
# Ends by asking each installed binary its version; a mismatch is a failure,
# not a warning.
set -eu

MAKE_DEFAULT=0
case "${1:-}" in
  "") ;;
  --make-default) MAKE_DEFAULT=1 ;;
  *) echo "usage: $0 [--make-default]" >&2; exit 1 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/../toolchain.env"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)   BB_ASSET=barretenberg-arm64-darwin.tar.gz; NARGO_ASSET=noir-aarch64-apple-darwin.tar.gz ;;
  Darwin-x86_64)  BB_ASSET=barretenberg-amd64-darwin.tar.gz; NARGO_ASSET=noir-x86_64-apple-darwin.tar.gz ;;
  Linux-x86_64)   BB_ASSET=barretenberg-amd64-linux.tar.gz;  NARGO_ASSET=noir-x86_64-unknown-linux-gnu.tar.gz ;;
  Linux-aarch64)  BB_ASSET=barretenberg-arm64-linux.tar.gz;  NARGO_ASSET=noir-aarch64-unknown-linux-gnu.tar.gz ;;
  *) echo "No nargo/bb release asset known for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

# Unpack into a fresh temporary folder first and move it into place only when
# the binary is there, so an interrupted download never leaves a folder that
# looks installed.
install_asset() {  # <url> <dest dir> <binary name>
  local url=$1 dest=$2 bin=$3 tmp
  if [ -x "$dest/$bin" ]; then
    return 0
  fi
  tmp=$(mktemp -d "${dest}.partial.XXXXXX")
  if ! curl -fsSL "$url" | tar -xz -C "$tmp"; then
    rm -rf "$tmp"
    echo "Download or unpack failed: $url" >&2
    exit 1
  fi
  if [ ! -x "$tmp/$bin" ]; then
    echo "$url did not contain ./$bin; it holds: $(ls "$tmp" | tr '\n' ' ')" >&2
    rm -rf "$tmp"
    exit 1
  fi
  rm -rf "$dest"
  mv "$tmp" "$dest"
}

NARGO_DIR="$HOME/.nargo/versions/$NARGO_VERSION"
BB_DIR="$HOME/.bb/versions/$BB_VERSION"
mkdir -p "$HOME/.nargo/versions" "$HOME/.bb/versions"
install_asset "https://github.com/noir-lang/noir/releases/download/v$NARGO_VERSION/$NARGO_ASSET" "$NARGO_DIR" nargo
install_asset "https://github.com/AztecProtocol/aztec-packages/releases/download/v$BB_VERSION/$BB_ASSET" "$BB_DIR" bb

got_nargo=$("$NARGO_DIR/nargo" --version | sed -n 's/^nargo version = //p')
got_bb=$("$BB_DIR/bb" --version)
[ "$got_nargo" = "$NARGO_VERSION" ] || { echo "$NARGO_DIR/nargo is $got_nargo, expected $NARGO_VERSION" >&2; exit 1; }
[ "$got_bb" = "$BB_VERSION" ] || { echo "$BB_DIR/bb is $got_bb, expected $BB_VERSION" >&2; exit 1; }
echo "installed: nargo $got_nargo ($NARGO_DIR), bb $got_bb ($BB_DIR)"

if [ "$MAKE_DEFAULT" = 1 ]; then
  if ! command -v noirup >/dev/null 2>&1 && [ ! -x "$HOME/.nargo/bin/noirup" ]; then
    curl -fsSL https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
  fi
  "$HOME/.nargo/bin/noirup" --version "$NARGO_VERSION"
  # Replace an existing link or file at ~/.bb/bb; never touch other versions.
  ln -sfn "$BB_DIR/bb" "$HOME/.bb/bb"
  got_nargo=$("$HOME/.nargo/bin/nargo" --version | sed -n 's/^nargo version = //p')
  got_bb=$("$HOME/.bb/bb" --version)
  [ "$got_nargo" = "$NARGO_VERSION" ] || { echo "global nargo is $got_nargo, expected $NARGO_VERSION" >&2; exit 1; }
  [ "$got_bb" = "$BB_VERSION" ] || { echo "global bb is $got_bb, expected $BB_VERSION" >&2; exit 1; }
  echo "global default: nargo $got_nargo ($HOME/.nargo/bin), bb $got_bb ($HOME/.bb/bb)"
fi
