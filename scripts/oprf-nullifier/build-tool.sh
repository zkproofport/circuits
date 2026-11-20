#!/bin/bash
# Build oprf-fixture (this folder's Rust crate) once; later calls are no-ops.
# Uses only crates already in Cargo's local registry cache when one exists
# (--offline), and falls back to a normal fetch from crates.io otherwise --
# crates.io, never TACEO's OPRF network.
set -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"
[ -x "$CARGO" ] || { echo "cargo not found at $CARGO (install Rust with rustup)" >&2; exit 1; }
cd "$SCRIPT_DIR"
"$CARGO" build --release --locked --offline -q 2>/dev/null || "$CARGO" build --release --locked -q
[ -x "$SCRIPT_DIR/target/release/oprf-fixture" ] || { echo "oprf-fixture was not built" >&2; exit 1; }
