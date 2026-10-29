#!/bin/bash
# Write a circuit's SRS (structured reference string) into its target/.
#
#   ./scripts/generate_srs.sh <circuit-dir>      e.g. coinbase-attestation
#
# Uses noir-rs's srs_downloader at the NOIR_RS_TAG in toolchain.env -- the
# noir-rs the phone proves with -- so the file matches the on-device prover.
# Lives in this repository because build.sh needs it and CI checks out this
# repository alone; it used to sit in the parent monorepo, and the first CI
# run that had to write an SRS stopped at "generate_srs.sh not found".
# Needs Rust (cargo); the first run builds srs_downloader, which takes minutes.

set -e

# rustup installs cargo into ~/.cargo/bin and edits only the INTERACTIVE shell
# profile, so a script run from a non-interactive shell -- which is every
# automated run -- gets "cargo: command not found" even though Rust is
# installed. The same trap as foundry's ~/.foundry/bin, noted in CLAUDE.md.
# Look where rustup actually puts it before giving up.
if ! command -v cargo >/dev/null 2>&1; then
    for candidate in "${CARGO_HOME:-$HOME/.cargo}/bin" "$HOME/.cargo/bin"; do
        if [ -x "$candidate/cargo" ]; then
            PATH="$candidate:$PATH"
            export PATH
            break
        fi
    done
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "Error: cargo not found on PATH and not in \$CARGO_HOME/bin or ~/.cargo/bin." >&2
    echo "Install Rust:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
    exit 1
fi

if [ -z "${1:-}" ]; then
    echo "Usage: ./scripts/generate_srs.sh <circuit-dir>   (path under circuits/, e.g. coinbase-attestation)"
    exit 1
fi

CIRCUIT_DIR_NAME="$1"
CIRCUITS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CIRCUIT_DIR="${CIRCUITS_DIR}/${CIRCUIT_DIR_NAME}"
TARGET_DIR="${CIRCUIT_DIR}/target"

echo "=================================================="
echo "SRS generation - ${CIRCUIT_DIR_NAME}"
echo "=================================================="
echo ""
echo "Circuits: $CIRCUITS_DIR"
echo "Circuit dir: $CIRCUIT_DIR"
echo ""

if [ ! -d "$CIRCUIT_DIR" ]; then
    echo "Error: Circuit directory not found: $CIRCUIT_DIR"
    exit 1
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Target directory not found: $TARGET_DIR"
    echo "Build it first: ./scripts/build.sh ${CIRCUIT_DIR_NAME}"
    exit 1
fi

# Find JSON file in target directory
CIRCUIT_JSON=$(find "$TARGET_DIR" -maxdepth 1 -name "*.json" -type f | head -1)
if [ -z "$CIRCUIT_JSON" ]; then
    echo "Error: No JSON file found in $TARGET_DIR"
    echo "Build it first: ./scripts/build.sh ${CIRCUIT_DIR_NAME}"
    exit 1
fi

CIRCUIT_NAME=$(basename "$CIRCUIT_JSON" .json)
echo "Circuit JSON: $CIRCUIT_JSON"
echo "Circuit name: $CIRCUIT_NAME"
echo ""

# The noir-rs that writes the reference string must be the one the phone
# proves with, so its tag comes from toolchain.env, and the cache is
# keyed by that tag: an unversioned cache once meant a toolchain change kept
# generating with the old prover.
# shellcheck disable=SC1091
. "${CIRCUITS_DIR}/toolchain.env"
[ -n "${NOIR_RS_TAG:-}" ] || { echo "Error: NOIR_RS_TAG missing from toolchain.env" >&2; exit 1; }
NOIR_RS_DIR="$HOME/.cache/noir-rs-tags/${NOIR_RS_TAG}"

if [ ! -d "$NOIR_RS_DIR" ]; then
    echo "Cloning noir-rs repository..."
    echo "  Location: $NOIR_RS_DIR"
    mkdir -p "$(dirname "$NOIR_RS_DIR")"
    git clone --depth 1 --branch "$NOIR_RS_TAG" https://github.com/zkmopro/noir-rs "$NOIR_RS_DIR"

    if [ $? -ne 0 ]; then
        echo "Error: noir-rs clone failed"
        exit 1
    fi
else
    echo "noir-rs repository exists (using cache)"
    echo "  Location: $NOIR_RS_DIR"
fi
echo ""

OUTPUT_SRS="${TARGET_DIR}/${CIRCUIT_NAME}.srs"

echo "Generating SRS..."
echo "  Input: $CIRCUIT_JSON"
echo "  Output: $OUTPUT_SRS"
echo "  (First run may take 5-10 min for Rust build)"
echo ""

cd "$NOIR_RS_DIR"

cargo run --release --bin srs_downloader --features srs-downloader -- \
    -c "$CIRCUIT_JSON" \
    -o "$OUTPUT_SRS"

if [ $? -eq 0 ]; then
    echo ""
    echo "=================================================="
    echo "SRS generation complete!"
    echo "=================================================="
    echo ""
    echo "Generated files in ${TARGET_DIR}:"
    ls -lh "${TARGET_DIR}/"*.srs 2>/dev/null || true
    ls -lh "${TARGET_DIR}/vk" 2>/dev/null || true
    echo ""
else
    echo ""
    echo "Error: SRS generation failed"
    echo ""
    echo "Troubleshooting:"
    echo "  1. Check Rust is installed: rustc --version"
    echo "  2. Check internet connection (SRS data download required)"
    echo "  3. Check disk space (build + SRS data)"
    echo "  4. Clear noir-rs cache and retry: rm -rf ${NOIR_RS_DIR}"
    exit 1
fi
