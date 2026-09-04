#!/bin/bash

# Generic Noir circuit build script using bb CLI + Keccak
# EVM-optimized on-chain verification
#
# Usage:
#   <circuits>/scripts/build.sh <circuit-dir>
#   <circuits>/scripts/build.sh coinbase-kyc

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"

if [ -z "$1" ]; then
    echo "Usage: ${SCRIPT_DIR}/build.sh <circuit-dir>"
    echo "Example: ${SCRIPT_DIR}/build.sh coinbase-kyc"
    exit 1
fi

# Handle relative path (.) or circuit name
if [ "$1" = "." ]; then
    CIRCUIT_DIR="$(pwd)"
else
    CIRCUIT_DIR="${CIRCUITS_DIR}/$1"
fi

if [ ! -d "$CIRCUIT_DIR" ]; then
    echo "Error: Circuit directory not found: $CIRCUIT_DIR"
    exit 1
fi

cd "$CIRCUIT_DIR"

CIRCUIT_DIR_NAME=$(basename "$CIRCUIT_DIR")

echo "=================================================="
echo "Building circuit: ${CIRCUIT_DIR_NAME}"
echo "=================================================="
echo ""

# THE bb VERSION IS CHECKED, NOT JUST PRINTED.
#
# This line used to only echo the version, and on 2026-09-03 at 01:21 — the same
# minute bb 1.2.0 was installed on a machine — proofs for all three Korea Mobile
# ID circuits were generated with it and committed. Nothing complained. The
# mistake surfaced only on 2026-09-04, when the pinned bb refused those proofs
# with "Conversion error here usually implies some bad proof serde or parsing".
#
# WHY NOTHING CAUGHT IT. The two versions produce the SAME verification key —
# measured, byte for byte, on mdl/kr-age. So the key cannot tell you which bb
# made a proof. The only visible difference is the proof itself: 16256 bytes
# from the pinned build, 16224 from 1.2.0, for the identical circuit and
# witness. A 32-byte difference in an opaque blob is not something anyone spots.
#
# The version string is therefore the only cheap signal, and printing it puts
# the burden on a person reading scrollback. Refusing is what a script is for.
#
# BB_ALLOW_VERSION_MISMATCH=1 exists for deliberately measuring another build —
# comparing output across versions is a legitimate thing to do. It is not a way
# past a surprise: anything it produces must be treated as scratch.
BB_EXPECTED_VERSION="1.0.0-nightly.20250723"
BB_VERSION=$(bb --version 2>/dev/null || echo "not found")
echo "bb CLI version: $BB_VERSION"
echo "bb CLI path:    $(command -v bb || echo 'not on PATH')"

if [ "$BB_VERSION" != "$BB_EXPECTED_VERSION" ]; then
    # The pinned binary built from source prints all-zeroes rather than a
    # version, because it skipped Aztec's release step. That is expected and
    # documented in CLAUDE.md, so it is allowed through — but named here, so
    # nobody reads it as a fault.
    if [ "$BB_VERSION" = "00000000.00000000.00000000" ]; then
        echo "  (all-zero version string: a bb built from source, which is the pinned one)"
    elif [ "${BB_ALLOW_VERSION_MISMATCH:-0}" = "1" ]; then
        echo "  [!] Version mismatch allowed by BB_ALLOW_VERSION_MISMATCH=1."
        echo "      Whatever this produces is scratch. Do not commit it."
    else
        echo ""
        echo "[FAIL] Wrong bb. Expected ${BB_EXPECTED_VERSION}, got ${BB_VERSION}."
        echo ""
        echo "  This matters even though the verification key would come out the"
        echo "  same: the PROOF format differs, and the pinned bb rejects proofs"
        echo "  another version made. That is how three circuits ended up with"
        echo "  unverifiable proofs committed on 2026-09-03."
        echo ""
        echo "  Fix the PATH rather than the symptom:"
        echo "    export PATH=\"\$HOME/.bb:\$PATH\"   # ~/.bb/bb links to the pinned build"
        echo ""
        echo "  To compare versions on purpose: BB_ALLOW_VERSION_MISMATCH=1"
        exit 1
    fi
fi
echo ""

rm -f ./target/*.json ./target/*.sol

# Do NOT `rm -rf` ./target/vk or ./target/proof, and do not delete the files bb
# writes inside them either — bb truncates vk, vk_hash, proof and public_inputs
# in place, so nothing stale survives a successful build. bb runs in a container
# over a bind-mounted host directory (Colima/lima on this machine); when the host
# removes a path that a container wrote into, the next container still resolves
# the old, now-deleted inode for it and dies with
#   Failed to open data file for writing: ./target/vk/vk (No such file or directory)
# Measured on kr-age, 6 consecutive builds each: `rm -rf ./target/vk` + let bb
# create it = 2 of 3 builds fail; `rm -rf` + host mkdir = 1 of 2 fail. Keeping the
# directory fixed vk and moved the identical failure onto ./target/proof, the
# other directory that was being `rm -rf`'d — so neither is removed now. Keeping
# target/vk also preserves the committed target/vk/SHA256SUMS digests, which the
# old `rm -rf` deleted on every build.
mkdir -p ./target/vk ./target/proof

# Detect whether this circuit ships a post-build hook (e.g. acceptance
# tests). If so, the hook OWNS all witness/prove/verify steps — the
# generic Prover.toml flow below is skipped to avoid double-running them
# against a stale single fixture.
HAS_POST_BUILD_HOOK=false
if [ -z "${SKIP_POST_BUILD:-}" ] && [ -f "$CIRCUIT_DIR/scripts/post-build.sh" ]; then
    HAS_POST_BUILD_HOOK=true
fi

# 1. Compile Noir circuit
echo "1. Compiling Noir circuit..."
nargo compile
echo "Compile complete"
echo ""

# Find compiled JSON file
CIRCUIT_JSON=$(find ./target -maxdepth 1 -name "*.json" -type f | head -1)
if [ -z "$CIRCUIT_JSON" ]; then
    echo "Error: No compiled JSON found in ./target"
    exit 1
fi

CIRCUIT_NAME=$(basename "$CIRCUIT_JSON" .json)
echo "Circuit name: $CIRCUIT_NAME"
echo ""

# NOTE ON THE PATHS INSIDE THE ARTIFACT
#
# nargo records the absolute path of every source file it read into the
# compiled .json (`file_map[*].path`), so two checkouts of the same commit
# produce byte-different artifacts purely because the accounts differ. The
# committed files carry /Users/nhn/...; a rebuild anywhere else writes its own.
# bytecode, abi, names and noir_version are identical — only file_map,
# debug_symbols and hash move.
#
# Do NOT paper over this by rewriting the paths after compiling. That was tried
# on 2026-09-04 and removed: the artifacts are meant to be produced by CI
# (.github/workflows/build-circuits.yml), which always builds at the same path,
# so there is nothing to normalize. Rewriting them locally would only make a
# local build look like a CI build while being neither.

# 2. Generate Verification Key (Keccak oracle hash + ZK)
echo "2. Generating Verification Key (Keccak + ZK)..."
bb write_vk \
  -b "$CIRCUIT_JSON" \
  -o ./target/vk \
  --oracle_hash keccak
echo "VK generation complete"
echo ""

# 3. Generate Witness (only if Prover.toml exists AND no hook owns testing)
if [ "$HAS_POST_BUILD_HOOK" = false ] && [ -f "./Prover.toml" ]; then
    echo "3. Generating Witness..."
    nargo execute witness
    mkdir -p ./target/proof
    mv ./target/witness.gz ./target/proof/
    echo "Witness generation complete"
    echo ""

    # 4. Generate Proof (Keccak oracle hash + ZK)
    echo "4. Generating Proof (Keccak + ZK)..."
    bb prove \
      -b "$CIRCUIT_JSON" \
      -w ./target/proof/witness.gz \
      -k ./target/vk/vk \
      -o ./target/proof \
      --oracle_hash keccak
    PROOF_SIZE=$(wc -c < ./target/proof/proof)
    echo "Proof generation complete: $PROOF_SIZE bytes"
    echo ""

    # 5. Convert Proof to hex
    echo "5. Converting Proof to hex..."
    xxd -p ./target/proof/proof | tr -d '\n' > ./target/proof/proof.hex
    echo "0x$(cat ./target/proof/proof.hex)" > ./target/proof/proof.hex
    echo "Hex conversion complete"
    echo ""

    # 6. Verify Proof (Keccak oracle hash + ZK)
    echo "6. Verifying Proof (Keccak + ZK)..."
    bb verify \
      -p ./target/proof/proof \
      -i ./target/proof/public_inputs \
      -k ./target/vk/vk \
      --oracle_hash keccak
    echo "Verification successful!"
    echo ""
else
    if [ "$HAS_POST_BUILD_HOOK" = true ]; then
        echo "3-6. Skipping witness/proof generation (post-build hook owns it)"
    else
        echo "3-6. Skipping witness/proof generation (no Prover.toml)"
    fi
    echo ""
    PROOF_SIZE="N/A"
fi

# 7. Generate Solidity Verifier (output to target/)
# Convert snake_case to PascalCase (e.g., zk_coinbase_attestor -> ZkCoinbaseAttestor)
VERIFIER_NAME=$(echo "$CIRCUIT_NAME" | awk -F'_' '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)} 1' OFS='')
VERIFIER_FILE="./target/${VERIFIER_NAME}.sol"

echo "7. Generating Solidity Verifier (Keccak + ZK)..."
bb write_solidity_verifier \
  -k ./target/vk/vk \
  -o "$VERIFIER_FILE"
VERIFIER_LINES=$(wc -l < "$VERIFIER_FILE")
echo "Verifier generation complete: $VERIFIER_LINES lines"
echo ""

echo "=================================================="
echo "Build complete: ${CIRCUIT_DIR_NAME}"
echo "=================================================="
echo ""
echo "Generated files in ${CIRCUIT_DIR}/target/:"
echo "  - ${CIRCUIT_NAME}.json (circuit)"
echo "  - vk/vk (verification key)"
echo "  - ${VERIFIER_NAME}.sol ($VERIFIER_LINES lines)"
if [ -f "./Prover.toml" ]; then
    echo "  - proof/ ($PROOF_SIZE bytes)"
    echo "    - witness.gz (private inputs)"
    echo "    - proof, public_inputs, proof.hex"
fi
echo ""
echo "bb CLI version: $BB_VERSION"
echo "Oracle Hash: Keccak (EVM-optimized)"

# ---------------------------------------------------------------------------
# Per-circuit post-build hook
#
# A circuit can ship a `scripts/post-build.sh` to run extra acceptance
# tests (e.g. edge-case proofs). The hook runs after the standard build
# pipeline; if it exits non-zero, the build itself is considered FAILED.
#
# To prevent infinite recursion when the hook re-invokes this script,
# SKIP_POST_BUILD=1 is propagated automatically.
# ---------------------------------------------------------------------------
if [ -z "${SKIP_POST_BUILD:-}" ] && [ -f "$CIRCUIT_DIR/scripts/post-build.sh" ]; then
    echo ""
    echo "=================================================="
    echo "Running post-build hook: scripts/post-build.sh"
    echo "=================================================="
    if ! SKIP_POST_BUILD=1 bash "$CIRCUIT_DIR/scripts/post-build.sh"; then
        echo ""
        echo "=================================================="
        echo "BUILD FAILED — post-build hook reported errors"
        echo "=================================================="
        exit 1
    fi
fi
