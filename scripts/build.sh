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

BB_VERSION=$(bb --version)
echo "bb CLI version: $BB_VERSION"
echo ""

rm -rf ./target/proof ./target/vk
rm -f ./target/*.json ./target/*.sol

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

# 2. Generate Verification Key (Keccak oracle hash + ZK)
echo "2. Generating Verification Key (Keccak + ZK)..."
bb write_vk \
  -b "$CIRCUIT_JSON" \
  -o ./target/vk \
  --oracle_hash keccak
echo "VK generation complete"
echo ""

# 3. Generate Witness (only if Prover.toml exists)
if [ -f "./Prover.toml" ]; then
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
    echo "3-6. Skipping witness/proof generation (no Prover.toml)"
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
