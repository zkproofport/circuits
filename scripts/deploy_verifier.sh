#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    echo ""
    echo "Usage: $0 <command> <network>"
    echo ""
    echo "Commands:"
    echo "  lib                    Deploy (or reuse) the libraries verifiers link, without a verifier"
    echo "  coinbase-attestation   Deploy CoinbaseAttestation verifier"
    echo "  coinbase-country-attestation   Deploy CoinbaseCountryAttestation verifier"
    echo "  oidc-domain-attestation        Deploy OidcDomainAttestation verifier"
    echo "  giwa-attestation               Deploy GiwaAttestation verifier"
    echo "  dojang-playground              Deploy DojangPlayground verifier"
    echo "  human-passport-score           Deploy HumanPassportScore verifier (Human Passport scoreV2 threshold)"
    echo "  coinbase-attestation-v2        Deploy CoinbaseAttestationV2 (mainnets refused while the test server key is pinned)"
    echo "  oidc-domain-attestation-android  Deploy OidcDomainAttestationAndroid (OIDC, Android key attestation signer)"
    echo "  coinbase-attestation-v2-android  Deploy CoinbaseAttestationV2Android (Coinbase KYC v2, Android key attestation signer)"
    echo "  oidc-domain-attestation-android-factory  Deploy OidcDomainAttestationAndroidFactory (OIDC, factory Android + Play Integrity)"
    echo "  coinbase-attestation-v2-android-factory  Deploy CoinbaseAttestationV2AndroidFactory (Coinbase KYC v2, factory Android + Play Integrity)"
    echo "  coinbase-country-attestation-v2  Deploy CoinbaseCountryAttestationV2 (Coinbase Country v2; mainnets refused while the test server key is pinned)"
    echo "  coinbase-country-attestation-v2-android  Deploy CoinbaseCountryAttestationV2Android (Coinbase Country v2, Android key attestation signer)"
    echo "  coinbase-country-attestation-v2-android-factory  Deploy CoinbaseCountryAttestationV2AndroidFactory (Coinbase Country v2, factory Android + Play Integrity)"
    echo ""
    echo "Networks: base-sepolia, sepolia, giwa-sepolia, base, mainnet, anvil"
    echo ""
    echo "  anvil: a local anvil node, for checking this script. Reads ANVIL_RPC_URL"
    echo "  and PRIVATE_KEY from the environment (no env file), refuses a chain id"
    echo "  other than 31337, and writes deployments/ and broadcast/ under"
    echo "  DEPLOY_OUTPUT_DIR instead of the repository. scripts/test-deploy-verifier.sh"
    echo "  runs it end to end."
    echo ""
    echo "Examples:"
    echo "  $0 lib base-sepolia"
    echo "  $0 coinbase-attestation base-sepolia"
    echo "  $0 coinbase-country-attestation base-sepolia"
    echo ""
    exit 1
}

if [ $# -ne 2 ]; then
    usage
fi

COMMAND=$1
NETWORK=$2

cd "$CIRCUITS_DIR"

case $NETWORK in
    base-sepolia|sepolia|giwa-sepolia)
        ENV_FILE=".env.development"
        ;;
    base|mainnet)
        ENV_FILE=".env.production"
        ;;
    anvil)
        ENV_FILE=""
        ;;
    *)
        echo -e "${RED}Error: Unknown network '$NETWORK'. Known: base-sepolia, sepolia, giwa-sepolia, base, mainnet, anvil.${NC}"
        exit 1
        ;;
esac

if [ -z "$ENV_FILE" ]; then
    # anvil: nothing is read from an env file, so a real deploy key or RPC URL
    # in one can never reach a local check.
    for var in ANVIL_RPC_URL PRIVATE_KEY DEPLOY_OUTPUT_DIR; do
        if [ -z "${!var:-}" ]; then
            echo -e "${RED}Error: $var must be set for network anvil${NC}"
            exit 1
        fi
    done
elif [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
    echo -e "${BLUE}Loaded $ENV_FILE${NC}"
else
    echo -e "${RED}Error: $ENV_FILE not found in $CIRCUITS_DIR${NC}"
    echo "Copy ${ENV_FILE}.example to $ENV_FILE and fill in values"
    exit 1
fi

# Read by the forge scripts (vm.envUint), never passed as a command-line flag:
# a flag shows in every process listing, and on 2026-10-23 one `ps` printed
# the mainnet deployer key into a session transcript.
export PRIVATE_KEY
if [ -z "$PRIVATE_KEY" ]; then
    echo -e "${RED}Error: PRIVATE_KEY not set in $ENV_FILE${NC}"
    exit 1
fi

case $NETWORK in
    base-sepolia)
        RPC_URL="$BASE_SEPOLIA_RPC_URL"
        CHAIN_ID=84532
        EXPLORER="https://sepolia.basescan.org"
        VERIFY_API_KEY="$ETHERSCAN_API_KEY"
        VERIFY_URL="https://api.etherscan.io/v2/api?chainid=84532"
        ;;
    sepolia)
        RPC_URL="$SEPOLIA_RPC_URL"
        CHAIN_ID=11155111
        EXPLORER="https://sepolia.etherscan.io"
        VERIFY_API_KEY="$ETHERSCAN_API_KEY"
        VERIFY_URL=""
        ;;
    base)
        RPC_URL="$BASE_RPC_URL"
        CHAIN_ID=8453
        EXPLORER="https://basescan.org"
        VERIFY_API_KEY="$ETHERSCAN_API_KEY"
        VERIFY_URL="https://api.etherscan.io/v2/api?chainid=8453"
        ;;
    mainnet)
        RPC_URL="$MAINNET_RPC_URL"
        CHAIN_ID=1
        EXPLORER="https://etherscan.io"
        VERIFY_API_KEY="$ETHERSCAN_API_KEY"
        VERIFY_URL=""
        ;;
    anvil)
        RPC_URL="$ANVIL_RPC_URL"
        CHAIN_ID=31337
        EXPLORER="(none: local anvil)"
        VERIFY_API_KEY=""
        VERIFY_URL=""
        ACTUAL_CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || true)
        if [ "$ACTUAL_CHAIN_ID" != "$CHAIN_ID" ]; then
            echo -e "${RED}Error: ANVIL_RPC_URL answers chain id '${ACTUAL_CHAIN_ID:-none}', not anvil's $CHAIN_ID${NC}"
            exit 1
        fi
        ;;
    giwa-sepolia)
        RPC_URL="$GIWA_SEPOLIA_RPC_URL"
        CHAIN_ID=91342
        EXPLORER="$GIWA_SEPOLIA_EXPLORER_URL"
        # GIWA explorer is Blockscout — no Etherscan-style verification yet
        VERIFY_API_KEY=""
        VERIFY_URL=""
        ;;
esac

if [ -z "$RPC_URL" ]; then
    echo -e "${RED}Error: RPC URL not set for $NETWORK${NC}"
    exit 1
fi

# Two shapes of contract verification. Etherscan wants an API key; Blockscout
# wants a --verifier name and no key at all, and treating one as the other
# fails only AFTER the contract is already deployed.
VERIFY_FLAGS=""
if [ -n "${VERIFIER:-}" ]; then
    VERIFY_FLAGS="--verify --verifier $VERIFIER"
    if [ -n "$VERIFY_URL" ]; then
        VERIFY_FLAGS="$VERIFY_FLAGS --verifier-url $VERIFY_URL"
    fi
elif [ -n "$VERIFY_API_KEY" ]; then
    VERIFY_FLAGS="--verify --etherscan-api-key $VERIFY_API_KEY"
    if [ -n "$VERIFY_URL" ]; then
        VERIFY_FLAGS="$VERIFY_FLAGS --verifier-url $VERIFY_URL"
    fi
fi

# anvil writes nothing into the repository: records and broadcasts go under
# DEPLOY_OUTPUT_DIR (forge reads FOUNDRY_BROADCAST for the broadcast folder),
# and no explorer verification is attempted whatever VERIFIER says.
if [ "$NETWORK" = anvil ]; then
    VERIFY_FLAGS=""
    mkdir -p "$DEPLOY_OUTPUT_DIR"
    DEPLOY_OUTPUT_DIR=$(cd "$DEPLOY_OUTPUT_DIR" && pwd)
    DEPLOYMENTS_DIR="$DEPLOY_OUTPUT_DIR/deployments/$CHAIN_ID"
    BROADCAST_ROOT="$DEPLOY_OUTPUT_DIR/broadcast"
    export FOUNDRY_BROADCAST="$BROADCAST_ROOT"
else
    DEPLOYMENTS_DIR="deployments/$CHAIN_ID"
    BROADCAST_ROOT="broadcast"
fi

# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/verifier-libraries.sh"

# LIBRARIES: every library the verifier source links, deployed once per chain
# per CODE HASH and reused by every verifier with the same library code.
#
#   deployments/<chain>/libraries/<Lib>/<codeHash>.json
#
# The hash (scripts/lib/verifier-libraries.sh) is computed from the compiled
# artifact of the .sol being deployed; a record is found by that hash, and the
# code at the recorded address is hashed again before it is linked. So a
# library of another bb is never linked: it has another hash, and a record
# that claims otherwise is refused with both hashes named.
#
# deployments/<chain>/ZKTranscriptLib.json is the bb 4.2 library the bb 4.2
# verifiers were linked to (their records name it under "library"). It stays
# as it is and is never read here: the bb 6.0.0 ZKTranscriptLib has the same
# name and different code. Measured 2026-11-17: deploying a bb 6.0.0 verifier
# with only that address linked fails in forge ("Dynamic linking not
# supported ... RelationsLib"); linking it as ZKTranscriptLib would not fail.

LIB_NAMES=()
LIB_ADDRS=()
LIB_HASHES=()
LINK_FLAGS=()

lib_fail() {
    echo -e "${RED}Error: $*${NC}" >&2
    exit 1
}

# The code at $2 must hash to $3, the hash $SOL_FILE's $1 compiles to.
check_linked_library() {
    local lib="$1" addr="$2" expected="$3" origin="$4" actual
    if ! actual=$(library_onchain_hash "$addr" "$RPC_URL"); then
        lib_fail "no code at $addr ($origin). $SOL_FILE needs $lib with code hash $expected there. Not linking it."
    fi
    if [ "$actual" != "$expected" ]; then
        lib_fail "$lib at $addr ($origin) has code hash $actual, but $SOL_FILE needs $lib with code hash $expected -- a library compiled from another verifier source (another bb). Not linking it. Remove the record if it is wrong; the next run deploys the library this source needs."
    fi
}

# Deploys library $1 through script/DeployVerifierLibrary.s.sol (from
# $LIBRARY_SOURCE, checked in resolve_libraries) and prints its address. Same
# rules as the verifier below: only a broadcast this run wrote counts, and
# only an address that holds code.
LIBRARY_SOURCE="coinbase-attestation/target/CoinbaseAttestation.sol"
deploy_library() {
    local lib="$1" status=0 marker broadcast addr="" code
    broadcast="$BROADCAST_ROOT/DeployVerifierLibrary.s.sol/$CHAIN_ID/run-latest.json"
    marker=$(mktemp)
    sleep 1
    VERIFIER_LIBRARY="$lib" forge script script/DeployVerifierLibrary.s.sol \
        --rpc-url "$RPC_URL" \
        --broadcast \
        --skip-simulation \
        --gas-estimate-multiplier "${GAS_ESTIMATE_MULTIPLIER:-130}" \
        $VERIFY_FLAGS >&2 || status=$?
    if [ -f "$broadcast" ] && [ "$broadcast" -nt "$marker" ]; then
        addr=$(python3 -c '
import json, sys
txs = json.load(open(sys.argv[1]))["transactions"]
hits = [t["contractAddress"] for t in txs if t.get("contractAddress")]
print(hits[-1] if hits else "")
' "$broadcast" 2>/dev/null)
    fi
    rm -f "$marker"
    if [ -z "$addr" ]; then
        lib_fail "no $lib address in a broadcast from this run; forge exited $status"
    fi
    code=$(cast code "$addr" --rpc-url "$RPC_URL" 2>/dev/null)
    if [ -z "$code" ] || [ "$code" = "0x" ]; then
        lib_fail "no code at $addr; $lib was not created (forge exited $status)"
    fi
    echo "$addr"
    return "$status"
}

resolve_libraries() {
    local lib artifact expected record addr recorded status i source_hash
    # The artifacts the hashes come from. forge script would compile anyway;
    # this makes the compile happen before anything is sent.
    if ! forge build > "$BUILD_LOG" 2>&1; then
        cat "$BUILD_LOG" >&2
        lib_fail "forge build failed"
    fi
    # Pass 1, no transactions: every recorded library is checked, and every
    # missing one is checked deployable, before anything is sent. Otherwise a
    # stale record found for the second library would stop the run after the
    # first was already deployed.
    for lib in $(verifier_linked_libraries "$SOL_FILE"); do
        artifact="out/$(basename "$SOL_FILE")/$lib.json"
        [ -f "$artifact" ] || lib_fail "no artifact $artifact after forge build"
        expected=$(library_artifact_hash "$artifact") || lib_fail "cannot hash $artifact"
        record="$DEPLOYMENTS_DIR/libraries/$lib/$expected.json"
        addr=""
        if [ -f "$record" ]; then
            addr=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["address"])' "$record")
            recorded=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("codeHash", ""))' "$record")
            if [ "$recorded" != "$expected" ]; then
                lib_fail "$record is filed under code hash $expected but says codeHash '$recorded'. Not linking $addr."
            fi
            check_linked_library "$lib" "$addr" "$expected" "recorded in $record"
            echo -e " $lib: reusing $addr (code hash $expected)" >&2
        else
            # script/DeployVerifierLibrary.s.sol deploys from $LIBRARY_SOURCE
            # (a forge script only sees the artifacts it imports), so that
            # file's library must be this one.
            source_hash=$(library_artifact_hash "out/$(basename "$LIBRARY_SOURCE")/$lib.json") \
                || lib_fail "cannot hash $lib in $LIBRARY_SOURCE (script/DeployVerifierLibrary.s.sol deploys it from there)"
            if [ "$source_hash" != "$expected" ]; then
                lib_fail "$lib in $LIBRARY_SOURCE has code hash $source_hash, but $SOL_FILE needs $expected. Rebuild both with the same bb (scripts/build.sh) before deploying."
            fi
            if [ -f "$DEPLOYMENTS_DIR/$lib.json" ]; then
                echo -e "${YELLOW} $lib: $DEPLOYMENTS_DIR/$lib.json is the single-library record of the bb 4.2 flow; left as it is, never linked from.${NC}" >&2
            fi
            echo -e " $lib: no record for code hash $expected on chain $CHAIN_ID; will deploy it" >&2
        fi
        LIB_NAMES+=("$lib")
        LIB_ADDRS+=("$addr")
        LIB_HASHES+=("$expected")
    done
    # Pass 2: deploy and record what is missing, then link everything.
    for i in "${!LIB_NAMES[@]}"; do
        lib="${LIB_NAMES[$i]}"
        expected="${LIB_HASHES[$i]}"
        addr="${LIB_ADDRS[$i]}"
        if [ -z "$addr" ]; then
            record="$DEPLOYMENTS_DIR/libraries/$lib/$expected.json"
            status=0
            addr=$(deploy_library "$lib") || status=$?
            # deploy_library runs in a subshell: its errors end only that.
            [ -n "$addr" ] || exit 1
            check_linked_library "$lib" "$addr" "$expected" "deployed by this run"
            mkdir -p "$(dirname "$record")"
            LIB_RECORD_ADDR="$addr" LIB_RECORD_NAME="$lib" LIB_RECORD_HASH="$expected" \
            LIB_RECORD_NETWORK="$NETWORK" LIB_RECORD_CHAIN="$CHAIN_ID" LIB_RECORD_SOURCE="$LIBRARY_SOURCE" \
            python3 -c '
import json, os, sys
e = os.environ
record = {
    "address": e["LIB_RECORD_ADDR"],
    "network": e["LIB_RECORD_NETWORK"],
    "chainId": int(e["LIB_RECORD_CHAIN"]),
    "contract": e["LIB_RECORD_NAME"],
    "codeHash": e["LIB_RECORD_HASH"],
    "codeHashOf": "keccak256 of the runtime code with its own address zeroed and the CBOR metadata removed (scripts/lib/verifier-libraries.sh)",
    "deployedFrom": e["LIB_RECORD_SOURCE"],
}
with open(sys.argv[1], "w") as f:
    json.dump(record, f, indent=2)
    f.write("\n")
' "$record"
            echo -e "${GREEN} $lib: deployed $addr, recorded in $record${NC}" >&2
            if [ "$status" -ne 0 ]; then
                echo -e "${YELLOW}$lib is deployed and recorded, but forge exited $status (usually explorer verification). Check the output above; a rerun reuses it.${NC}" >&2
                exit "$status"
            fi
            LIB_ADDRS[$i]="$addr"
        fi
        LINK_FLAGS+=(--libraries "$SOL_FILE:$lib:$addr")
    done
}

confirm_production() {
    if [ "$NETWORK" == "mainnet" ] || [ "$NETWORK" == "base" ]; then
        echo -e "${YELLOW}Warning: Deploying to production network ($NETWORK)${NC}"
        read -p "Continue? (y/N) " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    fi
}

BUILD_LOG=$(mktemp)
RUN_MARKER=$(mktemp)
trap 'rm -f "$RUN_MARKER" "$BUILD_LOG"' EXIT

if [ "$COMMAND" == "lib" ]; then
    # The libraries of one verifier source, without a verifier. Every circuit's
    # source gives the same hashes while they come from one bb, and a verifier
    # deploy resolves its own libraries anyway, so this step is optional.
    SOL_FILE="coinbase-attestation/target/CoinbaseAttestation.sol"
    if [ ! -f "$SOL_FILE" ]; then
        echo -e "${RED}Error: $SOL_FILE not found. Run build.sh first.${NC}"
        exit 1
    fi
    echo ""
    echo "============================================================"
    echo -e " ${BLUE}Libraries for $SOL_FILE on $NETWORK${NC}"
    echo "============================================================"
    confirm_production
    resolve_libraries
    for i in "${!LIB_NAMES[@]}"; do
        echo " ${LIB_NAMES[$i]}: ${LIB_ADDRS[$i]} (code hash ${LIB_HASHES[$i]})"
    done
    exit 0
fi

case $COMMAND in
    coinbase-attestation)
        SOL_FILE="coinbase-attestation/target/CoinbaseAttestation.sol"
        SCRIPT_FILE="script/DeployCoinbaseAttestation.s.sol"
        DISPLAY_NAME="CoinbaseAttestation"
        ;;
    coinbase-country-attestation)
        SOL_FILE="coinbase-country-attestation/target/CoinbaseCountryAttestation.sol"
        SCRIPT_FILE="script/DeployCoinbaseCountryAttestation.s.sol"
        DISPLAY_NAME="CoinbaseCountryAttestation"
        ;;
    oidc-domain-attestation)
        # The provider-key statement is signed by the keys statement-signer
        # pins (shared with coinbase-attestation-v2); a verifier built while
        # it pins the INSECURE test server key accepts statements anyone can
        # sign, so mainnets are refused until the real key is set.
        case $NETWORK in
            base|mainnet)
                if ! node "$SCRIPT_DIR/statement-signer/set-server-key.js" --require-real; then
                    echo -e "${RED}Error: statement-signer pins the test server key; not deploying to $NETWORK${NC}"
                    exit 1
                fi
                ;;
        esac
        SOL_FILE="oidc-domain-attestation/target/OidcDomainAttestation.sol"
        SCRIPT_FILE="script/DeployOidcDomainAttestation.s.sol"
        DISPLAY_NAME="OidcDomainAttestation"
        ;;
    oidc-domain-attestation-android|coinbase-attestation-v2-android|oidc-domain-attestation-android-factory|coinbase-attestation-v2-android-factory|coinbase-country-attestation-v2-android|coinbase-country-attestation-v2-android-factory)
        # The Android packages of oidc_domain_attestation and
        # coinbase_attestation v2 (same circuit ids, Android key attestation
        # signer). They pin Google's Key Attestation CA1 and our Play signing
        # certificate, not the server key, but share statement-signer with the
        # packages that do; mainnets are refused while it pins the test key,
        # as for those.
        case $NETWORK in
            base|mainnet)
                if ! node "$SCRIPT_DIR/statement-signer/set-server-key.js" --require-real; then
                    echo -e "${RED}Error: the statement-signer server-key check failed (see the output above); not deploying $COMMAND to $NETWORK${NC}"
                    exit 1
                fi
                ;;
        esac
        case $COMMAND in
            oidc-domain-attestation-android) DISPLAY_NAME="OidcDomainAttestationAndroid" ;;
            coinbase-attestation-v2-android) DISPLAY_NAME="CoinbaseAttestationV2Android" ;;
            oidc-domain-attestation-android-factory) DISPLAY_NAME="OidcDomainAttestationAndroidFactory" ;;
            coinbase-attestation-v2-android-factory) DISPLAY_NAME="CoinbaseAttestationV2AndroidFactory" ;;
            coinbase-country-attestation-v2-android) DISPLAY_NAME="CoinbaseCountryAttestationV2Android" ;;
            coinbase-country-attestation-v2-android-factory) DISPLAY_NAME="CoinbaseCountryAttestationV2AndroidFactory" ;;
            *) echo -e "${RED}Error: no Android package named '$COMMAND'${NC}"; exit 1 ;;
        esac
        SOL_FILE="$COMMAND/target/$DISPLAY_NAME.sol"
        SCRIPT_FILE="script/Deploy$DISPLAY_NAME.s.sol"
        ;;
    giwa-attestation)
        SOL_FILE="giwa-attestation/target/GiwaAttestation.sol"
        SCRIPT_FILE="script/DeployGiwaAttestation.s.sol"
        DISPLAY_NAME="GiwaAttestation"
        ;;
    dojang-playground)
        SOL_FILE="dojang-playground/target/DojangPlayground.sol"
        SCRIPT_FILE="script/DeployDojangPlayground.s.sol"
        DISPLAY_NAME="DojangPlayground"
        ;;
    human-passport-score)
        # No pinned server key: the issuer is chosen by a public Merkle root
        # that core compares with Human Passport's (HUMAN_PASSPORT_ISSUER_ROOT).
        SOL_FILE="human-passport-score/target/HumanPassportScore.sol"
        SCRIPT_FILE="script/DeployHumanPassportScore.s.sol"
        DISPLAY_NAME="HumanPassportScore"
        ;;
    coinbase-country-attestation-v2)
        # Coinbase Country v2: the same statement-signer anchors as Coinbase
        # KYC v2, so the same rule -- mainnets refused while the test server
        # key is pinned.
        case $NETWORK in
            base|mainnet)
                if ! node "$SCRIPT_DIR/statement-signer/set-server-key.js" --require-real; then
                    echo -e "${RED}Error: the statement-signer server-key check failed (see the output above); not deploying coinbase-country-attestation-v2 to $NETWORK${NC}"
                    exit 1
                fi
                ;;
        esac
        SOL_FILE="coinbase-country-attestation-v2/target/CoinbaseCountryAttestationV2.sol"
        SCRIPT_FILE="script/DeployCoinbaseCountryAttestationV2.s.sol"
        DISPLAY_NAME="CoinbaseCountryAttestationV2"
        ;;
    coinbase-attestation-v2)
        # Coinbase KYC v2. A verifier built while statement-signer/src/server_key.nr
        # pins the INSECURE test server key accepts statements anyone can sign,
        # so mainnets are refused until the real Cloud KMS key is set
        # (scripts/statement-signer/set-server-key.js --kms ...).
        # The prototype it replaced (coinbase-app-attest-poc) is on Base
        # Sepolia, deployments/84532/CoinbaseAppAttestPoc.json; its source is
        # circuits commit 33344e2.
        case $NETWORK in
            base|mainnet)
                if ! node "$SCRIPT_DIR/statement-signer/set-server-key.js" --require-real; then
                    # Not necessarily the test key: node itself failing (a
                    # NODE_OPTIONS preload that is missing, 2026-10-28) lands
                    # here too. The lines above say which.
                    echo -e "${RED}Error: the statement-signer server-key check failed (see the output above: the test key is pinned, or node could not run); not deploying coinbase-attestation-v2 to $NETWORK${NC}"
                    exit 1
                fi
                ;;
        esac
        SOL_FILE="coinbase-attestation-v2/target/CoinbaseAttestationV2.sol"
        SCRIPT_FILE="script/DeployCoinbaseAttestationV2.s.sol"
        DISPLAY_NAME="CoinbaseAttestationV2"
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$COMMAND'${NC}"
        usage
        ;;
esac

if [ ! -f "$SOL_FILE" ]; then
    echo -e "${RED}Error: $SOL_FILE not found. Run build.sh first.${NC}"
    exit 1
fi

confirm_production

echo ""
echo "============================================================"
echo -e " ${BLUE}Deploying $DISPLAY_NAME to $NETWORK${NC}"
echo "============================================================"
resolve_libraries
for i in "${!LIB_NAMES[@]}"; do
    echo -e " Linking ${LIB_NAMES[$i]}: ${LIB_ADDRS[$i]}"
done
echo ""

# `|| FORGE_STATUS=$?` and not a bare call: on a Blockscout chain the explorer
# verification runs AFTER the contract is already on chain and can fail on its
# own ("Not all (0 / 1) contracts were verified!"). `set -e` would take the
# script out at that point and skip the record below, leaving a deployed
# verifier that nothing in the repository names. Measured on a Blockscout
# testnet, 2026-09-22.
FORGE_STATUS=0
BROADCAST_FILE="$BROADCAST_ROOT/$(basename "$SCRIPT_FILE")/$CHAIN_ID/run-latest.json"
# Only a broadcast written by THIS run names what this run deployed. On
# 2026-10-22 a GIWA Sepolia simulation failed before broadcasting, and the
# run-latest.json left by the September deploy was read back as this run's
# result: the old address was re-recorded beside the new library and reported
# as "IS deployed".
#
# --skip-simulation: gas is estimated by the chain's own node, not by forge's
# local EVM. Since Glamsterdam reached Ethereum Sepolia (EIP-8037: code deposit
# 200 -> 1530 gas per byte), forge 1.4.3 under-estimated a 24 KB verifier by
# about 7x and every deploy ran out of gas (2026-10-23; drpc trace: "out of
# gas", stateGasUsed present). The node knows its own fork rules.
touch "$RUN_MARKER"
sleep 1
forge script "$SCRIPT_FILE" \
    --rpc-url "$RPC_URL" \
    --broadcast \
    "${LINK_FLAGS[@]}" \
    --skip-simulation \
    --gas-estimate-multiplier "${GAS_ESTIMATE_MULTIPLIER:-130}" \
    $VERIFY_FLAGS || FORGE_STATUS=$?

# RECORD THE ADDRESS, from the broadcast forge just wrote.
#
# The library had this and the verifiers did not, so deployments/<chain>/
# held one hand-written verifier record that went stale the first time the
# circuit was rebuilt. A stale verifier address does not fail: the old
# contract is still deployed and still answers, about a circuit nobody runs.
DEPLOYED_VERIFIER=""
if [ -f "$BROADCAST_FILE" ] && [ "$BROADCAST_FILE" -nt "$RUN_MARKER" ]; then
    DEPLOYED_VERIFIER=$(python3 -c "
import json
with open('$BROADCAST_FILE') as f:
    txs = json.load(f)['transactions']
hits = [t for t in txs if t.get('contractName') == 'HonkVerifier' and t.get('contractAddress')]
print(hits[-1]['contractAddress'] if hits else '')
" 2>/dev/null)
fi
# A broadcast records the address a CREATE was aimed at, mined or not. On
# 2026-10-22 three Ethereum Sepolia deploys ran out of gas (gas used == the
# estimated limit, status 0) and each was reported "IS deployed" at an address
# with no code. Only an address that now holds code counts.
if [ -n "$DEPLOYED_VERIFIER" ]; then
    CODE=$(cast code "$DEPLOYED_VERIFIER" --rpc-url "$RPC_URL" 2>/dev/null)
    if [ -z "$CODE" ] || [ "$CODE" = "0x" ]; then
        echo -e "${RED}No code at $DEPLOYED_VERIFIER: the deploy transaction did not create the contract.${NC}"
        DEPLOYED_VERIFIER=""
        [ "$FORGE_STATUS" -ne 0 ] || FORGE_STATUS=1
    fi
fi

# The verifier must call the libraries resolved above: each address appears
# in its code (forge writes them where the link placeholders were).
if [ -n "$DEPLOYED_VERIFIER" ]; then
    for i in "${!LIB_NAMES[@]}"; do
        addr_hex=$(echo "${LIB_ADDRS[$i]#0x}" | tr '[:upper:]' '[:lower:]')
        if [[ "$(echo "$CODE" | tr '[:upper:]' '[:lower:]')" != *"$addr_hex"* ]]; then
            echo -e "${RED}$DEPLOYED_VERIFIER does not contain ${LIB_NAMES[$i]} ${LIB_ADDRS[$i]}: it is not linked to the libraries resolved for it. Not recorded.${NC}"
            DEPLOYED_VERIFIER=""
            [ "$FORGE_STATUS" -ne 0 ] || FORGE_STATUS=1
            break
        fi
    done
fi

# The record names every linked library with its code hash. A record it
# replaces (an earlier verifier of this circuit on this chain, still deployed,
# perhaps still used by installed apps) is kept inside it under "replaces".
if [ -n "$DEPLOYED_VERIFIER" ]; then
    mkdir -p "$DEPLOYMENTS_DIR"
    LIBS_TSV=""
    for i in "${!LIB_NAMES[@]}"; do
        LIBS_TSV="$LIBS_TSV${LIB_NAMES[$i]} ${LIB_ADDRS[$i]} ${LIB_HASHES[$i]}
"
    done
    REC_ADDR="$DEPLOYED_VERIFIER" REC_NETWORK="$NETWORK" REC_CHAIN="$CHAIN_ID" \
    REC_LIBS="$LIBS_TSV" REC_SOURCE="$SOL_FILE" \
    python3 -c '
import json, os, sys
e = os.environ
path = sys.argv[1]
libraries = {}
for line in e["REC_LIBS"].splitlines():
    if line.strip():
        name, address, code_hash = line.split()
        libraries[name] = {"address": address, "codeHash": code_hash}
record = {
    "address": e["REC_ADDR"],
    "network": e["REC_NETWORK"],
    "chainId": int(e["REC_CHAIN"]),
    "contract": "HonkVerifier",
    "libraries": libraries,
    "deployedFrom": e["REC_SOURCE"],
}
if os.path.exists(path):
    old = json.load(open(path))
    if old.get("address", "").lower() != record["address"].lower():
        old.pop("replaces", None)
        record["replaces"] = old
with open(path, "w") as f:
    json.dump(record, f, indent=2)
    f.write("\n")
' "$DEPLOYMENTS_DIR/$DISPLAY_NAME.json"
fi

if [ "$FORGE_STATUS" -ne 0 ]; then
    echo ""
    if [ -n "$DEPLOYED_VERIFIER" ]; then
        echo -e "${YELLOW}The contract IS deployed at $DEPLOYED_VERIFIER and recorded in${NC}"
        echo -e "${YELLOW}$DEPLOYMENTS_DIR/$DISPLAY_NAME.json, but forge exited $FORGE_STATUS --${NC}"
        echo -e "${YELLOW}usually explorer source verification, which changes nothing on chain.${NC}"
        echo -e "${YELLOW}Check the output above before treating this as a failed deploy.${NC}"
    else
        echo -e "${RED}Deploy failed and no HonkVerifier address was recorded.${NC}"
    fi
    exit $FORGE_STATUS
fi

if [ -z "$DEPLOYED_VERIFIER" ]; then
    echo -e "${RED}Error: deployed, but no HonkVerifier address in $BROADCAST_FILE${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} $DISPLAY_NAME deployed to $NETWORK${NC}"
echo -e "${GREEN}============================================================${NC}"
echo " Address:   $DEPLOYED_VERIFIER"
echo " Recorded:  $DEPLOYMENTS_DIR/$DISPLAY_NAME.json"
echo " Broadcast: $BROADCAST_FILE"
echo " Explorer:  $EXPLORER"
