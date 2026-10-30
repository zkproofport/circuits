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
    echo "  lib                    Deploy ZKTranscriptLib (once per network)"
    echo "  coinbase-attestation   Deploy CoinbaseAttestation verifier"
    echo "  coinbase-country-attestation   Deploy CoinbaseCountryAttestation verifier"
    echo "  oidc-domain-attestation        Deploy OidcDomainAttestation verifier"
    echo "  giwa-attestation               Deploy GiwaAttestation verifier"
    echo "  dojang-playground              Deploy DojangPlayground verifier"
    echo "  coinbase-attestation-v2        Deploy CoinbaseAttestationV2 (mainnets refused while the test server key is pinned)"
    echo "  oidc-domain-attestation-android  Deploy OidcDomainAttestationAndroid (OIDC, Android key attestation signer)"
    echo "  coinbase-attestation-v2-android  Deploy CoinbaseAttestationV2Android (Coinbase KYC v2, Android key attestation signer)"
    echo "  oidc-domain-attestation-android-factory  Deploy OidcDomainAttestationAndroidFactory (OIDC, factory Android + Play Integrity)"
    echo "  coinbase-attestation-v2-android-factory  Deploy CoinbaseAttestationV2AndroidFactory (Coinbase KYC v2, factory Android + Play Integrity)"
    echo "  coinbase-country-attestation-v2  Deploy CoinbaseCountryAttestationV2 (Coinbase Country v2; mainnets refused while the test server key is pinned)"
    echo "  coinbase-country-attestation-v2-android  Deploy CoinbaseCountryAttestationV2Android (Coinbase Country v2, Android key attestation signer)"
    echo "  coinbase-country-attestation-v2-android-factory  Deploy CoinbaseCountryAttestationV2AndroidFactory (Coinbase Country v2, factory Android + Play Integrity)"
    echo ""
    echo "Networks: base-sepolia, sepolia, giwa-sepolia, base, mainnet"
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
    *)
        echo -e "${RED}Error: Unknown network '$NETWORK'${NC}"
        exit 1
        ;;
esac

if [ -f "$ENV_FILE" ]; then
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

DEPLOYMENTS_DIR="deployments/$CHAIN_ID"

resolve_lib_address() {
    local LIB_FILE="$DEPLOYMENTS_DIR/ZKTranscriptLib.json"
    if [ -f "$LIB_FILE" ]; then
        python3 -c "
import json
with open('$LIB_FILE') as f:
    print(json.load(f)['address'])
" 2>/dev/null
    fi
}

if [ "$COMMAND" == "lib" ]; then
    SOL_FILE="coinbase-attestation/target/CoinbaseAttestation.sol"

    if [ ! -f "$SOL_FILE" ]; then
        echo -e "${RED}Error: $SOL_FILE not found. Run build.sh first.${NC}"
        exit 1
    fi

    echo ""
    echo "============================================================"
    echo -e " ${BLUE}Deploying ZKTranscriptLib to $NETWORK${NC}"
    echo "============================================================"
    echo ""

    if [ "$NETWORK" == "mainnet" ] || [ "$NETWORK" == "base" ]; then
        echo -e "${YELLOW}Warning: Deploying to production network ($NETWORK)${NC}"
        read -p "Continue? (y/N) " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    fi

    # `|| LIB_STATUS=$?`: with `set -e` a failed explorer verification ended
    # the script after the library was already on chain and before it was
    # recorded, so the retry deployed a second one (Base mainnet, 2026-10-23).
    LIB_STATUS=0
    LIB_BROADCAST="broadcast/DeployTranscriptLib.s.sol/$CHAIN_ID/run-latest.json"
    LIB_MARKER=$(mktemp)
    sleep 1
    forge script script/DeployTranscriptLib.s.sol \
        --rpc-url "$RPC_URL" \
        --broadcast \
        --skip-simulation \
        $VERIFY_FLAGS || LIB_STATUS=$?

    DEPLOYED_ADDR=""
    if [ -f "$LIB_BROADCAST" ] && [ "$LIB_BROADCAST" -nt "$LIB_MARKER" ]; then
        DEPLOYED_ADDR=$(python3 -c "
import json
txs = json.load(open('$LIB_BROADCAST'))['transactions']
hits = [t['contractAddress'] for t in txs if t.get('contractAddress')]
print(hits[-1] if hits else '')
" 2>/dev/null)
    fi
    rm -f "$LIB_MARKER"
    if [ -z "$DEPLOYED_ADDR" ]; then
        echo -e "${RED}Error: no library address in a broadcast from this run; forge exited $LIB_STATUS${NC}"
        exit 1
    fi
    LIB_CODE=$(cast code "$DEPLOYED_ADDR" --rpc-url "$RPC_URL" 2>/dev/null)
    if [ -z "$LIB_CODE" ] || [ "$LIB_CODE" = "0x" ]; then
        echo -e "${RED}Error: no code at $DEPLOYED_ADDR; the library was not created${NC}"
        exit 1
    fi

    mkdir -p "$DEPLOYMENTS_DIR"
    python3 -c "
import json
data = {
    'address': '$DEPLOYED_ADDR',
    'network': '$NETWORK',
    'chainId': $CHAIN_ID,
    'contract': 'ZKTranscriptLib'
}
with open('$DEPLOYMENTS_DIR/ZKTranscriptLib.json', 'w') as f:
    json.dump(data, f, indent=2)
"

    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN} ZKTranscriptLib deployed to $NETWORK${NC}"
    echo -e "${GREEN} Address: $DEPLOYED_ADDR${NC}"
    echo -e "${GREEN} Saved to: $DEPLOYMENTS_DIR/ZKTranscriptLib.json${NC}"
    echo -e "${GREEN}============================================================${NC}"
    if [ "$LIB_STATUS" -ne 0 ]; then
        echo -e "${YELLOW}Deployed and recorded, but forge exited $LIB_STATUS (usually explorer verification). Check the output above.${NC}"
        exit "$LIB_STATUS"
    fi
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

LIB_ADDRESS=$(resolve_lib_address)
if [ -z "$LIB_ADDRESS" ]; then
    echo -e "${RED}Error: ZKTranscriptLib not deployed to $NETWORK (chain $CHAIN_ID)${NC}"
    echo "Deploy library first: $0 lib $NETWORK"
    exit 1
fi

echo ""
echo "============================================================"
echo -e " ${BLUE}Deploying $DISPLAY_NAME to $NETWORK${NC}"
echo "============================================================"
echo -e " Library: $LIB_ADDRESS"
echo ""

if [ "$NETWORK" == "mainnet" ] || [ "$NETWORK" == "base" ]; then
    echo -e "${YELLOW}Warning: Deploying to production network ($NETWORK)${NC}"
    read -p "Continue? (y/N) " -r
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
fi

# `|| FORGE_STATUS=$?` and not a bare call: on a Blockscout chain the explorer
# verification runs AFTER the contract is already on chain and can fail on its
# own ("Not all (0 / 1) contracts were verified!"). `set -e` would take the
# script out at that point and skip the record below, leaving a deployed
# verifier that nothing in the repository names. Measured on a Blockscout
# testnet, 2026-09-22.
FORGE_STATUS=0
BROADCAST_FILE="broadcast/$(basename $SCRIPT_FILE)/$CHAIN_ID/run-latest.json"
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
RUN_MARKER=$(mktemp)
trap 'rm -f "$RUN_MARKER"' EXIT
sleep 1
forge script "$SCRIPT_FILE" \
    --rpc-url "$RPC_URL" \
    --broadcast \
    --libraries "$SOL_FILE:ZKTranscriptLib:$LIB_ADDRESS" \
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

if [ -n "$DEPLOYED_VERIFIER" ]; then
    mkdir -p "$DEPLOYMENTS_DIR"
    python3 -c "
import json
record = {
    'address': '$DEPLOYED_VERIFIER',
    'network': '$NETWORK',
    'chainId': $CHAIN_ID,
    'contract': 'HonkVerifier',
    'library': '$LIB_ADDRESS',
}
with open('$DEPLOYMENTS_DIR/$DISPLAY_NAME.json', 'w') as f:
    json.dump(record, f, indent=2)
    f.write('\\n')
"
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
