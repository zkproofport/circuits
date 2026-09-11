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
    echo "  arc-eligibility                Deploy ArcEligibility verifier (action-bound KYC)"
    echo "  giwa-attestation               Deploy GiwaAttestation verifier"
    echo "  mdl-kr-ownership               Deploy MdlKrOwnership (Korea Mobile ID — ownership)"
    echo "  mdl-kr-age                     Deploy MdlKrAge (Korea Mobile ID — age predicate)"
    echo "  mdl-kr-region                  Deploy MdlKrRegion (Korea Mobile ID — region predicate)"
    echo ""
    echo "Networks: base-sepolia, sepolia, base, mainnet, arc-testnet"
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
    base-sepolia|sepolia|giwa-sepolia|arc-testnet)
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
    arc-testnet)
        # Circle's Arc. USDC is the gas token, so a deploying wallet needs USDC
        # here rather than ETH -- faucet.circle.com. Chain id and RPC are from
        # docs.arc.io/arc/references/connect-to-arc; public mainnet is
        # 2026-09-16 and its chain id is not published by Circle yet, so only
        # the testnet is listed. The explorer is Blockscout-shaped, with no
        # Etherscan-style verification endpoint, which is why both verify
        # values are empty below.
        RPC_URL="${ARC_TESTNET_RPC_URL:-https://rpc.testnet.arc.io}"
        CHAIN_ID=5042002
        EXPLORER="https://testnet.arcscan.app"
        # Blockscout, not Etherscan: it takes no API key and wants its own
        # --verifier flag. Passing --etherscan-api-key here makes forge post to
        # Etherscan's endpoint for a chain Etherscan does not index, which
        # fails after the deploy has already succeeded.
        VERIFIER="blockscout"
        VERIFY_API_KEY=""
        VERIFY_URL="https://testnet.arcscan.app/api"
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

    OUTPUT=$(forge create "$SOL_FILE:ZKTranscriptLib" \
        --rpc-url "$RPC_URL" \
        --private-key "$PRIVATE_KEY" \
        --broadcast \
        $VERIFY_FLAGS 2>&1)

    echo "$OUTPUT"

    DEPLOYED_ADDR=$(echo "$OUTPUT" | awk '/Deployed to:/ {print $3; exit}')
    if [ -z "$DEPLOYED_ADDR" ]; then
        echo -e "${RED}Error: Failed to parse deployed address${NC}"
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
    arc-eligibility)
        SOL_FILE="arc-eligibility/target/ArcEligibility.sol"
        SCRIPT_FILE="script/DeployArcEligibility.s.sol"
        DISPLAY_NAME="ArcEligibility"
        ;;
    oidc-domain-attestation)
        SOL_FILE="oidc-domain-attestation/target/OidcDomainAttestation.sol"
        SCRIPT_FILE="script/DeployOidcDomainAttestation.s.sol"
        DISPLAY_NAME="OidcDomainAttestation"
        ;;
    giwa-attestation)
        SOL_FILE="giwa-attestation/target/GiwaAttestation.sol"
        SCRIPT_FILE="script/DeployGiwaAttestation.s.sol"
        DISPLAY_NAME="GiwaAttestation"
        ;;
    mdl-kr-ownership)
        SOL_FILE="mdl/kr-ownership/target/MdlKrOwnership.sol"
        SCRIPT_FILE="script/DeployMdlKrOwnership.s.sol"
        DISPLAY_NAME="MdlKrOwnership"
        ;;
    mdl-kr-age)
        SOL_FILE="mdl/kr-age/target/MdlKrAge.sol"
        SCRIPT_FILE="script/DeployMdlKrAge.s.sol"
        DISPLAY_NAME="MdlKrAge"
        ;;
    mdl-kr-region)
        SOL_FILE="mdl/kr-region/target/MdlKrRegion.sol"
        SCRIPT_FILE="script/DeployMdlKrRegion.s.sol"
        DISPLAY_NAME="MdlKrRegion"
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

forge script "$SCRIPT_FILE" \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --libraries "$SOL_FILE:ZKTranscriptLib:$LIB_ADDRESS" \
    $VERIFY_FLAGS

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} $DISPLAY_NAME deployed to $NETWORK${NC}"
echo -e "${GREEN}============================================================${NC}"
echo " Broadcast: broadcast/$(basename $SCRIPT_FILE)/$CHAIN_ID/run-latest.json"
echo " Explorer: $EXPLORER"
