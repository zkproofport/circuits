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
    echo "  deploy    Deploy fresh implementation + proxy"
    echo "  upgrade   Upgrade existing proxy to new implementation"
    echo "  verify    Verify already-deployed contracts on Etherscan"
    echo ""
    echo "Networks: base-sepolia, sepolia, base, mainnet"
    echo ""
    echo "Examples:"
    echo "  $0 deploy base-sepolia"
    echo "  $0 upgrade base-sepolia"
    echo "  $0 verify base-sepolia"
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
    base-sepolia|sepolia)
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
esac

if [ -z "$RPC_URL" ]; then
    echo -e "${RED}Error: RPC URL not set for $NETWORK${NC}"
    exit 1
fi

VERIFY_FLAGS=""
if [ -n "$VERIFY_API_KEY" ]; then
    VERIFY_FLAGS="--verify --etherscan-api-key $VERIFY_API_KEY"
    if [ -n "$VERIFY_URL" ]; then
        VERIFY_FLAGS="$VERIFY_FLAGS --verifier-url $VERIFY_URL"
    fi
fi

DEPLOYMENTS_DIR="deployments/$CHAIN_ID"
DEPLOYMENT_FILE="$DEPLOYMENTS_DIR/ZKProofportNullifierRegistry.json"

get_deployment_addresses() {
    if [ -f "$DEPLOYMENT_FILE" ]; then
        python3 -c "
import json
with open('$DEPLOYMENT_FILE') as f:
    data = json.load(f)
    print(data.get('implementation', ''))
    print(data.get('proxy', ''))
" 2>/dev/null
    fi
}

case $COMMAND in
    deploy)
        SCRIPT_FILE="script/DeployZKProofportNullifierRegistry.s.sol"

        echo ""
        echo "============================================================"
        echo -e " ${BLUE}Deploying ZKProofportNullifierRegistry to $NETWORK${NC}"
        echo "============================================================"
        echo ""

        if [ "$NETWORK" == "mainnet" ] || [ "$NETWORK" == "base" ]; then
            echo -e "${YELLOW}Warning: Deploying to production network ($NETWORK)${NC}"
            read -p "Continue? (y/N) " -r
            [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
        fi

        OUTPUT=$(forge script "$SCRIPT_FILE" \
            --rpc-url "$RPC_URL" \
            --private-key "$PRIVATE_KEY" \
            --broadcast \
            $VERIFY_FLAGS 2>&1)

        echo "$OUTPUT"

        IMPL_ADDR=$(echo "$OUTPUT" | grep "Implementation deployed at:" | grep -oP '0x[0-9a-fA-F]+')
        PROXY_ADDR=$(echo "$OUTPUT" | grep "Proxy (ZKProofportNullifierRegistry) deployed at:" | grep -oP '0x[0-9a-fA-F]+')

        if [ -z "$IMPL_ADDR" ] || [ -z "$PROXY_ADDR" ]; then
            echo -e "${RED}Error: Failed to parse deployed addresses${NC}"
            exit 1
        fi

        mkdir -p "$DEPLOYMENTS_DIR"
        python3 -c "
import json
data = {
    'implementation': '$IMPL_ADDR',
    'proxy': '$PROXY_ADDR',
    'network': '$NETWORK',
    'chainId': $CHAIN_ID,
    'contract': 'ZKProofportNullifierRegistry'
}
with open('$DEPLOYMENT_FILE', 'w') as f:
    json.dump(data, f, indent=2)
"

        echo ""
        echo -e "${GREEN}============================================================${NC}"
        echo -e "${GREEN} ZKProofportNullifierRegistry deployed to $NETWORK${NC}"
        echo -e "${GREEN}============================================================${NC}"
        echo -e "${GREEN} Implementation: $IMPL_ADDR${NC}"
        echo -e "${GREEN} Proxy:          $PROXY_ADDR${NC}"
        echo -e "${GREEN} Saved to:       $DEPLOYMENT_FILE${NC}"
        echo -e "${GREEN}============================================================${NC}"
        echo " Broadcast: broadcast/DeployZKProofportNullifierRegistry.s.sol/$CHAIN_ID/run-latest.json"
        echo " Explorer: $EXPLORER"
        ;;

    upgrade)
        read -a ADDRS <<< $(get_deployment_addresses)
        OLD_IMPL="${ADDRS[0]}"
        PROXY_ADDR="${ADDRS[1]}"

        if [ -z "$PROXY_ADDR" ]; then
            echo -e "${RED}Error: No existing deployment found in $DEPLOYMENT_FILE${NC}"
            echo "Deploy first using: $0 deploy $NETWORK"
            exit 1
        fi

        echo ""
        echo "============================================================"
        echo -e " ${BLUE}Upgrading ZKProofportNullifierRegistry on $NETWORK${NC}"
        echo "============================================================"
        echo -e " Proxy:          $PROXY_ADDR"
        echo -e " Old Impl:       $OLD_IMPL"
        echo ""

        if [ "$NETWORK" == "mainnet" ] || [ "$NETWORK" == "base" ]; then
            echo -e "${YELLOW}Warning: Upgrading on production network ($NETWORK)${NC}"
            read -p "Continue? (y/N) " -r
            [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
        fi

        # Deploy new implementation
        OUTPUT=$(forge create "src/ZKProofportNullifierRegistry.sol:ZKProofportNullifierRegistry" \
            --rpc-url "$RPC_URL" \
            --private-key "$PRIVATE_KEY" \
            --broadcast \
            $VERIFY_FLAGS 2>&1)

        echo "$OUTPUT"

        NEW_IMPL=$(echo "$OUTPUT" | grep -oP 'Deployed to: \K0x[0-9a-fA-F]+')
        if [ -z "$NEW_IMPL" ]; then
            echo -e "${RED}Error: Failed to parse new implementation address${NC}"
            exit 1
        fi

        # Upgrade proxy to new implementation
        # Note: This requires the deployer to be the owner of the proxy
        echo ""
        echo -e "${BLUE}Calling upgradeToAndCall on proxy...${NC}"
        cast send "$PROXY_ADDR" \
            "upgradeToAndCall(address,bytes)" \
            "$NEW_IMPL" \
            "0x" \
            --rpc-url "$RPC_URL" \
            --private-key "$PRIVATE_KEY"

        # Update deployment file
        python3 -c "
import json
with open('$DEPLOYMENT_FILE', 'r') as f:
    data = json.load(f)
data['implementation'] = '$NEW_IMPL'
data['previousImplementation'] = '$OLD_IMPL'
with open('$DEPLOYMENT_FILE', 'w') as f:
    json.dump(data, f, indent=2)
"

        echo ""
        echo -e "${GREEN}============================================================${NC}"
        echo -e "${GREEN} ZKProofportNullifierRegistry upgraded on $NETWORK${NC}"
        echo -e "${GREEN}============================================================${NC}"
        echo -e "${GREEN} Proxy:          $PROXY_ADDR${NC}"
        echo -e "${GREEN} New Impl:       $NEW_IMPL${NC}"
        echo -e "${GREEN} Old Impl:       $OLD_IMPL${NC}"
        echo -e "${GREEN} Updated:        $DEPLOYMENT_FILE${NC}"
        echo -e "${GREEN}============================================================${NC}"
        ;;

    verify)
        read -a ADDRS <<< $(get_deployment_addresses)
        IMPL_ADDR="${ADDRS[0]}"
        PROXY_ADDR="${ADDRS[1]}"

        if [ -z "$IMPL_ADDR" ] || [ -z "$PROXY_ADDR" ]; then
            echo -e "${RED}Error: No deployment found in $DEPLOYMENT_FILE${NC}"
            echo "Deploy first using: $0 deploy $NETWORK"
            exit 1
        fi

        if [ -z "$VERIFY_API_KEY" ]; then
            echo -e "${RED}Error: ETHERSCAN_API_KEY not set in $ENV_FILE${NC}"
            exit 1
        fi

        echo ""
        echo "============================================================"
        echo -e " ${BLUE}Verifying ZKProofportNullifierRegistry on $NETWORK${NC}"
        echo "============================================================"
        echo -e " Implementation: $IMPL_ADDR"
        echo -e " Proxy:          $PROXY_ADDR"
        echo ""

        # Verify implementation
        echo -e "${BLUE}Verifying implementation...${NC}"
        forge verify-contract "$IMPL_ADDR" \
            "src/ZKProofportNullifierRegistry.sol:ZKProofportNullifierRegistry" \
            --chain-id "$CHAIN_ID" \
            --etherscan-api-key "$VERIFY_API_KEY" \
            $([ -n "$VERIFY_URL" ] && echo "--verifier-url $VERIFY_URL")

        # Verify proxy
        echo ""
        echo -e "${BLUE}Verifying proxy...${NC}"
        forge verify-contract "$PROXY_ADDR" \
            "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy" \
            --chain-id "$CHAIN_ID" \
            --etherscan-api-key "$VERIFY_API_KEY" \
            --constructor-args $(cast abi-encode "constructor(address,bytes)" "$IMPL_ADDR" "0x") \
            $([ -n "$VERIFY_URL" ] && echo "--verifier-url $VERIFY_URL")

        echo ""
        echo -e "${GREEN}============================================================${NC}"
        echo -e "${GREEN} Verification complete${NC}"
        echo -e "${GREEN}============================================================${NC}"
        echo " Explorer: $EXPLORER"
        ;;

    *)
        echo -e "${RED}Error: Unknown command '$COMMAND'${NC}"
        usage
        ;;
esac
