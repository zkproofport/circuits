#!/usr/bin/env bash
#
# Put a locally-generated proof in front of the DEPLOYED verifier contract.
#
#   ./scripts/verify-onchain.sh <circuit-dir> <network>
#   ./scripts/verify-onchain.sh arc-eligibility arc-testnet
#
# `build.sh` already runs `bb verify` off-chain at step 6, so a proof that
# reaches this script has been checked once. That check and this one are not
# the same claim: off-chain proves the maths, on-chain proves the DEPLOYED
# BYTES accept it. They diverge for real reasons -- a verifier built from a
# different bb, a public-input layout the contract disagrees with, a contract
# deployed from a stale .sol -- and each of those passes off-chain and fails
# here.
#
# `eth_call`, not a transaction: the verifier's `verify` is `view`, so this
# costs no gas and writes nothing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"
cd "$CIRCUITS_DIR"

if [ $# -ne 2 ]; then
    echo "Usage: $0 <circuit-dir> <network>" >&2
    echo "Example: $0 arc-eligibility arc-testnet" >&2
    exit 1
fi

CIRCUIT_DIR_NAME="$1"
NETWORK="$2"
TARGET="$CIRCUIT_DIR_NAME/target"

case "$NETWORK" in
  arc-testnet) RPC_URL="${ARC_TESTNET_RPC_URL:-https://rpc.testnet.arc.io}"; CHAIN_ID=5042002 ;;
  # GIWA was missing here, which is the whole reason a GIWA-only copy of this
  # check grew under scripts/giwa-poc/. One table, so the next circuit on a new
  # chain adds a line instead of a script.
  giwa-sepolia) RPC_URL="${GIWA_SEPOLIA_RPC_URL:-https://sepolia-rpc.giwa.io/}"; CHAIN_ID=91342 ;;
  base-sepolia) RPC_URL="${BASE_SEPOLIA_RPC_URL:-}"; CHAIN_ID=84532 ;;
  sepolia) RPC_URL="${SEPOLIA_RPC_URL:-}"; CHAIN_ID=11155111 ;;
  base) RPC_URL="${BASE_RPC_URL:-}"; CHAIN_ID=8453 ;;
  mainnet) RPC_URL="${MAINNET_RPC_URL:-}"; CHAIN_ID=1 ;;
  *) echo "Unknown network '$NETWORK'" >&2; exit 1 ;;
esac

if [ -z "$RPC_URL" ]; then
    echo "No RPC URL for $NETWORK. Set it in .env.development / .env.production." >&2
    exit 1
fi

for f in "$TARGET/proof/proof" "$TARGET/proof/public_inputs" "$TARGET/vk/vk"; do
    if [ ! -f "$f" ]; then
        echo "Missing $f" >&2
        echo "  Build the circuit first:  ./scripts/build.sh $CIRCUIT_DIR_NAME" >&2
        exit 1
    fi
done

# The deploy script's own record, not a hand-copied address.
SCRIPT_NAME=$(echo "$CIRCUIT_DIR_NAME" | awk -F'[-/]' '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)} 1' OFS='')
BROADCAST="broadcast/Deploy${SCRIPT_NAME}.s.sol/${CHAIN_ID}/run-latest.json"
if [ ! -f "$BROADCAST" ]; then
    echo "No deployment record at $BROADCAST" >&2
    echo "  Deploy first:  ./scripts/deploy_verifier.sh $CIRCUIT_DIR_NAME $NETWORK" >&2
    exit 1
fi
VERIFIER=$(python3 -c "
import json, sys
d = json.load(open('$BROADCAST'))
for t in d['transactions']:
    if t.get('transactionType') == 'CREATE' and t.get('contractName') == 'HonkVerifier':
        print(t['contractAddress']); sys.exit(0)
sys.exit('no HonkVerifier CREATE in $BROADCAST')
")

echo "Circuit:  $CIRCUIT_DIR_NAME"
echo "Network:  $NETWORK (chain $CHAIN_ID)"
echo "Verifier: $VERIFIER"
echo ""

# Off-chain first. Reporting an on-chain result without it cannot tell a broken
# proof from a mismatched contract.
echo "1. Off-chain (bb verify)..."
if ! bb verify -p "$TARGET/proof/proof" -i "$TARGET/proof/public_inputs" \
               -k "$TARGET/vk/vk" --oracle_hash keccak >/dev/null 2>&1; then
    echo "   FAILED -- the proof itself does not verify. Nothing to ask the chain." >&2
    exit 1
fi
echo "   verified"
echo ""

echo "2. On-chain (eth_call to the deployed verifier)..."
RESULT=$(python3 - "$TARGET/proof/proof" "$TARGET/proof/public_inputs" "$VERIFIER" "$RPC_URL" <<'PY'
import json, sys, urllib.request

proof_path, inputs_path, verifier, rpc = sys.argv[1:5]
proof = open(proof_path, 'rb').read()
raw_inputs = open(inputs_path, 'rb').read()
if len(raw_inputs) % 32:
    sys.exit(f'public_inputs is {len(raw_inputs)} bytes, not a multiple of 32')
words = [raw_inputs[i:i + 32] for i in range(0, len(raw_inputs), 32)]

# verify(bytes,bytes32[]) -- head is two offsets, then each dynamic part.
# keccak256("verify(bytes,bytes32[])")[:4]. Confirmed with ethers rather
# than written from memory -- the first draft of this line was wrong, and a
# wrong selector calls no function at all: the contract falls through to a
# revert that names nothing.
selector = bytes.fromhex('ea50d0e4')

def word(n: int) -> bytes:
    return n.to_bytes(32, 'big')

proof_padded = proof + b'\x00' * ((32 - len(proof) % 32) % 32)
proof_part = word(len(proof)) + proof_padded
inputs_part = word(len(words)) + b''.join(words)

head = word(64) + word(64 + len(proof_part))
data = '0x' + (selector + head + proof_part + inputs_part).hex()

req = urllib.request.Request(
    rpc,
    data=json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call',
        'params': [{'to': verifier, 'data': data}, 'latest'],
    }).encode(),
    headers={
        'content-type': 'application/json',
        # Arc's RPC answers 403 to urllib's default agent ("Python-urllib/3.x")
        # while accepting the identical request from curl. The 403 arrives
        # before any JSON-RPC error, so it reads as a rejected proof rather
        # than a rejected client.
        'user-agent': 'zkproofport-verify-onchain/1',
    },
)
with urllib.request.urlopen(req, timeout=60) as res:
    answer = json.load(res)

if 'error' in answer:
    print('REVERT ' + json.dumps(answer['error']))
    sys.exit(0)
value = answer['result']
print('TRUE' if int(value, 16) == 1 else 'FALSE ' + value)
PY
)

case "$RESULT" in
  TRUE)
    echo "   verified on chain: the deployed contract returned true"
    echo ""
    echo "=================================================="
    echo " Verified off-chain AND on-chain: $CIRCUIT_DIR_NAME on $NETWORK"
    echo "=================================================="
    ;;
  *)
    echo "   FAILED -- $RESULT" >&2
    echo "" >&2
    echo "The proof verifies locally but the deployed contract rejects it." >&2
    echo "That is a MISMATCH, not a bad proof. Usual causes:" >&2
    echo "  - the contract was deployed from a .sol built by a different bb" >&2
    echo "  - the public-input count differs from what the circuit emits" >&2
    echo "  - the deployment predates the current circuit" >&2
    exit 1
    ;;
esac
