#!/usr/bin/env bash
#
# Put a locally-generated proof in front of a verifier contract: the DEPLOYED
# one on a named network, or a fresh deployment on a throwaway local chain.
#
#   ./scripts/verify-onchain.sh <circuit-dir> <network> [proof-dir]
#   ./scripts/verify-onchain.sh giwa-attestation giwa-sepolia
#   ./scripts/verify-onchain.sh oidc-domain-attestation sepolia \
#       oidc-domain-attestation/test-vectors/proof_google_bound
#   ./scripts/verify-onchain.sh coinbase-attestation local
#
# [proof-dir] holds `proof` and `public_inputs`; default <circuit-dir>/target/proof.
# Circuits whose post-build hook proves acceptance fixtures leave them under
# test-vectors/proof_<case>/, and target/proof/ stays empty.
#
# After the proof returns true, the same call is made twice more and both must
# revert or return false: once with the first public input changed by one bit
# (a verifier that accepts it is not checking the inputs) and once with one
# byte of the proof changed (one that accepts it is not checking the proof).
#
# `build.sh` already runs `bb verify` off-chain at step 6, so a proof that
# reaches this script has been checked once. That check and this one are not
# the same claim: off-chain proves the maths, on-chain proves the CONTRACT
# BYTES accept it. They diverge for real reasons -- a verifier built from a
# different bb, a public-input layout the contract disagrees with, a contract
# deployed from a stale .sol -- and each of those passes off-chain and fails
# here.
#
# `eth_call`, not a transaction: the verifier's `verify` is `view`, so this
# costs no gas and writes nothing.
#
# INPUT_PLUS_P_INDEX=<i> (optional): also send the honest proof with public
# input i written as value + p (the BN254 scalar modulus) -- the same Field,
# another 256-bit number -- and report whether the contract reduces it
# (returns true) or refuses it. nargo refuses such an input ("exceeds field
# modulus"); what this tells a verifier is whether the contract does too (see
# oprf-nullifier-libs/README.md, "What a verifier checks").
#
# TAMPER_FIELDS=<field,...> (optional): after the three calls above, send the
# honest proof once per named proof field with that field changed (value + 1
# mod p, so it stays a field element and only the maths can notice), and
# require each call to be rejected. Offsets come from the verifier's own
# constants (LOG_N, NUMBER_OF_ENTITIES, NUM_MASKING_POLYNOMIALS,
# PAIRING_POINTS_SIZE, ZK_BATCHED_RELATION_PARTIAL_LENGTH) laid out the way
# its loadProof reads a ZK proof, and the computed size must equal the proof's
# size, or the run stops. Field names:
#   libraSum | libraEvaluation
#   sumcheckUnivariate:<round>:<index>   (round < LOG_N, index < ZK_BATCHED_RELATION_PARTIAL_LENGTH)
#   sumcheckEvaluation:<i> | geminiAEvaluation:<i> | libraPolyEval:<i> (i < 4)
#   default   = libraEvaluation,libraSum,sumcheckUnivariate:0:0,libraPolyEval:0,
#               libraPolyEval:1,libraPolyEval:2,libraPolyEval:3
# Unset: nothing extra is sent (the behaviour before this option).
#
# NETWORK `anvil`: the verifier `deploy_verifier.sh <pkg> anvil` deployed to a
# running anvil, read from that run's broadcast under DEPLOY_OUTPUT_DIR
# (ANVIL_RPC_URL names the node). VERIFIER_ADDRESS, anvil only, names a
# contract a test deployed itself instead. scripts/test-deploy-verifier.sh
# drives both.
#
# NETWORK `local`: the check a new toolchain needs before anything is
# deployed. It starts anvil on a free port (killed on exit; nothing leaves
# this machine), deploys ZKTranscriptLib and HonkVerifier from the circuit's
# target/<Name>.sol with anvil's own unlocked account, runs the three calls
# above, and also prints the gas eth_estimateGas reports for the honest call
# (a whole transaction: 21,000 intrinsic and calldata included) and both
# contracts' runtime size against the 24,576-byte EIP-170 limit. Anvil
# enforces that limit, so an oversized verifier fails to deploy here too.
# The committed .sol is first compared with what this bb writes from
# target/vk/vk; a verifier that no longer matches its key is refused.
# A `-synthetic-anchors` directory (gitignored, test anchors) has no committed
# verifier, so one is generated from its own vk into its target/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# nargo and bb from the versioned folders toolchain.env pins (never PATH).
# shellcheck disable=SC1091
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/lib/toolchain.sh"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/verifier-libraries.sh"
cd "$CIRCUITS_DIR"

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "Usage: $0 <circuit-dir> <network|anvil|local> [proof-dir]" >&2
    echo "Example: $0 giwa-attestation giwa-sepolia" >&2
    exit 1
fi

CIRCUIT_DIR_NAME="$1"
NETWORK="$2"
TARGET="$CIRCUIT_DIR_NAME/target"
PROOF_DIR="${3:-$TARGET/proof}"

pascal() { echo "$1" | awk -F'[-_/]' '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)} 1' OFS=''; }

for f in "$PROOF_DIR/proof" "$PROOF_DIR/public_inputs" "$TARGET/vk/vk"; do
    if [ ! -f "$f" ]; then
        echo "Missing $f" >&2
        echo "  Build the circuit first:  ./scripts/build.sh $CIRCUIT_DIR_NAME" >&2
        exit 1
    fi
done

WORK=$(mktemp -d)
ANVIL_PID=""
cleanup() {
    if [ -n "$ANVIL_PID" ]; then kill "$ANVIL_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

if [ "$NETWORK" = local ]; then
    EIP170_LIMIT=24576
    OVER_LIMIT=""

    # The verifier source: the one build.sh wrote (named after the package, as
    # build.sh names it), checked against what this bb writes from the vk.
    CIRCUIT_NAME=$(grep -m1 '^name' "$CIRCUIT_DIR_NAME/Nargo.toml" | sed 's/.*= *"\(.*\)"/\1/')
    PKG_SOL="$TARGET/$(pascal "$CIRCUIT_NAME").sol"
    bb write_solidity_verifier -k "$TARGET/vk/vk" -o "$WORK/fresh.sol" -t evm >/dev/null 2>&1 || {
        echo "bb write_solidity_verifier failed on $TARGET/vk/vk" >&2; exit 1; }
    case "$CIRCUIT_DIR_NAME" in
      *-synthetic-anchors)
        # Named after the directory: the package name is the real circuit's,
        # and two files of one basename collide in forge's artifacts.
        SOL_FILE="$TARGET/$(pascal "$CIRCUIT_DIR_NAME").sol"
        cp "$WORK/fresh.sol" "$SOL_FILE"
        SOL_ORIGIN="generated now from $TARGET/vk/vk (test-anchor copy, no committed verifier)"
        ;;
      *)
        SOL_FILE="$PKG_SOL"
        if [ ! -f "$SOL_FILE" ]; then
            echo "Missing $SOL_FILE. Build the circuit first:  ./scripts/build.sh $CIRCUIT_DIR_NAME" >&2
            exit 1
        fi
        if ! cmp -s "$SOL_FILE" "$WORK/fresh.sol"; then
            echo "$SOL_FILE is not what bb $BB_VERSION writes from $TARGET/vk/vk." >&2
            echo "  The verifier is stale. Rebuild:  ./scripts/build.sh $CIRCUIT_DIR_NAME" >&2
            exit 1
        fi
        SOL_ORIGIN="committed, identical to bb $BB_VERSION's output for $TARGET/vk/vk"
        ;;
    esac

    PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    RPC_URL="http://127.0.0.1:$PORT"
    anvil --host 127.0.0.1 --port "$PORT" >"$WORK/anvil.log" 2>&1 &
    ANVIL_PID=$!
    for _ in $(seq 1 100); do
        cast chain-id --rpc-url "$RPC_URL" >/dev/null 2>&1 && break
        kill -0 "$ANVIL_PID" 2>/dev/null || { echo "anvil exited:" >&2; cat "$WORK/anvil.log" >&2; exit 1; }
        sleep 0.1
    done
    CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL")
    FROM=$(cast rpc --rpc-url "$RPC_URL" eth_accounts | python3 -c 'import json, sys; print(json.load(sys.stdin)[0])')
    HARDFORK=$(cast rpc --rpc-url "$RPC_URL" anvil_nodeInfo | python3 -c 'import json, sys; print(json.load(sys.stdin).get("hardFork", "unknown"))')

    local_deploy() {
        local out
        if ! out=$(forge create "$@" --rpc-url "$RPC_URL" --unlocked --from "$FROM" --broadcast --json 2>"$WORK/forge.err"); then
            echo "forge create $1 failed:" >&2
            cat "$WORK/forge.err" >&2
            printf '%s\n' "$out" >&2
            exit 1
        fi
        # --json output may be pretty-printed and follow compiler lines: take
        # the last object that parses and names deployedTo.
        printf '%s\n' "$out" | python3 -c '
import json, sys
text = sys.stdin.read()
for i in sorted((i for i, ch in enumerate(text) if ch == "{"), reverse=True):
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[i:])
    except ValueError:
        continue
    if isinstance(obj, dict) and "deployedTo" in obj:
        print(obj["deployedTo"]); sys.exit(0)
sys.exit("no deployedTo in forge create output:\n" + text)'
    }
    # The libraries to link are read from the source, not listed here: a
    # library with an external function is deployed on its own and linked.
    # bb 4.2 had one (ZKTranscriptLib); bb 6.0.0 added RelationsLib. Each run
    # deploys them from the same file as its verifier, because their code
    # changes with bb.
    LINKED_LIBS=$(verifier_linked_libraries "$SOL_FILE")
    LINK_FLAGS=()
    LIB_REPORT=""
    LIB_SIZES=""
    for lib in $LINKED_LIBS; do
        addr=$(local_deploy "$SOL_FILE:$lib")
        size=$(cast codesize "$addr" --rpc-url "$RPC_URL")
        [ "$size" -gt 0 ] || { echo "No code for $lib at $addr" >&2; exit 1; }
        LINK_FLAGS+=(--libraries "$SOL_FILE:$lib:$addr")
        LIB_REPORT="${LIB_REPORT:+$LIB_REPORT
          }$lib $addr ($size bytes runtime)"
        LIB_SIZES="${LIB_SIZES:+$LIB_SIZES,}$lib=$size"
        if [ "$size" -gt "$EIP170_LIMIT" ]; then OVER_LIMIT="$OVER_LIMIT $lib"; fi
    done
    VERIFIER=$(local_deploy "$SOL_FILE:HonkVerifier" "${LINK_FLAGS[@]}")
    VERIFIER_BYTES=$(cast codesize "$VERIFIER" --rpc-url "$RPC_URL")
    if [ "$VERIFIER_BYTES" -eq 0 ]; then
        echo "No code after deploying HonkVerifier." >&2
        exit 1
    fi
    if [ "$VERIFIER_BYTES" -gt "$EIP170_LIMIT" ]; then OVER_LIMIT="$OVER_LIMIT HonkVerifier"; fi

    echo "Circuit:  $CIRCUIT_DIR_NAME"
    echo "Network:  local anvil (chain $CHAIN_ID, hardfork $HARDFORK)"
    echo "Source:   $SOL_FILE -- $SOL_ORIGIN"
    echo "Verifier: $VERIFIER ($VERIFIER_BYTES bytes runtime, EIP-170 limit $EIP170_LIMIT)"
    echo "Linked:   ${LIB_REPORT:-none}"
    echo "Proof:    $PROOF_DIR"
    echo ""
else
    # Load the RPC URLs the way deploy_verifier.sh does, so the check runs from a
    # plain shell. Values already exported by the caller win.
    case "$NETWORK" in
      base-sepolia|sepolia|giwa-sepolia) ENV_FILE="$CIRCUITS_DIR/.env.development" ;;
      base|mainnet) ENV_FILE="$CIRCUITS_DIR/.env.production" ;;
      *) ENV_FILE="" ;;
    esac
    if [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
      while IFS='=' read -r name value; do
        case "$name" in
          *_RPC_URL) [ -z "${!name:-}" ] && [ -n "$value" ] && export "$name=${value%\"}" && export "$name=${!name#\"}" ;;
        esac
      done < <(grep -E '^[A-Z_]+_RPC_URL=' "$ENV_FILE")
    fi

    case "$NETWORK" in
      # GIWA was missing here, which is the whole reason a GIWA-only copy of this
      # check grew under scripts/giwa-poc/. One table, so the next circuit on a new
      # chain adds a line instead of a script.
      giwa-sepolia) RPC_URL="${GIWA_SEPOLIA_RPC_URL:-https://sepolia-rpc.giwa.io/}"; CHAIN_ID=91342 ;;
      base-sepolia) RPC_URL="${BASE_SEPOLIA_RPC_URL:-}"; CHAIN_ID=84532 ;;
      sepolia) RPC_URL="${SEPOLIA_RPC_URL:-}"; CHAIN_ID=11155111 ;;
      base) RPC_URL="${BASE_RPC_URL:-}"; CHAIN_ID=8453 ;;
      mainnet) RPC_URL="${MAINNET_RPC_URL:-}"; CHAIN_ID=1 ;;
      # A running anvil that `deploy_verifier.sh <pkg> anvil` deployed to; the
      # same ANVIL_RPC_URL and DEPLOY_OUTPUT_DIR (scripts/test-deploy-verifier.sh).
      anvil) RPC_URL="${ANVIL_RPC_URL:-}"; CHAIN_ID=31337 ;;
      *) echo "Unknown network '$NETWORK'. Known: giwa-sepolia, base-sepolia, sepolia, base, mainnet, anvil, local." >&2; exit 1 ;;
    esac

    if [ -z "$RPC_URL" ]; then
        echo "No RPC URL for $NETWORK. Set it in .env.development / .env.production (anvil: ANVIL_RPC_URL)." >&2
        exit 1
    fi

    # The deploy script's own record, not a hand-copied address.
    SCRIPT_NAME=$(echo "$CIRCUIT_DIR_NAME" | awk -F'[-/]' '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)} 1' OFS='')
    if [ "$NETWORK" = anvil ]; then
        if [ -z "${DEPLOY_OUTPUT_DIR:-}" ]; then
            echo "DEPLOY_OUTPUT_DIR must name the folder deploy_verifier.sh wrote for anvil." >&2
            exit 1
        fi
        BROADCAST="$DEPLOY_OUTPUT_DIR/broadcast/Deploy${SCRIPT_NAME}.s.sol/${CHAIN_ID}/run-latest.json"
        ANVIL_CHAIN=$(cast chain-id --rpc-url "$RPC_URL" 2>/dev/null || true)
        if [ "$ANVIL_CHAIN" != "$CHAIN_ID" ]; then
            echo "ANVIL_RPC_URL answers chain id '${ANVIL_CHAIN:-none}', not anvil's $CHAIN_ID." >&2
            exit 1
        fi
    else
        BROADCAST="broadcast/Deploy${SCRIPT_NAME}.s.sol/${CHAIN_ID}/run-latest.json"
    fi
    if [ "$NETWORK" = anvil ] && [ -n "${VERIFIER_ADDRESS:-}" ]; then
        # anvil only: a contract the test deployed itself (a -synthetic-anchors
        # twin linked to the libraries deploy_verifier.sh recorded), which has
        # no deploy script and so no broadcast. A real network always reads
        # the deploy record.
        BROADCAST=""
    elif [ ! -f "$BROADCAST" ]; then
        echo "No deployment record at $BROADCAST" >&2
        echo "  Deploy first:  ./scripts/deploy_verifier.sh $CIRCUIT_DIR_NAME $NETWORK" >&2
        exit 1
    fi
    if [ -z "$BROADCAST" ]; then
        VERIFIER="$VERIFIER_ADDRESS"
    else
    VERIFIER=$(python3 -c "
import json, sys
d = json.load(open('$BROADCAST'))
for t in d['transactions']:
    if t.get('transactionType') == 'CREATE' and t.get('contractName') == 'HonkVerifier':
        print(t['contractAddress']); sys.exit(0)
sys.exit('no HonkVerifier CREATE in $BROADCAST')
")
    fi

    echo "Circuit:  $CIRCUIT_DIR_NAME"
    echo "Network:  $NETWORK (chain $CHAIN_ID)"
    echo "Verifier: $VERIFIER"
    echo ""
fi

# Off-chain first. Reporting an on-chain result without it cannot tell a broken
# proof from a mismatched contract.
echo "1. Off-chain (bb verify)..."
if ! bb verify -p "$PROOF_DIR/proof" -i "$PROOF_DIR/public_inputs" \
               -k "$TARGET/vk/vk" -t evm >/dev/null 2>&1; then
    echo "   FAILED -- the proof itself does not verify. Nothing to ask the chain." >&2
    exit 1
fi
echo "   verified"
echo ""

# Modes: honest | input (first public input, lowest bit flipped) | proof (one
# proof byte flipped: the lowest byte of the middle 32-byte word, so the word
# stays a field element and the maths, not the parser, has to notice) | gas.
onchain_call() {
python3 - "$PROOF_DIR/proof" "$PROOF_DIR/public_inputs" "$VERIFIER" "$RPC_URL" "$1" <<'PY'
import json, sys, urllib.request

proof_path, inputs_path, verifier, rpc, mode = sys.argv[1:6]
proof = open(proof_path, 'rb').read()
raw_inputs = open(inputs_path, 'rb').read()
if mode == 'input':
    # Flip the lowest bit of the first public input; stays inside the field.
    raw_inputs = raw_inputs[:31] + bytes([raw_inputs[31] ^ 1]) + raw_inputs[32:]
elif mode.startswith('plusp:'):
    # Public input i written as value + p: the same Field, another number.
    i = int(mode.split(':')[1])
    p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    v = int.from_bytes(raw_inputs[32 * i:32 * i + 32], 'big') + p
    if v >= 1 << 256:
        sys.exit(f'public input {i} + p does not fit 256 bits')
    raw_inputs = raw_inputs[:32 * i] + v.to_bytes(32, 'big') + raw_inputs[32 * i + 32:]
elif mode == 'proof':
    at = (len(proof) // 32 // 2) * 32 + 31
    proof = proof[:at] + bytes([proof[at] ^ 1]) + proof[at + 1:]
    print(f'byte {at} of {len(proof)}', file=sys.stderr)
elif mode.startswith('field:'):
    # field:<byte offset>: the 32-byte word there, plus one, mod p.
    at = int(mode.split(':')[1])
    p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    v = (int.from_bytes(proof[at:at + 32], 'big') + 1) % p
    proof = proof[:at] + v.to_bytes(32, 'big') + proof[at + 32:]
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

method, params = (
    ('eth_estimateGas', [{'to': verifier, 'data': data}])
    if mode == 'gas' else
    ('eth_call', [{'to': verifier, 'data': data}, 'latest'])
)
req = urllib.request.Request(
    rpc,
    data=json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params,
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
if mode == 'gas':
    print(int(value, 16))
else:
    print('TRUE' if int(value, 16) == 1 else 'FALSE ' + value)
PY
}

echo "2. On-chain (eth_call to the verifier)..."
RESULT=$(onchain_call honest)
if [ "$RESULT" != TRUE ]; then
    echo "   FAILED -- $RESULT" >&2
    echo "" >&2
    echo "The proof verifies locally but the contract rejects it." >&2
    echo "That is a MISMATCH, not a bad proof. Usual causes:" >&2
    echo "  - the contract was deployed from a .sol built by a different bb" >&2
    echo "  - the public-input count differs from what the circuit emits" >&2
    echo "  - the deployment predates the current circuit" >&2
    exit 1
fi
echo "   accepted: the contract returned true"
echo ""

echo "3. On-chain, first public input changed by one bit..."
TAMPERED=$(onchain_call input)
if [ "$TAMPERED" = TRUE ]; then
    echo "   FAILED -- the contract accepted a changed public input" >&2
    exit 1
fi
echo "   rejected: $TAMPERED"
echo ""

echo "4. On-chain, one proof byte changed..."
TAMPERED_PROOF=$(onchain_call proof 2>"$WORK/proof-flip" || true)
FLIP_AT=$(cat "$WORK/proof-flip")
if [ "$TAMPERED_PROOF" = TRUE ] || [ -z "$TAMPERED_PROOF" ]; then
    echo "   FAILED -- the contract accepted a changed proof (${TAMPERED_PROOF:-no answer})" >&2
    exit 1
fi
echo "   rejected (${FLIP_AT}): $TAMPERED_PROOF"
echo ""

if [ -n "${TAMPER_FIELDS:-}" ]; then
    # The verifier source whose constants give the layout: the one deployed
    # here (local), else the package's committed verifier.
    if [ -z "${SOL_FILE:-}" ]; then
        CIRCUIT_NAME=$(grep -m1 '^name' "$CIRCUIT_DIR_NAME/Nargo.toml" | sed 's/.*= *"\(.*\)"/\1/')
        SOL_FILE="$TARGET/$(pascal "$CIRCUIT_NAME").sol"
    fi
    [ -f "$SOL_FILE" ] || { echo "TAMPER_FIELDS: no verifier source $SOL_FILE to read the proof layout from" >&2; exit 1; }
    FIELD_OFFSETS=$(python3 - "$SOL_FILE" "$PROOF_DIR/proof" "$TAMPER_FIELDS" <<'PY'
import re, sys
sol_path, proof_path, wanted = sys.argv[1:4]
sol = open(sol_path).read()
def const(name):
    m = re.search(r'^uint256 constant ' + name + r' = (\d+);', sol, re.M)
    if not m:
        sys.exit(f'{sol_path} has no "uint256 constant {name} = <n>;" -- not a layout this check knows')
    return int(m.group(1))
if 'libraEvaluation' not in sol or 'struct ZKProof' not in sol:
    sys.exit(f'{sol_path} is not a ZK (Libra) verifier; TAMPER_FIELDS knows only that layout')
log_n = const('LOG_N')
entities = const('NUMBER_OF_ENTITIES') + const('NUM_MASKING_POLYNOMIALS')
pairing = const('PAIRING_POINTS_SIZE')
partial = const('ZK_BATCHED_RELATION_PARTIAL_LENGTH')
F, G = 32, 64
# The order the verifier's loadProof reads a ZK proof.
at = pairing * F + 10 * G          # pairing points; masking poly, w1-w3, read counts/tags, w4, inverses, zPerm, libra[0]
lib_sum = at; at += F
univ = at; at += log_n * partial * F
evals = at; at += entities * F
lib_eval = at; at += F
at += 2 * G                        # libra[1], libra[2]
at += (log_n - 1) * G              # gemini fold commitments
gemini_a = at; at += log_n * F
lib_poly = at; at += 4 * F
at += 2 * G                        # shplonk Q, KZG quotient
size = len(open(proof_path, 'rb').read())
if at != size:
    sys.exit(f'layout from {sol_path} gives a {at}-byte proof; {proof_path} is {size} bytes. Not tampering by guessed offsets.')
if wanted == 'default':
    wanted = 'libraEvaluation,libraSum,sumcheckUnivariate:0:0,libraPolyEval:0,libraPolyEval:1,libraPolyEval:2,libraPolyEval:3'
def bounded(i, n, what):
    if not 0 <= i < n:
        sys.exit(f'{what} index {i} out of range (0..{n - 1})')
    return i
for name in wanted.split(','):
    parts = name.strip().split(':')
    kind = parts[0]
    try:
        idx = [int(x) for x in parts[1:]]
    except ValueError:
        sys.exit(f'bad field {name!r}')
    if kind == 'libraSum' and not idx: off = lib_sum
    elif kind == 'libraEvaluation' and not idx: off = lib_eval
    elif kind == 'sumcheckUnivariate' and len(idx) == 2:
        off = univ + (bounded(idx[0], log_n, 'round') * partial + bounded(idx[1], partial, 'univariate')) * F
    elif kind == 'sumcheckEvaluation' and len(idx) == 1: off = evals + bounded(idx[0], entities, 'evaluation') * F
    elif kind == 'geminiAEvaluation' and len(idx) == 1: off = gemini_a + bounded(idx[0], log_n, 'gemini') * F
    elif kind == 'libraPolyEval' and len(idx) == 1: off = lib_poly + bounded(idx[0], 4, 'libraPolyEval') * F
    else:
        sys.exit(f'unknown field {name!r}. Known: libraSum, libraEvaluation, sumcheckUnivariate:<r>:<i>, sumcheckEvaluation:<i>, geminiAEvaluation:<i>, libraPolyEval:<i>, default')
    print(f'{name.strip()} {off}')
PY
) || exit 1
    echo "4c. On-chain, one named proof field changed (value + 1 mod p) each:"
    while read -r FIELD OFFSET; do
        [ -n "$FIELD" ] || continue
        FIELD_RESULT=$(onchain_call "field:$OFFSET")
        if [ "$FIELD_RESULT" = TRUE ] || [ -z "$FIELD_RESULT" ]; then
            echo "   FAILED -- the contract accepted the proof with $FIELD (byte $OFFSET) changed (${FIELD_RESULT:-no answer})" >&2
            exit 1
        fi
        echo "   rejected $FIELD (byte $OFFSET): $FIELD_RESULT"
    done <<< "$FIELD_OFFSETS"
    echo ""
fi

if [ -n "${INPUT_PLUS_P_INDEX:-}" ]; then
    PLUS_P=$(onchain_call "plusp:$INPUT_PLUS_P_INDEX")
    case "$PLUS_P" in
      TRUE) echo "4b. Public input $INPUT_PLUS_P_INDEX written as value + p: ACCEPTED (the contract reduces it mod p)" ;;
      *)    echo "4b. Public input $INPUT_PLUS_P_INDEX written as value + p: refused ($PLUS_P)" ;;
    esac
    echo ""
fi

if [ "$NETWORK" = local ]; then
    GAS=$(onchain_call gas)
    case "$GAS" in REVERT*) echo "eth_estimateGas failed: $GAS" >&2; exit 1 ;; esac
    echo "5. Gas (eth_estimateGas, honest call as a transaction): $GAS"
    echo "   Runtime size: HonkVerifier $VERIFIER_BYTES; ${LIB_SIZES:-no linked libraries} (limit $EIP170_LIMIT): ${OVER_LIMIT:+OVER:}${OVER_LIMIT:-within}"
    echo ""
    echo "SUMMARY circuit=$CIRCUIT_DIR_NAME proof=$PROOF_DIR accepts=yes rejects_input=yes rejects_proof=yes gas=$GAS verifier_bytes=$VERIFIER_BYTES libs=$LIB_SIZES hardfork=$HARDFORK"
    [ -z "$OVER_LIMIT" ] || exit 1
fi

echo "=================================================="
echo " Verified off-chain AND on-chain: $CIRCUIT_DIR_NAME on $NETWORK"
echo "=================================================="
