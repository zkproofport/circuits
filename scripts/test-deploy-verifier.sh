#!/usr/bin/env bash
#
# Runs scripts/deploy_verifier.sh end to end against a throwaway anvil chain
# and checks what it deployed with scripts/verify-onchain.sh:
#
#   ./scripts/test-deploy-verifier.sh
#
# Nothing leaves this machine: anvil runs on a free local port and is killed
# on exit, the deploy key is the one anvil prints for its own first account,
# and every record and broadcast goes to a temporary folder (DEPLOY_OUTPUT_DIR),
# never into deployments/ or broadcast/.
#
# Cases:
#   1. A chain that already has the bb 4.2 ZKTranscriptLib and its record
#      deployments/<chain>/ZKTranscriptLib.json, as every real network does.
#      Deploying coinbase-attestation must deploy BOTH bb 6.0.0 libraries
#      anew, record them under their code hashes, link them (never the bb 4.2
#      address), record the verifier with both, and leave the bb 4.2 record
#      byte for byte as it was.
#   2. verify-onchain.sh accepts the honest proof on that verifier and rejects
#      a changed public input and a changed proof byte.
#   3. Deploying oidc-domain-attestation and human-passport-score reuses both
#      recorded libraries (no library transaction) and links the same
#      addresses; human-passport-score is checked with its real proof.
#   4. The OIDC circuit pins real anchors, and every OIDC proof that exists
#      without a real signing key is for its -synthetic-anchors twin. So: the
#      deployed real OIDC verifier must REFUSE the twin's proof, and the twin's
#      verifier, linked to the libraries deploy_verifier.sh recorded, must pass
#      all of verify-onchain.sh's checks with it.
#   5. Stale library (the guard): a record filed under the bb 6.0.0
#      ZKTranscriptLib hash that names the bb 4.2 library's address. The
#      deploy must fail before any verifier is sent, naming the hash it
#      expected and the hash it found. Also: a record whose address holds no
#      code, and a record whose codeHash field disagrees with its file name.
#
# Needs: anvil, cast and forge (foundry), the circuits built (target/*.sol,
# target/vk, target/proof for coinbase-attestation and human-passport-score),
# and the OIDC synthetic-anchors twin built with its acceptance proofs
# (oidc-domain-attestation/scripts/post-build.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"
cd "$CIRCUITS_DIR"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/verifier-libraries.sh"
# bb from the versioned folder toolchain.env pins (never PATH).
# shellcheck disable=SC1091
. "$SCRIPT_DIR/lib/toolchain.sh"

# The last commit whose coinbase-attestation verifier came from bb 4.2
# (nargo beta.19): the source of the "old" library this test plants.
BB42_REF=35a8df456b4b01622235a05cc6fc66f00a7543f2
OIDC_TWIN=oidc-domain-attestation-synthetic-anchors
OIDC_TWIN_PROOF=$OIDC_TWIN/test-vectors/proof_google_bound

PASS=0
FAIL=0
ok() { echo "  PASS  $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }

WORK=$(mktemp -d)
ANVIL_PID=""
cleanup() {
    if [ -n "$ANVIL_PID" ]; then kill "$ANVIL_PID" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

for f in coinbase-attestation/target/CoinbaseAttestation.sol coinbase-attestation/target/proof/proof \
         oidc-domain-attestation/target/OidcDomainAttestation.sol \
         human-passport-score/target/HumanPassportScore.sol human-passport-score/target/proof/proof \
         "$OIDC_TWIN/target/vk/vk" "$OIDC_TWIN_PROOF/proof"; do
    [ -f "$f" ] || { echo "Missing $f; build the circuits first (see this script's header)." >&2; exit 1; }
done

PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
export ANVIL_RPC_URL="http://127.0.0.1:$PORT"
anvil --host 127.0.0.1 --port "$PORT" > "$WORK/anvil.log" 2>&1 &
ANVIL_PID=$!
for _ in $(seq 1 100); do
    cast chain-id --rpc-url "$ANVIL_RPC_URL" > /dev/null 2>&1 && break
    kill -0 "$ANVIL_PID" 2>/dev/null || { echo "anvil exited:" >&2; cat "$WORK/anvil.log" >&2; exit 1; }
    sleep 0.1
done
# anvil's own first account, read from what anvil printed: a development key
# that holds nothing anywhere else.
PRIVATE_KEY=$(python3 -c '
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r"Private Keys.*?\(0\) (0x[0-9a-fA-F]{64})", text, re.S)
sys.exit("no private key in the anvil output") if not m else print(m.group(1))
' "$WORK/anvil.log") || exit 1
export PRIVATE_KEY
FROM=$(cast wallet address --private-key "$PRIVATE_KEY")
CHAIN=$(cast chain-id --rpc-url "$ANVIL_RPC_URL")
echo "anvil on $ANVIL_RPC_URL (chain $CHAIN), deployer $FROM"

# The bb 4.2 ZKTranscriptLib, compiled with this repository's compiler
# settings in a project of its own and deployed with anvil's unlocked account.
LEGACY="$WORK/legacy"
mkdir -p "$LEGACY/src"
git show "$BB42_REF:coinbase-attestation/target/CoinbaseAttestation.sol" > "$LEGACY/src/Bb42Verifier.sol"
cat > "$LEGACY/foundry.toml" <<'TOML'
[profile.default]
src = "src"
out = "out"
solc = "0.8.28"
optimizer = true
optimizer_runs = 1
TOML
if ! forge build --root "$LEGACY" > "$WORK/legacy-build.log" 2>&1; then
    cat "$WORK/legacy-build.log" >&2; exit 1
fi
BB42_LIB=$(forge create --root "$LEGACY" "src/Bb42Verifier.sol:ZKTranscriptLib" \
    --rpc-url "$ANVIL_RPC_URL" --unlocked --from "$FROM" --broadcast --json 2> "$WORK/legacy-create.err" \
    | python3 -c '
import json, sys
text = sys.stdin.read()
for i in sorted((i for i, ch in enumerate(text) if ch == "{"), reverse=True):
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[i:])
    except ValueError:
        continue
    if isinstance(obj, dict) and "deployedTo" in obj:
        print(obj["deployedTo"]); sys.exit(0)
sys.exit("no deployedTo")') || { cat "$WORK/legacy-create.err" >&2; exit 1; }
BB42_HASH=$(library_onchain_hash "$BB42_LIB" "$ANVIL_RPC_URL")
BB6_TRANSCRIPT_HASH=$(library_artifact_hash out/CoinbaseAttestation.sol/ZKTranscriptLib.json 2>/dev/null || true)
echo "bb 4.2 ZKTranscriptLib (from $BB42_REF) at $BB42_LIB, code hash $BB42_HASH"
echo ""

# deploy_verifier.sh <pkg> into output folder <dir>; output in <log>.
deploy() {
    DEPLOY_OUTPUT_DIR="$2" "$SCRIPT_DIR/deploy_verifier.sh" "$1" anvil > "$3" 2>&1
}
rec() { python3 -c 'import json, sys; d = json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {"d": d}))' "$1" "$2"; }

OUT="$WORK/out"
DEP="$OUT/deployments/$CHAIN"
mkdir -p "$DEP"
python3 -c '
import json, sys
json.dump({"address": sys.argv[1], "network": "anvil", "chainId": int(sys.argv[2]), "contract": "ZKTranscriptLib"},
          open(sys.argv[3], "w"), indent=2)
' "$BB42_LIB" "$CHAIN" "$DEP/ZKTranscriptLib.json"
cp "$DEP/ZKTranscriptLib.json" "$WORK/legacy-record.json"

echo "1. coinbase-attestation on a chain that has the bb 4.2 library and record"
if deploy coinbase-attestation "$OUT" "$WORK/d1.log"; then
    ok "deploy_verifier.sh coinbase-attestation anvil exited 0"
else
    bad "deploy_verifier.sh coinbase-attestation anvil exited non-zero"; cat "$WORK/d1.log"
fi
if [ -z "$BB6_TRANSCRIPT_HASH" ]; then
    BB6_TRANSCRIPT_HASH=$(library_artifact_hash out/CoinbaseAttestation.sol/ZKTranscriptLib.json)
fi
BB6_RELATIONS_HASH=$(library_artifact_hash out/CoinbaseAttestation.sol/RelationsLib.json)
if [ "$BB6_TRANSCRIPT_HASH" != "$BB42_HASH" ]; then
    ok "bb 6.0.0 ZKTranscriptLib hash $BB6_TRANSCRIPT_HASH differs from bb 4.2's"
else
    bad "bb 6.0.0 and bb 4.2 ZKTranscriptLib hash the same ($BB42_HASH); the test plants nothing stale"
fi
VREC="$DEP/CoinbaseAttestation.json"
TREC="$DEP/libraries/ZKTranscriptLib/$BB6_TRANSCRIPT_HASH.json"
RREC="$DEP/libraries/RelationsLib/$BB6_RELATIONS_HASH.json"
if [ -f "$TREC" ] && [ -f "$RREC" ] && [ -f "$VREC" ]; then
    ok "records written: libraries/ZKTranscriptLib/<hash>, libraries/RelationsLib/<hash>, CoinbaseAttestation.json"
    T_ADDR=$(rec "$TREC" 'd["address"]')
    R_ADDR=$(rec "$RREC" 'd["address"]')
    [ "$(rec "$VREC" 'd["libraries"]["ZKTranscriptLib"]["address"]')" = "$T_ADDR" ] \
        && [ "$(rec "$VREC" 'd["libraries"]["RelationsLib"]["address"]')" = "$R_ADDR" ] \
        && ok "verifier record links ZKTranscriptLib $T_ADDR and RelationsLib $R_ADDR" \
        || bad "verifier record names other library addresses than the library records"
    lc() { echo "$1" | tr '[:upper:]' '[:lower:]'; }
    [ "$(lc "$T_ADDR")" != "$(lc "$BB42_LIB")" ] && ok "the bb 4.2 library address was not linked" \
        || bad "the bb 4.2 library address was linked"
    [ "$(library_onchain_hash "$T_ADDR" "$ANVIL_RPC_URL")" = "$BB6_TRANSCRIPT_HASH" ] \
        && [ "$(library_onchain_hash "$R_ADDR" "$ANVIL_RPC_URL")" = "$BB6_RELATIONS_HASH" ] \
        && ok "code at both library addresses hashes to the recorded hashes" \
        || bad "code at a recorded library address does not match its hash"
    VCODE=$(lc "$(cast code "$(rec "$VREC" 'd["address"]')" --rpc-url "$ANVIL_RPC_URL")")
    [[ "$VCODE" == *"$(lc "${T_ADDR#0x}")"* && "$VCODE" == *"$(lc "${R_ADDR#0x}")"* && "$VCODE" != *"$(lc "${BB42_LIB#0x}")"* ]] \
        && ok "verifier code calls both bb 6.0.0 libraries and not the bb 4.2 one" \
        || bad "verifier code does not reference exactly the recorded libraries"
else
    bad "missing records under $DEP"; find "$OUT" -type f | sed 's/^/        /'
    T_ADDR=""; R_ADDR=""
fi
cmp -s "$DEP/ZKTranscriptLib.json" "$WORK/legacy-record.json" \
    && ok "bb 4.2 record ZKTranscriptLib.json unchanged" || bad "bb 4.2 record ZKTranscriptLib.json changed"
echo ""

echo "2. verify-onchain.sh coinbase-attestation anvil"
if DEPLOY_OUTPUT_DIR="$OUT" "$SCRIPT_DIR/verify-onchain.sh" coinbase-attestation anvil > "$WORK/v1.log" 2>&1; then
    ok "honest proof accepted, changed input and changed proof rejected"
    grep -E "rejected" "$WORK/v1.log" | sed 's/^/        /'
else
    bad "verify-onchain.sh coinbase-attestation anvil"; cat "$WORK/v1.log"
fi
echo ""

echo "3. oidc-domain-attestation and human-passport-score reuse the recorded libraries"
for pkg in oidc-domain-attestation human-passport-score; do
    case $pkg in
        oidc-domain-attestation) NAME=OidcDomainAttestation ;;
        human-passport-score) NAME=HumanPassportScore ;;
        *) echo "no record name for $pkg" >&2; exit 1 ;;
    esac
    before=$(cast nonce "$FROM" --rpc-url "$ANVIL_RPC_URL")
    if deploy "$pkg" "$OUT" "$WORK/d-$pkg.log"; then
        ok "deploy_verifier.sh $pkg anvil exited 0"
    else
        bad "deploy_verifier.sh $pkg anvil exited non-zero"; cat "$WORK/d-$pkg.log"; continue
    fi
    after=$(cast nonce "$FROM" --rpc-url "$ANVIL_RPC_URL")
    [ $((after - before)) -eq 1 ] && ok "$pkg: one transaction (the verifier), no library deployed" \
        || bad "$pkg: $((after - before)) transactions, expected 1"
    [ "$(grep -c "reusing" "$WORK/d-$pkg.log")" -eq 2 ] && ok "$pkg: both libraries reused" \
        || bad "$pkg: expected two 'reusing' lines"
    [ "$(rec "$DEP/$NAME.json" 'd["libraries"]["ZKTranscriptLib"]["address"]')" = "$T_ADDR" ] \
        && [ "$(rec "$DEP/$NAME.json" 'd["libraries"]["RelationsLib"]["address"]')" = "$R_ADDR" ] \
        && ok "$pkg: record links the same two libraries" || bad "$pkg: record links other libraries"
done
if DEPLOY_OUTPUT_DIR="$OUT" "$SCRIPT_DIR/verify-onchain.sh" human-passport-score anvil > "$WORK/v-hp.log" 2>&1; then
    ok "verify-onchain.sh human-passport-score anvil: accepted honest, rejected both changes"
else
    bad "verify-onchain.sh human-passport-score anvil"; cat "$WORK/v-hp.log"
fi
echo ""

echo "4. OIDC: real verifier refuses the twin's proof; twin verifier on the recorded libraries accepts it"
# verify-onchain.sh would stop at its off-chain step (the twin proof is not a
# proof for the real key), so the contract is asked directly.
REAL_OIDC=$(rec "$DEP/OidcDomainAttestation.json" 'd["address"]')
INPUTS=$(python3 -c '
import sys
raw = open(sys.argv[1], "rb").read()
print("[" + ",".join("0x" + raw[i:i + 32].hex() for i in range(0, len(raw), 32)) + "]")
' "$OIDC_TWIN_PROOF/public_inputs")
PROOF_HEX=0x$(xxd -p "$OIDC_TWIN_PROOF/proof" | tr -d '\n')
REAL_ANSWER=$(cast call "$REAL_OIDC" "verify(bytes,bytes32[])(bool)" "$PROOF_HEX" "$INPUTS" --rpc-url "$ANVIL_RPC_URL" 2>&1)
if [ "$REAL_ANSWER" != true ]; then
    ok "deployed OidcDomainAttestation $REAL_OIDC does not accept the synthetic-anchors proof: $(echo "$REAL_ANSWER" | tail -1)"
else
    bad "the real OIDC verifier accepted a synthetic-anchors proof"
fi
TWIN_SOL="$OIDC_TWIN/target/OidcDomainAttestationSyntheticAnchors.sol"
TWIN_DIR="$WORK/twin"
mkdir -p "$TWIN_DIR/src"
bb write_solidity_verifier -k "$OIDC_TWIN/target/vk/vk" -o "$TWIN_DIR/src/Twin.sol" -t evm > /dev/null 2>&1 \
    || { bad "bb write_solidity_verifier on the twin vk"; }
cp "$LEGACY/foundry.toml" "$TWIN_DIR/foundry.toml"
TWIN_T_HASH=""
if forge build --root "$TWIN_DIR" > "$WORK/twin-build.log" 2>&1; then
    TWIN_T_HASH=$(library_artifact_hash "$TWIN_DIR/out/Twin.sol/ZKTranscriptLib.json")
    TWIN_R_HASH=$(library_artifact_hash "$TWIN_DIR/out/Twin.sol/RelationsLib.json")
fi
if [ "$TWIN_T_HASH" = "$BB6_TRANSCRIPT_HASH" ] && [ "${TWIN_R_HASH:-}" = "$BB6_RELATIONS_HASH" ]; then
    ok "twin's libraries hash to the recorded hashes"
    TWIN=$(forge create --root "$TWIN_DIR" "src/Twin.sol:HonkVerifier" \
        --libraries "src/Twin.sol:ZKTranscriptLib:$T_ADDR" --libraries "src/Twin.sol:RelationsLib:$R_ADDR" \
        --rpc-url "$ANVIL_RPC_URL" --unlocked --from "$FROM" --broadcast --json 2> "$WORK/twin-create.err" \
        | python3 -c '
import json, sys
text = sys.stdin.read()
for i in sorted((i for i, ch in enumerate(text) if ch == "{"), reverse=True):
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[i:])
    except ValueError:
        continue
    if isinstance(obj, dict) and "deployedTo" in obj:
        print(obj["deployedTo"]); sys.exit(0)
sys.exit("no deployedTo")')
    if [ -n "$TWIN" ] && VERIFIER_ADDRESS="$TWIN" DEPLOY_OUTPUT_DIR="$OUT" \
        "$SCRIPT_DIR/verify-onchain.sh" "$OIDC_TWIN" anvil "$OIDC_TWIN_PROOF" > "$WORK/v-twin.log" 2>&1; then
        ok "twin verifier $TWIN on the recorded libraries: accepted honest, rejected both changes"
    else
        bad "twin verifier check"; cat "$WORK/twin-create.err" "$WORK/v-twin.log" 2>/dev/null
    fi
else
    bad "twin's library hashes differ from the recorded ones (or it did not build)"; cat "$WORK/twin-build.log"
fi
echo ""

echo "5. Stale library records are refused"
stale_case() {
    local label="$1" dir="$2" expect="$3"
    local before after
    before=$(cast nonce "$FROM" --rpc-url "$ANVIL_RPC_URL")
    if deploy coinbase-attestation "$dir" "$WORK/stale.log"; then
        bad "$label: deploy succeeded"; cat "$WORK/stale.log"; return
    fi
    after=$(cast nonce "$FROM" --rpc-url "$ANVIL_RPC_URL")
    local missing=""
    for want in $expect; do grep -qF -- "$want" "$WORK/stale.log" || missing="$missing $want"; done
    if [ -z "$missing" ] && [ "$after" -eq "$before" ] && [ ! -f "$dir/deployments/$CHAIN/CoinbaseAttestation.json" ]; then
        ok "$label: refused, nothing sent, no verifier recorded"
        grep -m1 "Error:" "$WORK/stale.log" | sed 's/\x1b\[[0-9;]*m//g; s/^/        /'
    else
        bad "$label: missing [$missing ], nonce $before -> $after"; cat "$WORK/stale.log"
    fi
}
plant() {
    local dir="$1" address="$2" code_hash="$3"
    mkdir -p "$dir/deployments/$CHAIN/libraries/ZKTranscriptLib"
    python3 -c '
import json, sys
json.dump({"address": sys.argv[1], "network": "anvil", "chainId": int(sys.argv[2]),
           "contract": "ZKTranscriptLib", "codeHash": sys.argv[3]}, open(sys.argv[4], "w"), indent=2)
' "$address" "$CHAIN" "$code_hash" "$dir/deployments/$CHAIN/libraries/ZKTranscriptLib/$BB6_TRANSCRIPT_HASH.json"
}
plant "$WORK/stale-a" "$BB42_LIB" "$BB6_TRANSCRIPT_HASH"
stale_case "bb 4.2 library filed under the bb 6.0.0 hash" "$WORK/stale-a" \
    "$BB6_TRANSCRIPT_HASH $BB42_HASH $BB42_LIB"
plant "$WORK/stale-b" "0x000000000000000000000000000000000000dEaD" "$BB6_TRANSCRIPT_HASH"
stale_case "record naming an address with no code" "$WORK/stale-b" \
    "no code at 0x000000000000000000000000000000000000dEaD $BB6_TRANSCRIPT_HASH"
plant "$WORK/stale-c" "$T_ADDR" "$BB42_HASH"
stale_case "record whose codeHash disagrees with its file name" "$WORK/stale-c" \
    "$BB6_TRANSCRIPT_HASH $BB42_HASH"
echo ""

echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
