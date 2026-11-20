# Helpers for the libraries a generated HonkVerifier links. Source it; do not
# run it.
#
#   . "$CIRCUITS_DIR/scripts/lib/verifier-libraries.sh"
#
# A Solidity library with an external or public function is deployed on its
# own and linked into the verifier's bytecode by address. bb 4.2 verifiers
# had one (ZKTranscriptLib); bb 6.0.0 verifiers have two (ZKTranscriptLib,
# whose code changed, and RelationsLib). Which libraries a verifier needs is
# read from its source, never listed by hand, because it changes with bb.
#
# A library is identified by its CODE HASH, not its name: the name stayed the
# same across bb versions while the code did not, and a verifier linked to a
# library of another bb answers wrong (or reverts) instead of failing to
# deploy. The hash is keccak256 of the runtime code with
#   - the 20 bytes after the leading PUSH20 zeroed: Solidity writes the
#     library's own address there at deploy time (the call guard), and
#   - the trailing CBOR metadata removed: it hashes the whole source file,
#     and every circuit's verifier file differs (its key), so the same
#     library compiled from two circuits' files would otherwise differ.
# The same function is applied to the compiled artifact and to the code on
# chain, so an address can be checked against the hash it is recorded under.

# Library names with an external/public function, one per line, sorted.
verifier_linked_libraries() {
    awk '/^library /{lib=$2} /^(abstract )?contract |^interface /{lib=""} lib && /\) *(external|public)/ {print lib}' "$1" | sort -u
}

# Normalised code hash of a hex runtime code string (0x-prefixed or not).
# Prints nothing and fails on empty code.
library_code_hash() {
    local normalised
    normalised=$(python3 -c '
import sys
code = sys.argv[1].lower().removeprefix("0x")
if not code:
    sys.exit("empty code")
raw = bytes.fromhex(code)
if raw[0] == 0x73 and len(raw) > 21:
    raw = raw[:1] + bytes(20) + raw[21:]
if len(raw) >= 2:
    meta = int.from_bytes(raw[-2:], "big")
    if meta + 2 <= len(raw) and raw[len(raw) - meta - 2] in (0xa1, 0xa2, 0xa3):
        raw = raw[:len(raw) - meta - 2]
print("0x" + raw.hex())
' "$1") || return 1
    cast keccak "$normalised"
}

# Normalised code hash of a compiled library: out/<File>.sol/<Lib>.json.
library_artifact_hash() {
    local artifact="$1" code
    code=$(python3 -c '
import json, sys
a = json.load(open(sys.argv[1]))
obj = a["deployedBytecode"]["object"]
if "__$" in obj:
    sys.exit(sys.argv[1] + " links another library; not supported")
print(obj)
' "$artifact") || return 1
    library_code_hash "$code"
}

# Normalised code hash of whatever is deployed at an address. Fails on no code.
library_onchain_hash() {
    local address="$1" rpc="$2" code
    code=$(cast code "$address" --rpc-url "$rpc") || return 1
    if [ -z "$code" ] || [ "$code" = "0x" ]; then
        return 1
    fi
    library_code_hash "$code"
}
