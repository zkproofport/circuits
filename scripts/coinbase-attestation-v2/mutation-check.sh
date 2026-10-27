#!/bin/bash
# Prove that a refusal in the acceptance run is caused by the code it names.
#
#   scripts/coinbase-attestation-v2/mutation-check.sh [fixture-regex]
#
# With a regex, only cases whose fixture name matches run (each case compiles
# the whole 2^20 circuit).
#
# For each case below: copy the synthetic-anchors circuit (and the App Attest
# library) to sibling directories, apply ONE mutation, and run the named
# refusal fixture. The mutant must ACCEPT it -- otherwise something else was
# doing the refusing and the acceptance case proves nothing about that code.
#   delete~<assert message>~<fixture>     delete the one line carrying the message
#                                         (single-line asserts only)
#   replace~<exact text>~<new text>~<fixture>  replace text occurring exactly once
# The separator is `~` because the texts contain Noir's `|` (boolean or). With
# `|` as the separator, five cases split in the wrong places and compiled
# broken mutants that "still refused" for the wrong reason (found 2026-10-28).
# The originals are never edited; the copies are removed on exit.
#
# Needs the synthetic-anchors copy and its fixtures
# (scripts/coinbase-attestation-v2/make-fixtures.sh).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(cd "$SCRIPT_DIR/../.." && pwd)"
SYN="$CIRCUITS/coinbase-attestation-v2-synthetic-anchors"
# Siblings, so ../deps and ../coinbase-libs still resolve.
MUTANT="$CIRCUITS/coinbase-attestation-v2-mutant"
MUTANT_LIB="$CIRCUITS/app-attest-libs-mutant"

CASES=(
  # The statement (client_data.nr)
  "delete~clientData wallet is not the proven wallet~client_wallet_mismatch"
  "delete~clientData says the attestation is revoked~client_revoked"
  "delete~clientData does not bind this request~client_other_request"
  "delete~clientData does not bind this scope~client_other_scope"
  "delete~clientData timestamp is not the public timestamp~timestamp_changed"
  "delete~clientData names another EAS schema~client_other_schema"
  # The signer kind (main.nr)
  # Multi-line asserts are neutralised by replacing their condition: deleting
  # only the message line would leave a message-less assert that still refuses.
  "replace~        (signer_kind == KIND_APP) | (signer_kind == KIND_SERVER),~        true,~kind_unknown"
  "replace~        (signer_kind == KIND_APP) | (signer_kind == KIND_SERVER),~        true,~kind_zero"
  "replace~    if signer_kind == KIND_APP {~    if false {~app_chain_with_server_signature"
  "replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~server_other_key"
  "replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~assertion_other_key"
  # Apple's chain under the pinned CA (app-attest-libs). The root -> intermediate
  # link is not in this circuit (CA 1 is pinned); its checks are the
  # library's unit tests.
  "replace~        verify_credential_signature(~        true | verify_credential_signature(~cert_other_ca"
  "delete~App Attest environment does not match~env_development"
  "delete~Assertion is not for this app~assertion_wrong_rpid"
  "delete~Assertion counter is zero~assertion_counter_zero"
)

[ -f "$SYN/test-vectors/client_revoked.toml" ] || { echo "fixtures missing: run scripts/coinbase-attestation-v2/make-fixtures.sh" >&2; exit 1; }
for d in "$MUTANT" "$MUTANT_LIB"; do
  [ ! -e "$d" ] || { echo "$d exists; remove it (a previous run was interrupted)" >&2; exit 1; }
done
trap 'rm -rf "$MUTANT" "$MUTANT_LIB"' EXIT

PASSED=0
FAILED=0
ONLY="${1:-}"
for c in "${CASES[@]}"; do
  IFS='~' read -r kind a b d <<< "$c"
  if [ "$kind" = delete ]; then msg="$a"; vector="$b"; label="without \"$msg\""
  else from="$a"; to="$b"; vector="$d"; label="with \"$(echo "$from" | sed 's/^ *//')\" -> \"$(echo "$to" | sed 's/^ *//')\""; fi
  if [ -n "$ONLY" ] && ! echo "$vector" | grep -Eq "$ONLY"; then continue; fi
  rm -rf "$MUTANT" "$MUTANT_LIB"
  mkdir -p "$MUTANT" "$MUTANT_LIB"
  cp -R "$SYN/Nargo.toml" "$SYN/src" "$SYN/test-vectors" "$MUTANT/"
  cp -R "$CIRCUITS/app-attest-libs/Nargo.toml" "$CIRCUITS/app-attest-libs/src" "$MUTANT_LIB/"
  sed -i.bak 's#"../app-attest-libs"#"../app-attest-libs-mutant"#' "$MUTANT/Nargo.toml"
  grep -q 'app-attest-libs-mutant' "$MUTANT/Nargo.toml" || { echo "could not point the mutant at its library copy" >&2; exit 1; }

  if [ "$kind" = delete ]; then
    # Exactly one line may carry the message, and exactly one line must go.
    count=$(grep -rcF "\"$msg\"" "$MUTANT/src" "$MUTANT_LIB/src" | awk -F: '{s+=$2} END {print s}')
    if [ "$count" != 1 ]; then
      echo "  FAILED   $msg: found on $count lines, need exactly 1"; FAILED=$((FAILED + 1)); continue
    fi
    hits=$(grep -rlF "\"$msg\"" "$MUTANT/src" "$MUTANT_LIB/src")
    before=$(wc -l < "$hits")
    grep -vF "\"$msg\"" "$hits" > "$hits.new" && mv "$hits.new" "$hits"
    after=$(wc -l < "$hits")
    if [ $((before - after)) != 1 ]; then
      echo "  FAILED   $msg: the deletion removed $((before - after)) lines"; FAILED=$((FAILED + 1)); continue
    fi
  else
    count=$(grep -rcF -- "$from" "$MUTANT/src" "$MUTANT_LIB/src" | awk -F: '{s+=$2} END {print s}')
    if [ "$count" != 1 ]; then
      echo "  FAILED   \"$from\": found on $count lines, need exactly 1"; FAILED=$((FAILED + 1)); continue
    fi
    hits=$(grep -rlF -- "$from" "$MUTANT/src" "$MUTANT_LIB/src")
    FROM="$from" TO="$to" python3 -I -c 'import os,sys; p=sys.argv[1]; s=open(p).read(); n=s.replace(os.environ["FROM"], os.environ["TO"]); assert n != s; open(p,"w").write(n)' "$hits" \
      || { echo "  FAILED   could not apply the replacement"; FAILED=$((FAILED + 1)); continue; }
  fi

  if (cd "$MUTANT" && nargo execute w --prover-name "test-vectors/$vector" > "$MUTANT/run.log" 2>&1); then
    echo "  ok       $label, $vector is ACCEPTED -- that code is what refuses it"
    PASSED=$((PASSED + 1))
  else
    echo "  FAILED   $label, $vector is still refused:"
    grep -m1 "Assertion failed\|error\|Failed" "$MUTANT/run.log" | sed 's/^/           /'
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "  $PASSED caught, $FAILED not"
exit $([ "$FAILED" -eq 0 ] && echo 0 || echo 1)
