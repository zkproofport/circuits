#!/bin/bash
# Prove that each refusal in the acceptance run is caused by the code it names.
#
#   oidc-domain-attestation/scripts/mutation-check.sh [fixture-regex]
#
# For each case: copy the circuit to a sibling directory (so ../deps still
# resolves), apply ONE mutation, and run the named refusal fixture. The mutant
# must ACCEPT it -- otherwise something else was doing the refusing and the
# acceptance case proves nothing about that code.
#   delete|<assert message>|<fixture>          delete the one line carrying the message
#   replace|<exact text>|<new text>|<fixture>  replace text occurring exactly once
# The original is never edited; the copy is removed on exit.
#
# Needs the fixtures (scripts/post-build.sh or scripts/make-fixtures.ts).
#
# Guards NOT listed, because no honest witness can isolate them (each is
# defence in depth behind another check; see README.md "Mutation checks"):
#   "base64_decode_offset is outside partial_data", "payload start is not in
#   the first block of partial_data", "claim key is not inside the payload
#   object", "claim value mismatch", "claim value has no opening quote",
#   "claim value has no closing quote",
#   "claim value is not terminated", "number claim is empty", "boolean claim
#   is neither true nor false".
# Swapping the provider (a Google token with provider 1 and the reverse) is
# refused by the issuer check AND by the other provider's email-verified
# claim being absent, so it is not listed either.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT="$(dirname "$SCRIPT_DIR")"
MUTANT="$(dirname "$CIRCUIT")/oidc-domain-attestation-mutant"

CASES=(
  # The decode position (claims.nr)
  "replace|        data.storage()[base64_decode_offset - 1] == PERIOD,|        true,|decode_offset_plus_4"
  # Key and value shape (claims.nr)
  "delete|claim key is not a top-level key|nonce_escaped_key"
  "delete|claim key is not followed by a colon|nonce_array_spoof"
  "delete|claim value contains an escape|aud_escaped"
  "delete|number claim is not a decimal integer|exp_not_integer"
  # Issuer (main.nr)
  "delete|iss is not Google|google_wrong_iss"
  "delete|iss is not a Microsoft v2.0 tenant issuer|microsoft_v1_iss"
  "delete|iss is not a Microsoft v2.0 tenant issuer|microsoft_iss_uppercase_tenant"
  # Audience
  "delete|aud is empty|aud_empty"
  "delete|aud does not match aud_hash|foreign_aud"
  # Freshness
  "delete|token issued after now|before_iat"
  "delete|token expired at now|expired"
  # Nonce
  "replace|        (nonce_mode == NONCE_MODE_NONE) \| (nonce_mode == NONCE_MODE_BOUND),|        true,|nonce_mode_2"
  "delete|nonce claim is not 64 characters|nonce_65_chars"
  "replace|                (nonce.storage()[2 * i] == hex_digit(b >> 4))|                true \| (nonce.storage()[2 * i] == hex_digit(b >> 4))|nonce_mismatch"
  "replace|                (nonce.storage()[2 * i] == hex_digit(b >> 4))|                true \| (nonce.storage()[2 * i] == hex_digit(b >> 4))|nonce_uppercase"
  "replace|                (nonce.storage()[2 * i] == hex_digit(b >> 4))|                true \| (nonce.storage()[2 * i] == hex_digit(b >> 4))|nonce_inside_value"
  "replace|                (nonce.storage()[2 * i] == hex_digit(b >> 4))|                true \| (nonce.storage()[2 * i] == hex_digit(b >> 4))|duplicate_nonce_first_wrong"
  "delete|nonce_binding must be zero when nonce_mode is 0|nonzero_binding_mode0"
  # Email verification (unchanged semantics, now through claims.nr)
  "replace|            claims::bool_claim(payload, \"email_verified\".as_bytes()),|            true,|email_not_verified"
  "delete|xms_edov is not true|xms_edov_false"
)

[ -f "$CIRCUIT/test-vectors/nonce_mismatch.toml" ] || { echo "fixtures missing: run scripts/make-fixtures.ts" >&2; exit 1; }
[ ! -e "$MUTANT" ] || { echo "$MUTANT exists; remove it (a previous run was interrupted)" >&2; exit 1; }
trap 'rm -rf "$MUTANT"' EXIT

PASSED=0
FAILED=0
ONLY="${1:-}"
for c in "${CASES[@]}"; do
  # `\|` in a case is a literal | inside the text.
  c="${c//\\|/$'\x01'}"
  IFS='|' read -r kind a b d <<< "$c"
  a="${a//$'\x01'/|}"; b="${b//$'\x01'/|}"; d="${d//$'\x01'/|}"
  if [ "$kind" = delete ]; then msg="$a"; vector="$b"; label="without \"$msg\""
  else from="$a"; to="$b"; vector="$d"; label="with \"$(echo "$from" | sed 's/^ *//')\" -> \"$(echo "$to" | sed 's/^ *//')\""; fi
  if [ -n "$ONLY" ] && ! echo "$vector" | grep -Eq "$ONLY"; then continue; fi
  rm -rf "$MUTANT"
  mkdir -p "$MUTANT"
  cp -R "$CIRCUIT/Nargo.toml" "$CIRCUIT/src" "$CIRCUIT/test-vectors" "$MUTANT/"

  if [ "$kind" = delete ]; then
    count=$(grep -rcF "\"$msg\"" "$MUTANT/src" | awk -F: '{s+=$2} END {print s}')
    if [ "$count" != 1 ]; then
      echo "  FAILED   $msg: found on $count lines, need exactly 1"; FAILED=$((FAILED + 1)); continue
    fi
    hits=$(grep -rlF "\"$msg\"" "$MUTANT/src")
    if ! grep -F "\"$msg\"" "$hits" | grep -q "assert("; then
      echo "  FAILED   $msg: not a single-line assert; use replace"; FAILED=$((FAILED + 1)); continue
    fi
    before=$(wc -l < "$hits")
    grep -vF "\"$msg\"" "$hits" > "$hits.new" && mv "$hits.new" "$hits"
    after=$(wc -l < "$hits")
    if [ $((before - after)) != 1 ]; then
      echo "  FAILED   $msg: the deletion removed $((before - after)) lines"; FAILED=$((FAILED + 1)); continue
    fi
  else
    count=$(grep -rcF -- "$from" "$MUTANT/src" | awk -F: '{s+=$2} END {print s}')
    if [ "$count" != 1 ]; then
      echo "  FAILED   \"$from\": found on $count lines, need exactly 1"; FAILED=$((FAILED + 1)); continue
    fi
    hits=$(grep -rlF -- "$from" "$MUTANT/src")
    FROM="$from" TO="$to" python3 -I -c 'import os,sys; p=sys.argv[1]; s=open(p).read(); n=s.replace(os.environ["FROM"], os.environ["TO"]); assert n != s; open(p,"w").write(n)' "$hits" \
      || { echo "  FAILED   could not apply the replacement"; FAILED=$((FAILED + 1)); continue; }
  fi

  if (cd "$MUTANT" && nargo execute w --prover-name "test-vectors/$vector" > "$MUTANT/run.log" 2>&1); then
    echo "  ok       $label: $vector is ACCEPTED -- that code is what refuses it"
    PASSED=$((PASSED + 1))
  else
    echo "  FAILED   $label: $vector is still refused:"
    grep -m1 "error:" "$MUTANT/run.log" | sed 's/^/           /'
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "  $PASSED caught, $FAILED not"
[ "$FAILED" -eq 0 ]
