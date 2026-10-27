#!/bin/bash
# oidc_domain_attestation -- acceptance run (v2: aud, iss, iat/exp, nonce).
#
# Run by scripts/build.sh after the circuit compiles; also runnable alone:
#   oidc-domain-attestation/scripts/post-build.sh
#
# Fixtures are regenerated on every run by scripts/make-fixtures.ts from an
# RSA key made on the spot, so nothing secret or real is stored and nothing
# goes stale. They land in test-vectors/ (gitignored).
#
# Every refusal must name its reason: a fixture refused for some OTHER reason
# would hide the guard it is meant to exercise being gone. Which code does the
# refusing is checked separately by scripts/mutation-check.sh.
#
# The accepted cases marked PROVE also go through bb prove / bb verify, and
# the public inputs bb writes are compared with the layout the reference
# builder (scripts/oidc-inputs.ts) computes -- 214 values in a fixed order.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_DIR="$(dirname "$SCRIPT_DIR")"
VECTORS="$CIRCUIT_DIR/test-vectors"
CIRCUIT_NAME=$(grep -m1 '^name' "$CIRCUIT_DIR/Nargo.toml" | sed 's/.*= *"\(.*\)"/\1/')
CIRCUIT_JSON="$CIRCUIT_DIR/target/${CIRCUIT_NAME}.json"

cd "$SCRIPT_DIR"
if [ ! -x node_modules/.bin/tsx ]; then
  echo "  installing fixture-script dependencies (npm ci)"
  env -u NODE_OPTIONS npm ci --silent > /dev/null 2>&1 || { echo "  FAILED   npm ci in $SCRIPT_DIR"; exit 1; }
fi
echo "  regenerating fixtures"
if ! env -u NODE_OPTIONS node_modules/.bin/tsx make-fixtures.ts > "$CIRCUIT_DIR/make-fixtures.log" 2>&1; then
  echo "  FAILED   make-fixtures.ts"
  sed -n '1,20p' "$CIRCUIT_DIR/make-fixtures.log" | sed 's/^/           /'
  exit 1
fi
mv "$CIRCUIT_DIR/make-fixtures.log" "$VECTORS/make-fixtures.log"

cd "$CIRCUIT_DIR"
PASSED=0
FAILED=0

accept() {
  local name="$1" prove="${2:-}"
  if ! nargo execute "witness_${name}" --prover-name "test-vectors/${name}" > "$VECTORS/${name}.log" 2>&1; then
    echo "  FAILED   $name  (expected the circuit to accept it)"
    sed -n '1,8p' "$VECTORS/${name}.log" | sed 's/^/           /'
    FAILED=$((FAILED + 1))
    return
  fi
  if [ "$prove" != PROVE ]; then
    echo "  ok       $name"
    PASSED=$((PASSED + 1))
    return
  fi
  local out="$VECTORS/proof_${name}"
  mkdir -p "$out"
  if bb prove -b "$CIRCUIT_JSON" -w "target/witness_${name}.gz" -k target/vk/vk -o "$out" -t evm > "$out/prove.log" 2>&1 \
     && bb verify -p "$out/proof" -i "$out/public_inputs" -k target/vk/vk -t evm > "$out/verify.log" 2>&1; then
    local got want
    got=$(xxd -p "$out/public_inputs" | tr -d '\n')
    want=$(cat "$VECTORS/${name}.public_inputs.hex")
    if [ "$got" = "$want" ]; then
      echo "  ok       $name  (proved, verified, $(( ${#got} / 64 )) public inputs as laid out)"
      PASSED=$((PASSED + 1))
    else
      echo "  FAILED   $name  (verified, but public inputs differ from the reference layout: $(( ${#got} / 64 )) vs $(( ${#want} / 64 )))"
      FAILED=$((FAILED + 1))
    fi
  else
    echo "  FAILED   $name  (witness ok, but bb prove/verify failed)"
    tail -5 "$out/prove.log" "$out/verify.log" 2>/dev/null | sed 's/^/           /'
    FAILED=$((FAILED + 1))
  fi
}

refuse() {
  local name="$1" expected="$2"
  if nargo execute "witness_${name}" --prover-name "test-vectors/${name}" > "$VECTORS/${name}.log" 2>&1; then
    echo "  FAILED   $name  (the circuit ACCEPTED something it must refuse)"
    FAILED=$((FAILED + 1))
  elif grep -qF "$expected" "$VECTORS/${name}.log"; then
    echo "  ok       $name  -> $expected"
    PASSED=$((PASSED + 1))
  else
    echo "  FAILED   $name  (refused, but not for the stated reason)"
    echo "           wanted: $expected"
    grep -m1 "error:" "$VECTORS/${name}.log" | sed 's/^/           got:    /'
    FAILED=$((FAILED + 1))
  fi
}

echo ""
echo "Acceptance run: $CIRCUIT_NAME"
echo ""
echo "Accepted:"
accept google_bound PROVE
accept google_device_no_nonce PROVE   # nonce_mode 0, no nonce claim at all
accept microsoft_bound PROVE
accept microsoft_large PROVE          # partial_data at the 2048 cap
accept google_iss_bare
accept google_mode0_foreign_nonce
accept google_now_equals_iat
accept google_now_last_second
accept google_reordered
accept microsoft_consumer_order
accept microsoft_no_nonce

echo ""
echo "Accepted, and recorded as a limitation (README.md, duplicate claims):"
accept doc_duplicate_nonce_first_matches

echo ""
echo "Refused:"
refuse foreign_aud                    "aud does not match aud_hash"
refuse aud_empty                      "aud is empty"
refuse aud_array                      "claim value has no opening quote"
refuse aud_escaped                    "claim value contains an escape"
refuse google_wrong_iss               "iss is not Google"
refuse microsoft_token_as_google      "iss is not Google"
refuse google_token_as_microsoft      "iss is not a Microsoft v2.0 tenant issuer"
refuse microsoft_v1_iss               "iss is not a Microsoft v2.0 tenant issuer"
refuse microsoft_iss_uppercase_tenant "iss is not a Microsoft v2.0 tenant issuer"
refuse expired                        "token expired at now"
refuse before_iat                     "token issued after now"
refuse exp_not_integer                "number claim is not a decimal integer"
refuse iat_quoted                     "claim value is not terminated"
refuse missing_nonce_mode1            "claim key not found in the payload"
refuse nonzero_binding_mode0          "nonce_binding must be zero when nonce_mode is 0"
refuse nonce_mode_2                   "unsupported nonce_mode"
refuse nonce_mismatch                 "nonce claim does not match nonce_binding"
refuse nonce_uppercase                "nonce claim does not match nonce_binding"
refuse nonce_65_chars                 "nonce claim is not 64 characters"
refuse nonce_0x_prefixed              "claim value has no closing quote"
refuse nonce_inside_value             "nonce claim does not match nonce_binding"
refuse nonce_escaped_key              "claim key is not a top-level key"
refuse nonce_as_array_element         "claim key is not followed by a colon"
refuse nonce_array_spoof              "claim key is not followed by a colon"
refuse duplicate_nonce_first_wrong    "nonce claim does not match nonce_binding"
refuse email_not_verified             "email_verified is not true"
refuse xms_edov_false                 "xms_edov is not true"
refuse decode_offset_plus_1           "base64_decode_offset is not the payload start"
refuse decode_offset_plus_4           "base64_decode_offset is not the payload start"
refuse wrong_nullifier                "nullifier mismatch"
# RSA: noir-jwt's signature assert carries no message.
refuse other_key_signed               "Failed constraint"

echo ""
echo "  $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
