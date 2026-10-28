#!/bin/bash
# oidc_domain_attestation, ANDROID FACTORY package -- acceptance run.
#
# Run by scripts/build.sh after the circuit compiles; also runnable alone:
#   oidc-domain-attestation-android-factory/scripts/post-build.sh
#
#   1. the Noir tests of android-key-attestation (real Google chains),
#      statement-signer and oidc-libs;
#   2. the synthetic-anchors copy (scripts/statement-signer/
#      make-synthetic-anchors.sh): this circuit unchanged, the library's
#      Google root replaced by a synthetic root the generator holds;
#   3. fixtures, regenerated on every run by scripts/make-fixtures.ts (RSA and
#      EC keys made on the spot; nothing real or secret is stored);
#   4. every case against the synthetic-anchors copy;
#   5. the cases that must run against the real circuit (Google's root).
#
# Every refusal must name its reason, so a fixture refused for some other
# reason cannot hide the guard it exercises being gone. Which code refuses is
# checked by scripts/android-key-attestation/mutation-check.sh. Accepted
# cases marked PROVE also go through bb prove / bb verify, and the public
# inputs bb writes are compared with the reference layout (214 values).
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_DIR="$(dirname "$SCRIPT_DIR")"
CIRCUITS="$(dirname "$REAL_DIR")"
CIRCUIT_DIR="$CIRCUITS/oidc-domain-attestation-android-factory-synthetic-anchors"
VECTORS="$CIRCUIT_DIR/test-vectors"
REAL_VECTORS="$REAL_DIR/test-vectors"
CIRCUIT_NAME=$(grep -m1 '^name' "$REAL_DIR/Nargo.toml" | sed 's/.*= *"\(.*\)"/\1/')
CIRCUIT_JSON="$CIRCUIT_DIR/target/${CIRCUIT_NAME}.json"
TSX_DIR="$CIRCUITS/oidc-domain-attestation/scripts"

LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT
for lib in android-key-attestation play-integrity statement-signer oidc-libs; do
  if (cd "$CIRCUITS/$lib" && nargo test > "$LOG" 2>&1); then
    echo "  $lib Noir tests: $(grep -E 'tests passed' "$LOG" | tail -1 | sed 's/^.*\] //')"
  else
    grep -E "FAIL|failed" "$LOG" | sed 's/^/  /'
    echo "  FAILED   nargo test in $lib"
    exit 1
  fi
done
echo "  building the synthetic-anchors copy"
if ! "$CIRCUITS/scripts/statement-signer/make-synthetic-anchors.sh" oidc-domain-attestation-android-factory > "$LOG" 2>&1; then
  echo "  FAILED   make-synthetic-anchors.sh"
  sed -n '1,20p' "$LOG" | sed 's/^/           /'
  exit 1
fi
grep -E "synthetic-anchors copy:" "$LOG" | sed 's/^/  /'

if [ ! -x "$TSX_DIR/node_modules/.bin/tsx" ]; then
  echo "  installing fixture-script dependencies (npm ci in oidc-domain-attestation/scripts)"
  (cd "$TSX_DIR" && env -u NODE_OPTIONS npm ci --silent > /dev/null 2>&1) || { echo "  FAILED   npm ci in $TSX_DIR"; exit 1; }
fi
echo "  regenerating fixtures"
if ! (cd "$SCRIPT_DIR" && env -u NODE_OPTIONS "$TSX_DIR/node_modules/.bin/tsx" make-fixtures.ts > "$LOG" 2>&1); then
  echo "  FAILED   make-fixtures.ts"
  sed -n '1,20p' "$LOG" | sed 's/^/           /'
  exit 1
fi

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
      echo "  ok       $name  (proved, verified, $(( ${#got} / 64 )) public inputs as laid out, proof $(wc -c < "$out/proof" | tr -d ' ') bytes)"
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
accept microsoft_bound PROVE
accept strong_integrity_only
accept strongbox_key

echo ""
echo "Refused, the statement:"
refuse stmt_other_key_vouched            "Statement signature is invalid"
refuse stmt_coinbase_replay              "Statement signature is invalid"

echo ""
echo "Refused, the chain and key description:"
refuse other_package                     "Key belongs to another app"
refuse debug_signing_certificate         "App is signed with another certificate"
refuse bootloader_unlocked               "Device bootloader is unlocked"
refuse boot_unverified                   "Device boot state is not Verified"
refuse software_key                      "Key is not in secure hardware"
refuse ik_not_a_ca                       "Certificate is not a CA certificate"
refuse key_description_in_batch          "Batch certificate carries a key description"
refuse batch_signed_by_other_key         "Batch certificate is not signed by the intermediate"
refuse leaf_signed_by_other_key          "Leaf certificate is not signed by the batch key"
# noir_rsa refuses inside its padding check, without a message of ours.
refuse ik_signed_by_other_rsa_key        "Failed constraint"
refuse other_rsa_root_inputs             "RSA root is not Google's"
refuse other_play_key_input              "Play Integrity key is not our app's"

echo ""
echo "Refused, the Play Integrity verdict:"
refuse verdict_basic_only                "Device does not meet Play device integrity"
refuse verdict_no_device_verdict         "Device does not meet Play device integrity"
refuse verdict_unrecognized              "App is not recognized by Google Play"
refuse verdict_requested_by_other_app    "Integrity verdict was requested by another app"
refuse verdict_for_other_app             "Integrity verdict is for another app"
refuse verdict_for_other_statement       "Integrity verdict nonce is not this statement's"
refuse verdict_signed_by_other_key       "Integrity verdict is not signed by Google Play"
refuse verdict_tampered                  "Integrity verdict is not signed by Google Play"

echo ""
echo "Refused, the token (a sample):"
refuse token_expired                     "token expired at now"

echo ""
echo "Real circuit (Google's RSA root and our Play key as committed):"
cd "$REAL_DIR"
VECTORS="$REAL_VECTORS"
refuse real_synthetic_root                 "RSA root is not Google's"
refuse real_google_factory_chain_other_app "Key belongs to another app"
if [ -f "$REAL_VECTORS/real_device.toml" ]; then
  accept real_device
fi

echo ""
echo "  $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
