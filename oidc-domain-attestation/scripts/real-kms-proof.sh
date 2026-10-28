#!/bin/bash
# A real proof of the REAL circuit (anchors as committed): a real Google ID
# token from gcloud, Google's live key, a provider-key statement signed by the
# pinned Cloud KMS key (scripts/real-kms-fixture.ts). Proves with bb, verifies
# with bb, and leaves the proof in test-vectors/proof_real_kms_google/ for
# scripts/verify-onchain.sh:
#
#   oidc-domain-attestation/scripts/real-kms-proof.sh
#   scripts/verify-onchain.sh oidc-domain-attestation base-sepolia \
#       oidc-domain-attestation/test-vectors/proof_real_kms_google
#
# Needs the circuit built (scripts/build.sh oidc-domain-attestation), gcloud
# logged in with an account allowed to sign with the key (see
# real-kms-fixture.ts), and network access. The witness file carries the
# token and is deleted on exit; the proof and public inputs do not carry it.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUIT_DIR="$(dirname "$SCRIPT_DIR")"
VECTORS="$CIRCUIT_DIR/test-vectors"
CASE=real_kms_google
OUT="$VECTORS/proof_$CASE"
JSON="$CIRCUIT_DIR/target/oidc_domain_attestation.json"
mkdir -p "$VECTORS" "$OUT"
trap 'rm -f "$VECTORS/$CASE.toml" "$CIRCUIT_DIR/target/witness_$CASE.gz"' EXIT

[ -s "$JSON" ] && [ -s "$CIRCUIT_DIR/target/vk/vk" ] || { echo "build the circuit first: scripts/build.sh oidc-domain-attestation" >&2; exit 1; }
cd "$SCRIPT_DIR"
[ -x node_modules/.bin/tsx ] || env -u NODE_OPTIONS npm ci --silent > /dev/null 2>&1 || { echo "npm ci failed in $SCRIPT_DIR" >&2; exit 1; }
ID_TOKEN=$(gcloud auth print-identity-token 2>/dev/null) || { echo "gcloud auth print-identity-token failed" >&2; exit 1; }
ID_TOKEN="$ID_TOKEN" env -u NODE_OPTIONS node_modules/.bin/tsx real-kms-fixture.ts "$VECTORS/$CASE.toml" || exit 1

cd "$CIRCUIT_DIR"
nargo execute "witness_$CASE" --prover-name "test-vectors/$CASE" > "$OUT/execute.log" 2>&1 \
  || { echo "FAILED   the real circuit refused the real statement:"; grep -m3 "error\|Assertion" "$OUT/execute.log"; exit 1; }
START=$(date +%s)
bb prove -b "$JSON" -w "target/witness_$CASE.gz" -k target/vk/vk -o "$OUT" -t evm > "$OUT/prove.log" 2>&1 \
  || { echo "FAILED   bb prove"; tail -5 "$OUT/prove.log"; exit 1; }
END=$(date +%s)
bb verify -p "$OUT/proof" -i "$OUT/public_inputs" -k target/vk/vk -t evm > "$OUT/verify.log" 2>&1 \
  || { echo "FAILED   bb verify"; tail -5 "$OUT/verify.log"; exit 1; }
GOT=$(xxd -p "$OUT/public_inputs" | tr -d '\n')
WANT=$(cat "$VECTORS/$CASE.public_inputs.hex")
[ "$GOT" = "$WANT" ] || { echo "FAILED   public inputs differ from the reference layout"; exit 1; }
echo "ok       $CASE: real token, live Google key, KMS-signed statement; proved in $((END - START)) s ($(wc -c < "$OUT/proof" | tr -d ' ') bytes), verified, $(( ${#GOT} / 64 )) public inputs as laid out"
