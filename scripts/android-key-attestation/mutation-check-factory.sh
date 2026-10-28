#!/bin/bash
# Which code refuses each refusal in oidc-domain-attestation-android-factory's
# acceptance run (factory chain + Play Integrity verdict). One assert is
# neutralised in a mutant copy and the named fixture must then be ACCEPTED.
#
#   scripts/android-key-attestation/mutation-check-factory.sh [fixture-regex]
#
# Needs the synthetic-anchors copy and its fixtures
# (oidc-domain-attestation-android-factory/scripts/post-build.sh). Mechanics:
# scripts/statement-signer/mutation-check.sh.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(cd "$SCRIPT_DIR/../.." && pwd)"
CASES=$(mktemp)
trap 'rm -f "$CASES"' EXIT
cat > "$CASES" <<'CASES'
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, statement_digest),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, statement_digest),~stmt_other_key_vouched
replace~        verify_credential_signature(ik_x, ik_y, chain.batch_tbs, chain.batch_tbs_len, rb, sb),~        true | verify_credential_signature(ik_x, ik_y, chain.batch_tbs, chain.batch_tbs_len, rb, sb),~batch_signed_by_other_key
replace~        std::ecdsa_secp256r1::verify_signature(batch_x, batch_y, chain.leaf_sig, leaf_digest),~        true | std::ecdsa_secp256r1::verify_signature(batch_x, batch_y, chain.leaf_sig, leaf_digest),~leaf_signed_by_other_key
replace~    assert(ka_in_batch == 0, "Batch certificate carries a key description");~    assert(true, "Batch certificate carries a key description");~key_description_in_batch
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, token.signature, digest),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, token.signature, digest),~verdict_signed_by_other_key
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, token.signature, digest),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, token.signature, digest),~verdict_tampered
replace~        same_string(recognition, "PLAY_RECOGNIZED".as_bytes()),~        true,~verdict_unrecognized
replace~    assert(meets, "Device does not meet Play device integrity");~    assert(true, "Device does not meet Play device integrity");~verdict_basic_only
replace~    assert(same_string(request_package, package), "Integrity verdict was requested by another app");~    assert(true, "Integrity verdict was requested by another app");~verdict_requested_by_other_app
replace~    assert(same_string(app_package, package), "Integrity verdict is for another app");~    assert(true, "Integrity verdict is for another app");~verdict_for_other_app
replace~    assert(ok, "Integrity verdict nonce is not this statement's");~    assert(true, "Integrity verdict nonce is not this statement's");~verdict_for_other_statement
CASES
"$CIRCUITS/scripts/statement-signer/mutation-check.sh" oidc-domain-attestation-android-factory "$CASES" "${1:-}"
