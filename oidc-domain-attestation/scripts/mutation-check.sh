#!/bin/bash
# Prove that each refusal in the acceptance run is caused by the code it names.
#
#   oidc-domain-attestation/scripts/mutation-check.sh [fixture-regex]
#
# The engine is scripts/statement-signer/mutation-check.sh (shared with
# coinbase_attestation_v2): for each case it copies the synthetic-anchors
# circuit, the statement-signer library and the App Attest library to sibling
# directories, applies ONE mutation to any of them, and runs the named refusal
# fixture. The mutant must ACCEPT it -- otherwise something else was doing the
# refusing and the acceptance case proves nothing about that code.
#   delete~<assert message>~<fixture>          delete the one line carrying the message
#   replace~<exact text>~<new text>~<fixture>  replace text occurring exactly once
# The originals are never edited; the copies are removed on exit.
#
# Needs the synthetic-anchors copy and its fixtures (scripts/post-build.sh).
#
# Guards NOT listed, because no honest witness can isolate them (each is
# defence in depth behind another check; see README.md "Mutation checks"):
#   "base64_decode_offset is outside partial_data", "payload start is not in
#   the first block of partial_data", "claim key is not inside the payload
#   object", "claim value mismatch", "claim value has no opening quote",
#   "claim value has no closing quote",
#   "claim value contains a quote" (needs a dishonest hint; held by the
#   Noir test claims::an_email_run_into_the_next_claim_is_refused instead),
#   "claim value is not terminated", "number claim is empty", "boolean claim
#   is neither true nor false".
# Swapping the provider (a Google token with provider 1 and the reverse) is
# refused by the issuer check AND by the other provider's email-verified
# claim being absent, so it is not listed either.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(cd "$SCRIPT_DIR/../.." && pwd)"
CASES=$(mktemp)
trap 'rm -f "$CASES"' EXIT
cat > "$CASES" <<'CASES'
# The decode position (claims.nr)
replace~        data.storage()[base64_decode_offset - 1] == PERIOD,~        true,~decode_offset_plus_4
# Key and value shape (claims.nr)
delete~claim key is not a top-level key~nonce_escaped_key
delete~claim key is not followed by a colon~nonce_array_spoof
delete~claim value contains an escape~aud_escaped
delete~number claim is not a decimal integer~exp_not_integer
# Issuer (main.nr)
delete~iss is not Google~google_wrong_iss
delete~iss is not a Microsoft v2.0 tenant issuer~microsoft_v1_iss
delete~iss is not a Microsoft v2.0 tenant issuer~microsoft_iss_uppercase_tenant
# Audience
delete~aud is empty~aud_empty
delete~aud does not match aud_hash~foreign_aud
# Freshness
delete~token issued after now~before_iat
delete~token expired at now~expired
# Nonce
replace~        (nonce_mode == NONCE_MODE_NONE) | (nonce_mode == NONCE_MODE_BOUND),~        true,~nonce_mode_2
delete~nonce claim is not 64 characters~nonce_65_chars
replace~                (nonce.storage()[2 * i] == hex_digit(b >> 4))~                true | (nonce.storage()[2 * i] == hex_digit(b >> 4))~nonce_mismatch
replace~                (nonce.storage()[2 * i] == hex_digit(b >> 4))~                true | (nonce.storage()[2 * i] == hex_digit(b >> 4))~nonce_uppercase
replace~                (nonce.storage()[2 * i] == hex_digit(b >> 4))~                true | (nonce.storage()[2 * i] == hex_digit(b >> 4))~nonce_inside_value
replace~                (nonce.storage()[2 * i] == hex_digit(b >> 4))~                true | (nonce.storage()[2 * i] == hex_digit(b >> 4))~duplicate_nonce_first_wrong
delete~nonce_binding must be zero when nonce_mode is 0~nonzero_binding_mode0
# Email verification (unchanged semantics, now through claims.nr)
replace~            claims::bool_claim(payload, "email_verified".as_bytes()),~            true,~email_not_verified
delete~xms_edov is not true~xms_edov_false
# The provider-key statement (src/provider_key.nr): each field the circuit
# writes is what refuses a statement signed with another value there.
replace~    s[48] = provider;~    s[48] = 1;~stmt_other_provider
replace~    let t = u64_be(now);~    let t = u64_be(now - 1);~stmt_other_time
replace~    [0x5a, 0x4b, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x50, 0x4b, 0x2f, 0x31];~    [0x5a, 0x4b, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x41, 0x41, 0x2f, 0x31];~stmt_wrong_magic
# Who signed it (statement-signer/src/lib.nr, shared with coinbase_attestation_v2)
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~stmt_other_key_vouched_server
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~stmt_other_key_vouched_app
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~stmt_coinbase_replay_server
replace~        (signer_kind == KIND_APP) | (signer_kind == KIND_SERVER),~        true,~kind_unknown
replace~    if signer_kind == KIND_APP {~    if false {~app_chain_with_server_signature
# Apple's chain under the pinned CA (app-attest-libs)
replace~        verify_credential_signature(~        true | verify_credential_signature(~cert_other_ca
delete~App Attest environment does not match~env_development
delete~Assertion is not for this app~assertion_wrong_rpid
delete~Assertion counter is zero~assertion_counter_zero
CASES
"$CIRCUITS/scripts/statement-signer/mutation-check.sh" oidc-domain-attestation "$CASES" "${1:-}"
