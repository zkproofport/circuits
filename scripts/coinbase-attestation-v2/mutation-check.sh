#!/bin/bash
# Prove that a refusal in coinbase_attestation_v2's acceptance run is caused
# by the code it names.
#
#   scripts/coinbase-attestation-v2/mutation-check.sh [fixture-regex]
#
# With a regex, only cases whose fixture name matches run (each case compiles
# the whole 2^20 circuit). The engine is scripts/statement-signer/mutation-check.sh
# (shared with oidc_domain_attestation): it copies the synthetic-anchors
# circuit, the statement-signer library and the App Attest library, applies
# ONE mutation from the list below to any of them, and requires the named
# refusal fixture to be ACCEPTED by the mutant.
#   delete~<assert message>~<fixture>          delete the one line carrying the message
#   replace~<exact text>~<new text>~<fixture>  replace text occurring exactly once
#
# Needs the synthetic-anchors copy and its fixtures
# (scripts/coinbase-attestation-v2/make-fixtures.sh).
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CASES=$(mktemp)
trap 'rm -f "$CASES"' EXIT
cat > "$CASES" <<'CASES'
# The statement (client_data.nr)
delete~clientData wallet is not the proven wallet~client_wallet_mismatch
delete~clientData says the attestation is revoked~client_revoked
delete~clientData does not bind this request~client_other_request
delete~clientData does not bind this scope~client_other_scope
delete~clientData timestamp is not the public timestamp~timestamp_changed
delete~clientData names another EAS schema~client_other_schema
# The signer kind (statement-signer/src/lib.nr)
# Multi-line asserts are neutralised by replacing their condition: deleting
# only the message line would leave a message-less assert that still refuses.
replace~        (signer_kind == KIND_APP) | (signer_kind == KIND_SERVER),~        true,~kind_unknown
replace~        (signer_kind == KIND_APP) | (signer_kind == KIND_SERVER),~        true,~kind_zero
replace~    if signer_kind == KIND_APP {~    if false {~app_chain_with_server_signature
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~server_other_key
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~assertion_other_key
# Apple's chain under the pinned CA (app-attest-libs). The root -> intermediate
# link is not in this circuit (CA 1 is pinned); its checks are the
# library's unit tests.
replace~        verify_credential_signature(\n            ca_x,~        true | verify_credential_signature(\n            ca_x,~cert_other_ca
delete~App Attest environment does not match~env_development
delete~Assertion is not for this app~assertion_wrong_rpid
delete~Assertion counter is zero~assertion_counter_zero
CASES
"$SCRIPT_DIR/../statement-signer/mutation-check.sh" coinbase-attestation-v2 "$CASES" "${1:-}"
