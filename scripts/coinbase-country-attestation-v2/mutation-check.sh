#!/bin/bash
# Prove that a refusal in coinbase_country_attestation v2's acceptance run is
# caused by the code it names.
#
#   scripts/coinbase-country-attestation-v2/mutation-check.sh [fixture-regex]
#
# The KYC v2 list (scripts/coinbase-attestation-v2/mutation-check.sh) for the
# shared signer, plus every check this circuit adds in
# ../../coinbase-country-v2-libs: the country list rule, the attestCountry
# selector, the statement's tag, schema and country. Engine:
# scripts/statement-signer/mutation-check.sh, against
# coinbase-country-attestation-v2-synthetic-anchors and its fixtures
# (scripts/coinbase-country-attestation-v2/make-fixtures.sh).
#   delete~<assert message>~<fixture>          delete the one line carrying the message
#   replace~<exact text>~<new text>~<fixture>  replace text occurring exactly once
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CASES=$(mktemp)
trap 'rm -f "$CASES"' EXIT
cat > "$CASES" <<'CASES'
# The statement (coinbase-country-v2-libs client_data.nr)
delete~clientData wallet is not the proven wallet~client_wallet_mismatch
delete~clientData says the attestation is revoked~client_revoked
delete~clientData does not bind this request~client_other_request
delete~clientData does not bind this scope~client_other_scope
delete~clientData timestamp is not the public timestamp~timestamp_changed
delete~clientData names another EAS schema~client_kyc_schema
delete~clientData is for another circuit~client_kyc_tag
delete~clientData names another country~client_other_country
delete~clientData names another country~server_other_country
# The transaction and the list (coinbase-country-v2-libs lib.nr)
delete~Invalid function selector~kyc_tx
delete~Country is in exclusion list~exclusion_refused
delete~Country not in inclusion list~not_in_inclusion_list
delete~Country list must not be empty~list_length_zero
delete~Country list length exceeds maximum~list_length_eleven
replace~        if i < country_list_length {~        if true {~match_past_length
# The signer (statement-signer, shared with KYC v2)
replace~        (signer_kind == KIND_APP) | (signer_kind == KIND_SERVER),~        true,~kind_unknown
replace~    if signer_kind == KIND_APP {~    if false {~app_chain_with_server_signature
replace~        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~        true | std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),~server_other_key
replace~        verify_credential_signature(~        true | verify_credential_signature(~cert_other_ca
delete~App Attest environment does not match~env_development
CASES
"$SCRIPT_DIR/../statement-signer/mutation-check.sh" coinbase-country-attestation-v2 "$CASES" "${1:-}"
