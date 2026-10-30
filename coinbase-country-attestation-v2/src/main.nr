// coinbase_country_attestation v2 -- Coinbase Verified Country whose
// revocation is bound by a signed statement, from Apple App Attest or from
// the AI server.
//
// coinbase_attestation v2 (../coinbase-attestation-v2) applied to the Country
// attestation, decided 2026-10-23 for "the Coinbase circuits" and built
// 2026-10-30: the same signers (../statement-signer), the same optional
// EIP-712 action, the same wallet + circuit-tag nullifier, and v1's country
// list rule unchanged. The package is coinbase_country_attestation_v2 while
// v1 still lives in ../coinbase-country-attestation; the circuit ID it serves
// is the canonical `coinbase_country_attestation`, which is what its
// nullifier tag and statement carry. README.md has the statement, the public
// inputs and the measurements.
//
// WHAT THIS PROVES
//
//   1. The wallet signed the request: personal_sign over signal_hash, or an
//      EIP-712 action (coinbase_libs::signed_message::signed_digest).
//   2. v1's checks, unchanged: an attestCountry(country ++ wallet) transaction
//      to Coinbase's attester, signed by a key whose address is in the public
//      signer Merkle root; the country is in (or, in exclusion mode, not in)
//      the public list.
//   3. A 227-byte statement (../coinbase-country-v2-libs client_data.nr)
//      naming this wallet, the public attested_at, Coinbase's Country schema
//      and attester, revoked = 0, this request's digest, this scope and the
//      transaction's country, signed by the app (production App Attest only)
//      or by the server.
//   4. Nullifier: keccak(keccak(wallet ++ CIRCUIT_TAG) ++ scope).

use coinbase_libs::nullifier::verify_wallet_nullifier;
use coinbase_country_v2_libs::{
    check_country_list, check_request_and_country_tx, CIRCUIT_TAG, COUNTRY_LIST_MAX,
};
use coinbase_country_v2_libs::client_data::{check_country_client_data, COUNTRY_CLIENT_DATA_LEN};
use statement_signer::{
    ASSERT_AUTH_DATA_MAX_LEN, ATT_AUTH_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN, SignerChain,
    verify_statement,
};

fn main(
    // ============ Public Inputs ============
    // coinbase_attestation v2's order with v1's country fields where v1 had
    // them: after the signer root, before scope and nullifier.
    signal_hash: pub [u8; 32],
    domain_separator: pub [u8; 32],
    action_hash: pub [u8; 32],
    signer_list_merkle_root: pub [u8; 32],
    // Up to 10 ISO 3166-1 alpha-2 codes; entries at or past the length are ignored.
    country_list: pub [[u8; 2]; COUNTRY_LIST_MAX],
    country_list_length: pub u32,
    // true: the attested country must be in the list; false: must not be.
    is_included: pub bool,
    scope: pub [u8; 32],
    nullifier: pub [u8; 32],

    // ============ Public Input (the statement's time) ============
    // When the signer saw the attestation unrevoked (unix seconds). The
    // verifier enforces freshness against its own clock.
    attested_at: pub u64,

    // ============ Private Inputs ============
    user_address: [u8; 20],
    user_signature: [u8; 64],
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],

    raw_transaction: [u8; 300],
    tx_length: u32,
    coinbase_attester_pubkey_x: [u8; 32],
    coinbase_attester_pubkey_y: [u8; 32],
    coinbase_signer_merkle_proof: [[u8; 32]; 8],
    coinbase_signer_leaf_index: u32,
    merkle_proof_depth: u32,

    // The statement, and who signed it.
    client_data: [u8; COUNTRY_CLIENT_DATA_LEN],
    signer_kind: u8,
    // P-256 r || s, s in low form: the App Attest assertion signature (app)
    // or the server's signature (server).
    statement_sig: [u8; 64],

    // App Attest chain below the pinned intermediate. The server kind passes
    // zeros for all of these.
    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    credential_tbs_len: u32,
    credential_sig: [u8; 96],
    att_auth_data: [u8; ATT_AUTH_DATA_MAX_LEN],
    att_auth_data_len: u32,
    att_client_data_hash: [u8; 32],
    assertion_auth_data: [u8; ASSERT_AUTH_DATA_MAX_LEN],
    assertion_auth_data_len: u32,
) {
    // ===================================================================
    // PARTS 1-2: this wallet signed THIS request; coinbase_country_attestation's
    //            transaction and country-list checks (../coinbase-country-v2-libs)
    // ===================================================================
    let (message_hash, country_code) = check_request_and_country_tx(
        signal_hash,
        domain_separator,
        action_hash,
        signer_list_merkle_root,
        user_address,
        user_signature,
        user_pubkey_x,
        user_pubkey_y,
        raw_transaction,
        tx_length,
        coinbase_attester_pubkey_x,
        coinbase_attester_pubkey_y,
        coinbase_signer_merkle_proof,
        coinbase_signer_leaf_index,
        merkle_proof_depth,
    );
    check_country_list(country_code, country_list, country_list_length, is_included);

    // ===================================================================
    // PART 3: a trusted signer said, at attested_at, that this wallet's
    //         Coinbase Country attestation for this
    //         country was unrevoked -- for this request
    // ===================================================================
    check_country_client_data(
        client_data,
        CIRCUIT_TAG,
        user_address,
        attested_at,
        message_hash,
        scope,
        country_code,
    );
    verify_statement(
        client_data,
        signer_kind,
        statement_sig,
        SignerChain {
            credential_tbs,
            credential_tbs_len,
            credential_sig,
            att_auth_data,
            att_auth_data_len,
            att_client_data_hash,
            assertion_auth_data,
            assertion_auth_data_len,
        },
    );

    // ===================================================================
    // PART 4: one nullifier per wallet per scope, nothing to choose
    // ===================================================================
    verify_wallet_nullifier(user_address, CIRCUIT_TAG, scope, nullifier);
}
