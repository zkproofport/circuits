// PROTOTYPE -- Coinbase KYC with revocation enforced through Apple App Attest.
// Not a canonical circuit; no verifier is deployed for it. README.md has the
// clientData spec, the public-input layout and the measurements.
//
// WHY APP ATTEST
//
// coinbase_attestation proves Coinbase once sent attestAccount(wallet). That
// stays true after Coinbase revokes the attestation. Decided 2026-10-23 (see
// .claude/agents/circuits-dev.md, "Decisions"): do what zkPassport does for
// FaceMatch. The app looks the EAS attestation up right before proving, and
// only if it is unrevoked asks App Attest to sign a statement saying so,
// bound to this wallet, this time and this request. The circuit checks that
// a genuine instance of our app on a genuine Apple device made that statement.
// The gap that remains is a device owner feeding the genuine app a forged
// lookup answer (own root CA + proxy); certificate pinning narrows it.
//
// WHAT THIS PROVES
//
//   1. The wallet signed the request: personal_sign over signal_hash, or an
//      EIP-712 action -- coinbase_libs::signed_message::signed_digest, the
//      same rule as giwa_attestation, with the same public-input order.
//   2. coinbase_attestation's checks, unchanged: an attestAccount(wallet)
//      transaction to Coinbase's attester, signed by a key whose address is
//      in the public signer Merkle root.
//   3. App Attest: the credential certificate is signed by the intermediate
//      CA whose key hashes to the public app_attest_ca_key_hash, is for our
//      App ID, and its key signed an assertion over a clientData that names
//      this wallet, the public attested_at, Coinbase's KYC schema and
//      attester, revoked = 0, this request's digest and this scope.
//   4. Nullifier: keccak(keccak(wallet ++ CIRCUIT_TAG) ++ scope).
//
// THE NULLIFIER TAG IS keccak256("coinbase_attestation"), NOT THIS PACKAGE'S
// NAME. This prototype is the next version of coinbase_attestation (circuits
// v2.0.0), and that circuit keeps its canonical id; its nullifiers must be
// the ones the shipped circuit will produce, and proofport-ai's
// computeWalletNullifier(address, circuitId) derives the tag from the id.

mod client_data;

use keccak256::keccak256;
use coinbase_libs::eip1559_tx_parser;
use coinbase_libs::merkle;
use coinbase_libs::nullifier::verify_wallet_nullifier;
use coinbase_libs::signed_message::signed_digest;
use coinbase_libs::ethereum::{COINBASE_ATTESTER_CONTRACT, derive_address_from_pubkey};
use app_attest::{
    AppAttestInputs, ASSERT_AUTH_DATA_MAX_LEN, ATT_AUTH_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN,
    verify_app_attest,
};
use client_data::{CLIENT_DATA_LEN, check_client_data};

/// attestAccount(address) -- 0x56feed5e
global ATTEST_ACCOUNT_SELECTOR: [u8; 4] = [0x56, 0xfe, 0xed, 0x5e];

/// keccak256("coinbase_attestation"). See the header for why not this
/// package's name.
global CIRCUIT_TAG: [u8; 32] = [
    0x16, 0x3f, 0xeb, 0x85, 0xbf, 0xfe, 0x62, 0x69, 0x88, 0x19, 0x7d, 0x1c, 0x5f, 0x0b, 0x70, 0xdc,
    0x10, 0xf5, 0x93, 0xd7, 0x08, 0xab, 0x0e, 0xfb, 0xcd, 0xfa, 0x06, 0x81, 0x4d, 0x28, 0x6b, 0xe2,
];

/// The App ID: team id (proofport-app/ios DEVELOPMENT_TEAM) . bundle id.
global APP_ID: [u8; 36] = [
    0x52, 0x34, 0x47, 0x33, 0x32, 0x43, 0x56, 0x59, 0x32, 0x39, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x6d,
    0x61, 0x73, 0x73, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x2e, 0x7a, 0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66,
    0x70, 0x6f, 0x72, 0x74,
]; // "R4G32CVY29.com.masselabs.zkproofport"

/// SHA256(APP_ID): the RP ID hash in App Attest authenticator data.
global APP_ID_HASH: [u8; 32] = [
    0x6b, 0x26, 0x19, 0x1f, 0x2b, 0x69, 0xdc, 0x7f, 0xb7, 0xee, 0x29, 0x2a, 0x73, 0x29, 0xa3, 0x5e,
    0x31, 0x45, 0xef, 0x69, 0x80, 0xbd, 0x54, 0x9d, 0x2c, 0x61, 0x2e, 0x2c, 0x2f, 0x70, 0x7b, 0xe9,
];

fn main(
    // ============ Public Inputs (giwa_attestation's six, in its order) ============
    signal_hash: pub [u8; 32],
    domain_separator: pub [u8; 32],
    action_hash: pub [u8; 32],
    signer_list_merkle_root: pub [u8; 32],
    scope: pub [u8; 32],
    nullifier: pub [u8; 32],

    // ============ Public Inputs (App Attest) ============
    // SHA256(X || Y) of the App Attest intermediate CA key. The verifier
    // checks it is the key Apple's root signed (outside the circuit).
    app_attest_ca_key_hash: pub [u8; 32],
    // When the app saw the attestation unrevoked (unix seconds). The verifier
    // enforces freshness against its own clock.
    attested_at: pub u64,
    // true: the key is from the production App Attest environment; false:
    // development. The verifier decides which it accepts.
    app_attest_production: pub bool,

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

    client_data: [u8; CLIENT_DATA_LEN],
    app_attest_ca_key: [u8; 96],
    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    credential_tbs_len: u32,
    credential_sig: [u8; 96],
    att_auth_data: [u8; ATT_AUTH_DATA_MAX_LEN],
    att_auth_data_len: u32,
    att_client_data_hash: [u8; 32],
    assertion_auth_data: [u8; ASSERT_AUTH_DATA_MAX_LEN],
    assertion_auth_data_len: u32,
    assertion_sig: [u8; 64],
) {
    // ===================================================================
    // PART 1: this wallet signed THIS request
    // ===================================================================
    let derived_user_address = derive_address_from_pubkey(user_pubkey_x, user_pubkey_y);
    assert(derived_user_address == user_address, "User pubkey does not match address");

    let message_hash = signed_digest(signal_hash, domain_separator, action_hash);
    let valid_user_sig = std::ecdsa_secp256k1::verify_signature(
        user_pubkey_x,
        user_pubkey_y,
        user_signature,
        message_hash,
    );
    assert(valid_user_sig, "Invalid user signature on the signed message");

    // ===================================================================
    // PART 2: coinbase_attestation's transaction checks, unchanged
    // ===================================================================
    let unsigned_tx_hash = eip1559_tx_parser::create_unsigned_tx_hash(raw_transaction, tx_length);
    let tx_signature = eip1559_tx_parser::extract_signature_from_tx(raw_transaction);
    let mut attester_signature: [u8; 64] = [0; 64];
    for i in 0..64 {
        attester_signature[i] = tx_signature[i];
    }
    let valid_attester_sig = std::ecdsa_secp256k1::verify_signature(
        coinbase_attester_pubkey_x,
        coinbase_attester_pubkey_y,
        attester_signature,
        unsigned_tx_hash,
    );
    assert(valid_attester_sig, "Invalid TX signature");

    let derived_signer_address =
        derive_address_from_pubkey(coinbase_attester_pubkey_x, coinbase_attester_pubkey_y);
    let leaf_hash = keccak256(derived_signer_address, 20);
    let calculated_root = merkle::verify_merkle_proof(
        leaf_hash,
        coinbase_signer_leaf_index,
        coinbase_signer_merkle_proof,
        merkle_proof_depth,
    );
    assert(calculated_root == signer_list_merkle_root, "Signer not in valid list");

    let to_address = eip1559_tx_parser::extract_to_address(raw_transaction);
    assert(to_address == COINBASE_ATTESTER_CONTRACT, "TX sent to wrong contract");
    let calldata = eip1559_tx_parser::extract_calldata(raw_transaction);
    let mut selector: [u8; 4] = [0; 4];
    for i in 0..4 {
        selector[i] = calldata[i];
    }
    assert(selector == ATTEST_ACCOUNT_SELECTOR, "Invalid function selector");
    let calldata_address = eip1559_tx_parser::extract_address_from_calldata(calldata);
    assert(calldata_address == user_address, "Calldata address does not match user_address");

    // ===================================================================
    // PART 3: the genuine app said, at attested_at, that this wallet's
    //         Coinbase attestation was unrevoked -- for this request
    // ===================================================================
    check_client_data(
        client_data,
        CIRCUIT_TAG,
        user_address,
        attested_at,
        message_hash,
        scope,
    );
    let _counter = verify_app_attest(
        AppAttestInputs {
            ca_key: app_attest_ca_key,
            credential_tbs,
            credential_tbs_len,
            credential_sig,
            att_auth_data,
            att_auth_data_len,
            att_client_data_hash,
            assertion_auth_data,
            assertion_auth_data_len,
            assertion_sig,
        },
        app_attest_ca_key_hash,
        APP_ID,
        APP_ID_HASH,
        app_attest_production,
        client_data,
    );

    // ===================================================================
    // PART 4: one nullifier per wallet per scope, nothing to choose
    // ===================================================================
    verify_wallet_nullifier(user_address, CIRCUIT_TAG, scope, nullifier);
}
