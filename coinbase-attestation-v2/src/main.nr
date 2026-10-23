// coinbase_attestation v2 -- Coinbase KYC whose revocation is bound by a
// signed statement, from Apple App Attest or from the AI server.
//
// Built from the coinbase_app_attest_poc prototype (circuits commit
// b281485 / 33344e2). This package is named coinbase_attestation_v2 while v1
// still lives in ../coinbase-attestation; the circuit ID it serves is the
// canonical `coinbase_attestation`, and that is what its nullifier tag and
// clientData carry. README.md has the clientData spec, what the server signs,
// the public inputs and the measurements.
//
// WHY A SIGNED STATEMENT
//
// coinbase_attestation v1 proves Coinbase once sent attestAccount(wallet).
// That stays true after Coinbase revokes the attestation. So whoever builds
// the proof looks the EAS attestation up right before proving and, only if it
// is unrevoked, has a key the circuit trusts sign a statement saying so,
// bound to this wallet, this time and this request (decided 2026-10-23,
// .claude/agents/circuits-dev.md "Decisions").
//
// TWO SIGNERS, ONE CIRCUIT, AND THE PROOF DOES NOT SAY WHICH
//
//   app     The phone. Apple App Attest: Apple's root -> App Attest
//           intermediate -> credential certificate for our App ID -> an
//           assertion over the statement. Only Apple's ROOT key is pinned
//           (apple_root.nr); the intermediate is verified here, so Apple
//           rotating it needs nothing from us.
//   server  The AI server, which proves for SDK/MCP callers and has no
//           Secure Enclave. Its P-256 key (Cloud KMS) is pinned in
//           server_key.nr and signs SHA256(statement) directly.
//
// The signer kind is a PRIVATE byte. Both kinds end in the same P-256
// signature check; they differ only in where the key and the digest come
// from. A prover cannot pick their own key: the server key is a constant and
// the app key must come out of a certificate chain ending at Apple's root.
//
// The app-only checks sit inside `if kind == app { ... }`. Noir compiles that
// into constraints that hold only when the condition is true (they cost the
// same either way), so the server passes zeros for every App Attest input
// instead of a dummy certificate chain.
//
// WHAT THIS PROVES
//
//   1. The wallet signed the request: personal_sign over signal_hash, or an
//      EIP-712 action -- coinbase_libs::signed_message::signed_digest, the
//      same rule as giwa_attestation, with the same public-input order.
//   2. coinbase_attestation v1's checks, unchanged: an attestAccount(wallet)
//      transaction to Coinbase's attester, signed by a key whose address is
//      in the public signer Merkle root.
//   3. A statement (client_data.nr) naming this wallet, the public
//      attested_at, Coinbase's KYC schema and attester, revoked = 0, this
//      request's digest and this scope, signed by the app (production App
//      Attest environment only) or by the server.
//   4. Nullifier: keccak(keccak(wallet ++ CIRCUIT_TAG) ++ scope).
//
// THE NULLIFIER TAG IS keccak256("coinbase_attestation"), the canonical id,
// not this package's name: proofport-ai's computeWalletNullifier(address,
// circuitId) derives the tag from the id.

mod client_data;
mod apple_root;
mod server_key;

use keccak256::keccak256;
use coinbase_libs::eip1559_tx_parser;
use coinbase_libs::merkle;
use coinbase_libs::nullifier::verify_wallet_nullifier;
use coinbase_libs::signed_message::signed_digest;
use coinbase_libs::ethereum::{COINBASE_ATTESTER_CONTRACT, derive_address_from_pubkey};
use app_attest::{
    AppAttestChain, ASSERT_AUTH_DATA_MAX_LEN, ATT_AUTH_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN,
    INTERMEDIATE_TBS_MAX_LEN, app_attest_signing_key,
};
use client_data::{CLIENT_DATA_LEN, check_client_data};
use apple_root::APPLE_APP_ATTESTATION_ROOT_KEY;
use server_key::SERVER_KEY;

/// The private signer-kind byte. Any other value is refused.
global KIND_APP: u8 = 1;
global KIND_SERVER: u8 = 2;

/// Only production App Attest keys are accepted. Development (sandbox) keys
/// chain to the same Apple root and differ only in the AAGUID, so this is
/// the check that keeps them out. Apple: builds distributed through
/// TestFlight / the App Store use production regardless of the entitlement,
/// and a development build can be pointed at production by setting
/// com.apple.developer.devicecheck.appattest-environment to "production".
global APP_ATTEST_PRODUCTION: bool = true;

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
    client_data: [u8; CLIENT_DATA_LEN],
    signer_kind: u8,
    // P-256 r || s, s in low form: the App Attest assertion signature (app)
    // or the server's signature (server).
    statement_sig: [u8; 64],

    // App Attest chain. The server kind passes zeros for all of these.
    intermediate_tbs: [u8; INTERMEDIATE_TBS_MAX_LEN],
    intermediate_tbs_len: u32,
    intermediate_sig: [u8; 96],
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
    // PART 3: a trusted signer said, at attested_at, that this wallet's
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
    assert(
        (signer_kind == KIND_APP) | (signer_kind == KIND_SERVER),
        "Unknown statement signer kind",
    );
    let client_data_hash = sha256::digest(client_data);

    // Server: the pinned key over SHA256(clientData).
    let mut key_x: [u8; 32] = [0; 32];
    let mut key_y: [u8; 32] = [0; 32];
    for i in 0..32 {
        key_x[i] = SERVER_KEY[i];
        key_y[i] = SERVER_KEY[32 + i];
    }
    let mut digest = client_data_hash;

    // App: the credential key Apple's chain vouches for, over Apple's
    // assertion digest SHA256(SHA256(authenticatorData || SHA256(clientData))).
    if signer_kind == KIND_APP {
        let mut root_x: [u8; 48] = [0; 48];
        let mut root_y: [u8; 48] = [0; 48];
        for i in 0..48 {
            root_x[i] = APPLE_APP_ATTESTATION_ROOT_KEY[i];
            root_y[i] = APPLE_APP_ATTESTATION_ROOT_KEY[48 + i];
        }
        let (x, y, d, _counter) = app_attest_signing_key(
            AppAttestChain {
                intermediate_tbs,
                intermediate_tbs_len,
                intermediate_sig,
                credential_tbs,
                credential_tbs_len,
                credential_sig,
                att_auth_data,
                att_auth_data_len,
                att_client_data_hash,
                assertion_auth_data,
                assertion_auth_data_len,
            },
            root_x,
            root_y,
            APP_ID,
            APP_ID_HASH,
            APP_ATTEST_PRODUCTION,
            client_data_hash,
        );
        key_x = x;
        key_y = y;
        digest = d;
    }

    // One P-256 check for both kinds (a Barretenberg black box; it refuses a
    // high s, so the signer's s is put in low form before proving).
    assert(
        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, digest),
        "Statement signature is invalid",
    );

    // ===================================================================
    // PART 4: one nullifier per wallet per scope, nothing to choose
    // ===================================================================
    verify_wallet_nullifier(user_address, CIRCUIT_TAG, scope, nullifier);
}
