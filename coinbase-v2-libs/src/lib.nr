// coinbase_attestation v2's checks other than who signed the statement,
// shared by every package serving that id (coinbase-attestation-v2: iPhone App
// Attest or the AI server; coinbase-attestation-v2-android: Android key
// attestation). A package's main calls, in this order:
//   check_request_and_tx -> check_client_data -> <its signer check over
//   client_data> -> verify_wallet_nullifier(user_address, CIRCUIT_TAG, ...)
// The order is coinbase-attestation-v2's before this library existed, so its
// constraint system (and its deployed verifiers' vk) did not change.

pub mod client_data;

use keccak256::keccak256;
use coinbase_libs::eip1559_tx_parser;
use coinbase_libs::merkle;
use coinbase_libs::signed_message::signed_digest;
use coinbase_libs::ethereum::{COINBASE_ATTESTER_CONTRACT, derive_address_from_pubkey};

/// attestAccount(address) -- 0x56feed5e
global ATTEST_ACCOUNT_SELECTOR: [u8; 4] = [0x56, 0xfe, 0xed, 0x5e];

/// keccak256("coinbase_attestation"): the canonical id, not a package name.
/// proofport-ai's computeWalletNullifier(address, circuitId) derives the tag
/// from the id, so every package serving the id uses this tag.
pub global CIRCUIT_TAG: [u8; 32] = [
    0x16, 0x3f, 0xeb, 0x85, 0xbf, 0xfe, 0x62, 0x69, 0x88, 0x19, 0x7d, 0x1c, 0x5f, 0x0b, 0x70, 0xdc,
    0x10, 0xf5, 0x93, 0xd7, 0x08, 0xab, 0x0e, 0xfb, 0xcd, 0xfa, 0x06, 0x81, 0x4d, 0x28, 0x6b, 0xe2,
];

/// PARTS 1-2: the wallet signed this request, and Coinbase's attester sent
/// attestAccount(wallet) from a key in the public signer root. Returns the
/// digest the wallet signed (the statement must bind it).
pub fn check_request_and_tx(
    signal_hash: [u8; 32],
    domain_separator: [u8; 32],
    action_hash: [u8; 32],
    signer_list_merkle_root: [u8; 32],
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
) -> [u8; 32] {
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

    message_hash
}
