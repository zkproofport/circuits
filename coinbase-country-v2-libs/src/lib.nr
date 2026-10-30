// coinbase_country_attestation v2's checks other than who signed the
// statement, shared by every package serving that id. A package's main calls,
// in this order:
//   check_request_and_country_tx -> check_country_list
//   -> check_country_client_data -> <its signer check over client_data>
//   -> verify_wallet_nullifier(user_address, CIRCUIT_TAG, ...)
// It mirrors ../coinbase-v2-libs (coinbase_attestation v2) line for line; the
// differences are the attestCountry selector, the country read from the
// calldata, the country list (v1's rule, unchanged) and the statement's
// schema and country.

pub mod client_data;

use keccak256::keccak256;
use coinbase_libs::eip1559_tx_parser;
use coinbase_libs::merkle;
use coinbase_libs::signed_message::signed_digest;
use coinbase_libs::ethereum::{COINBASE_ATTESTER_CONTRACT, derive_address_from_pubkey};

/// attestCountry(uint256) -- 0x0a225248
global ATTEST_COUNTRY_SELECTOR: [u8; 4] = [0x0a, 0x22, 0x52, 0x48];

/// How many countries the public list holds.
pub global COUNTRY_LIST_MAX: u32 = 10;

/// keccak256("coinbase_country_attestation"): the canonical id, not a package
/// name. proofport-ai's computeWalletNullifier(address, circuitId) derives the
/// tag from the id, so every package serving the id uses this tag.
pub global CIRCUIT_TAG: [u8; 32] = [
    0x58, 0xbb, 0xa1, 0x74, 0x94, 0xbc, 0xf6, 0x8a, 0x76, 0xfb, 0x92, 0x16, 0x5b, 0x32, 0xfc, 0x19,
    0x8f, 0x30, 0x77, 0x54, 0x7e, 0x16, 0x9d, 0xf2, 0x57, 0x73, 0x2d, 0xd6, 0x9f, 0x8b, 0x03, 0xb4,
];

/// PARTS 1-2: the wallet signed this request, and Coinbase's attester sent
/// attestCountry(country ++ wallet) from a key in the public signer root.
/// Returns the digest the wallet signed (the statement must bind it) and the
/// attested country (two ASCII bytes).
pub fn check_request_and_country_tx(
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
) -> ([u8; 32], [u8; 2]) {
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
    // PART 2: coinbase_country_attestation v1's transaction checks, unchanged
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
    assert(selector == ATTEST_COUNTRY_SELECTOR, "Invalid function selector");
    // attestCountry(uint256): [selector(4)][zero(10)][country(2)][address(20)]
    let country_code: [u8; 2] = [calldata[14], calldata[15]];
    let calldata_address = eip1559_tx_parser::extract_address_from_calldata(calldata);
    assert(calldata_address == user_address, "Calldata address does not match user_address");

    (message_hash, country_code)
}

/// PART 3: the attested country is in the public list (inclusion) or not in
/// it (exclusion). v1's rule, with v1's messages: 1 to 10 entries, entries at
/// or past `country_list_length` ignored.
pub fn check_country_list(
    country_code: [u8; 2],
    country_list: [[u8; 2]; COUNTRY_LIST_MAX],
    country_list_length: u32,
    is_included: bool,
) {
    assert(country_list_length <= COUNTRY_LIST_MAX, "Country list length exceeds maximum");
    assert(country_list_length > 0, "Country list must not be empty");

    let mut found = false;
    for i in 0..COUNTRY_LIST_MAX {
        if i < country_list_length {
            if (country_list[i][0] == country_code[0]) & (country_list[i][1] == country_code[1]) {
                found = true;
            }
        }
    }

    if is_included {
        assert(found, "Country not in inclusion list");
    } else {
        assert(!found, "Country is in exclusion list");
    }
}
