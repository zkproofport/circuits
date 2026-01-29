// Coinbase Country Attestation Circuit: Private Country Verification
//
// This circuit proves a user has a Coinbase-attested country code without
// revealing the address, the transaction, or the attester's signature.
// It supports checking against a country list in inclusion or exclusion mode.
//
// Reuses the same hybrid verification model as coinbase-attestation:
// - Part 1: User ownership (identical)
// - Part 2: On-chain TX verification (identical)
// - Part 3: Country extraction + list check (new)

use dep::std;
use dep::keccak256::keccak256;
use dep::coinbase_libs::eip1559_tx_parser;
use dep::coinbase_libs::merkle;
use dep::coinbase_libs::ethereum::{
    COINBASE_ATTESTER_CONTRACT,
    derive_address_from_pubkey,
    create_eth_signed_message_hash,
};

// Global Constants

/// Function selector for "attestCountry(uint256)"
/// 0x0a225248
global ATTEST_COUNTRY_SELECTOR: [u8; 4] = [0x0a, 0x22, 0x52, 0x48];

// ===================================================================
// Main Circuit Logic
// ===================================================================

fn main(
    // ============ Public Inputs ============
    // (Visible to the Verifier)

    // Anti-replay challenge from the dApp
    signal_hash: pub [u8; 32],

    // The root hash of the dApp's *current* list of valid Coinbase signers
    signer_list_merkle_root: pub [u8; 32],

    // Country list for inclusion/exclusion check (up to 10 ISO 3166-1 alpha-2 codes)
    country_list: pub [[u8; 2]; 10],
    country_list_length: pub u32,
    is_included: pub bool,

    // ============ Private Inputs ============
    // (Provided by the User/Prover, kept hidden)

    // --- Part 1: User Ownership Inputs ---
    user_address: [u8; 20],
    user_signature: [u8; 64],  // r + s (without v)
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],

    // --- Part 2: On-Chain Fact Inputs ---
    // Padded RLP-encoded attestation TX
    raw_transaction: [u8; 300],
    tx_length: u32,

    // Pre-calculated by JS ecrecover (Hybrid model)
    coinbase_attester_pubkey_x: [u8; 32],
    coinbase_attester_pubkey_y: [u8; 32],

    // Merkle proof inputs (for signer verification)
    coinbase_signer_merkle_proof: [[u8; 32]; 8],  // Max depth 8 (supports up to 256 signers)
    coinbase_signer_leaf_index: u32,
    merkle_proof_depth: u32,
) {
    // ===================================================================
    // PART 1: User Ownership Verification
    // "I am the owner of `user_address` and I am proving this for `signal_hash`."
    // ===================================================================

    // 1. Verify user's public key matches their address
    let derived_user_address = derive_address_from_pubkey(user_pubkey_x, user_pubkey_y);
    assert(derived_user_address == user_address, "User pubkey does not match address");

    // 2. Verify user signed the dApp's challenge
    let message_hash = create_eth_signed_message_hash(signal_hash);
    let valid_user_sig = std::ecdsa_secp256k1::verify_signature(
        user_pubkey_x,
        user_pubkey_y,
        user_signature,
        message_hash
    );
    assert(valid_user_sig, "Invalid user signature on signal_hash");

    // ===================================================================
    // PART 2: On-Chain Fact Verification (The Hybrid Model)
    // "The `raw_transaction` is authentic and was signed by a *valid* Coinbase signer."
    // ===================================================================

    // 3. Securely decode the RLP transaction
    //    Note: EIP-1559 only - Coinbase attestations use Type 0x02 transactions
    let unsigned_tx_hash = eip1559_tx_parser::create_unsigned_tx_hash(raw_transaction, tx_length);

    // 4. (CRITICAL) Verify the signature *before* trusting the pubkey
    //    This checks: "Does the provided pubkey match the signature on this TX?"
    //    Note: The signature is embedded in raw_transaction, we extract it using RLP
    let tx_signature = eip1559_tx_parser::extract_signature_from_tx(raw_transaction);

    // Extract r, s from signature (v is at the end)
    let mut signature_r: [u8; 32] = [0; 32];
    let mut signature_s: [u8; 32] = [0; 32];
    for i in 0..32 {
        signature_r[i] = tx_signature[i];
        signature_s[i] = tx_signature[32 + i];
    }

    // Combine r and s for verify_signature
    let mut coinbase_signature: [u8; 64] = [0; 64];
    for i in 0..32 {
        coinbase_signature[i] = signature_r[i];
        coinbase_signature[32 + i] = signature_s[i];
    }

    let valid_coinbase_sig = std::ecdsa_secp256k1::verify_signature(
        coinbase_attester_pubkey_x,  // Private input from JS
        coinbase_attester_pubkey_y,  // Private input from JS
        coinbase_signature,          // Extracted from RLP
        unsigned_tx_hash
    );
    assert(valid_coinbase_sig, "Invalid TX signature");

    // 5. (CRITICAL) Verify the signer is in the valid list
    //    This checks: "Is this pubkey *authorized* by the dApp?"

    // 5a. Derive the signer's address from the pubkey
    let derived_signer_address = derive_address_from_pubkey(
        coinbase_attester_pubkey_x,
        coinbase_attester_pubkey_y
    );

    // 5b. Create the leaf hash for the Merkle tree
    let leaf_hash = keccak256(derived_signer_address, 20);

    // 5c. Verify the leaf against the public Merkle root
    let calculated_root = merkle::verify_merkle_proof(
        leaf_hash,
        coinbase_signer_leaf_index,
        coinbase_signer_merkle_proof,
        merkle_proof_depth
    );

    assert(calculated_root == signer_list_merkle_root, "Signer not in valid list");

    // ===================================================================
    // PART 3: The Logical Link + Country Verification
    // "Does the authentic TX from Part 2 attest a country for user_address,
    //  and is that country in/not-in the provided list?"
    // ===================================================================

    // 6. Verify the transaction target is the Coinbase Attester contract
    let to_address = eip1559_tx_parser::extract_to_address(raw_transaction);
    assert(to_address == COINBASE_ATTESTER_CONTRACT, "TX sent to wrong contract");

    // 7. Verify calldata function selector
    let calldata = eip1559_tx_parser::extract_calldata(raw_transaction);
    let mut selector: [u8; 4] = [0; 4];
    for i in 0..4 {
        selector[i] = calldata[i];
    }
    assert(selector == ATTEST_COUNTRY_SELECTOR, "Invalid function selector");

    // 8. Extract country code from calldata
    //    attestCountry(uint256) encodes: [selector(4)][zero(10)][country(2)][address(20)]
    //    Country bytes are at calldata[14] and calldata[15]
    let country_code: [u8; 2] = [calldata[14], calldata[15]];

    // 9. Verify the address in calldata matches user_address
    //    Address is at calldata[16..36] -- same position as attestAccount
    let calldata_address = eip1559_tx_parser::extract_address_from_calldata(calldata);
    assert(calldata_address == user_address, "Calldata address does not match user_address");

    // 10. Country list verification
    assert(country_list_length <= 10, "Country list length exceeds maximum");
    assert(country_list_length > 0, "Country list must not be empty");

    let mut found = false;
    for i in 0..10 {
        if (i as u32) < country_list_length {
            if (country_list[i][0] == country_code[0]) & (country_list[i][1] == country_code[1]) {
                found = true;
            }
        }
    }

    if is_included {
        // Inclusion mode: country MUST be in the list
        assert(found, "Country not in inclusion list");
    } else {
        // Exclusion mode: country must NOT be in the list
        assert(!found, "Country is in exclusion list");
    }

    // ===================================================================
    // If all assertions pass, the proof is valid!
    // ===================================================================
}
