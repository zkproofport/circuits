// ZKProofport: Private Coinbase KYC Attestation Verifier (Advanced)
//
// This circuit proves ownership of a Coinbase KYC'd address without
// revealing the address, the transaction, or the attester's signature.
//
// It uses a hybrid verification model for performance and a
// Merkle tree for flexible signer validation.
//
// Key Improvements over Basic Circuit:
// - Complete privacy: user_address is hidden
// - Anti-replay: signal_hash prevents proof reuse
// - Flexible signer management: Merkle tree instead of hardcoded array
// - Hybrid verification: JavaScript ecrecover + circuit signature verification

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

/// Function selector for "attestAccount(address)"
/// 0x56feed5e
global ATTEST_ACCOUNT_SELECTOR: [u8; 4] = [0x56, 0xfe, 0xed, 0x5e];

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
    // PART 3: The Logical Link
    // "Does the *authentic* TX from Part 2 *actually* apply to the `user_address` from Part 1?"
    // ===================================================================

    // 6. Verify the transaction's contents (destination and data)
    let to_address = eip1559_tx_parser::extract_to_address(raw_transaction);
    assert(to_address == COINBASE_ATTESTER_CONTRACT, "TX sent to wrong contract");

    // 7. Verify calldata format
    let calldata = eip1559_tx_parser::extract_calldata(raw_transaction);

    // Check function selector
    let mut selector: [u8; 4] = [0; 4];
    for i in 0..4 {
        selector[i] = calldata[i];
    }
    assert(selector == ATTEST_ACCOUNT_SELECTOR, "Invalid function selector");

    // 8. (FINAL LINK) Verify the address in the calldata matches the user's address
    let calldata_address = eip1559_tx_parser::extract_address_from_calldata(calldata);

    assert(calldata_address == user_address, "Calldata address does not match user_address");

    // ===================================================================
    // If all assertions pass, the proof is valid!
    // ===================================================================
}
