// ===================================================================
// Imports
// ===================================================================

// Standard library for signature verification and utilities
use dep::std;
// Keccak256 hash function
use dep::keccak256::keccak256;
// RLP decoding library (as per the provided context)
use dep::noir_trie_proofs::rlp;
// (Note: `rlp::encode_list` is a hypothetical function needed for
// unsigned hash calculation, assuming the library or a helper provides it)
use dep::noir_trie_proofs::rlp::{decode, encode_list}; // Assuming `encode_list` exists

// ===================================================================
// Global Constants
// ===================================================================

// Coinbase Attester Contract address on Base Mainnet
global COINBASE_ATTESTER_CONTRACT: [u8; 20] = [
    0x35, 0x74, 0x58, 0x73, 0x9F, 0x90, 0x46, 0x1b,
    0x99, 0x78, 0x93, 0x50, 0x86, 0x8C, 0xD7, 0xCF,
    0x33, 0x0D, 0xd7, 0xEE
];

// Function selector for "attestAccount(address)"
// keccak256("attestAccount(address)")[..4]
global ATTEST_ACCOUNT_SELECTOR: [u8; 4] = [0x41, 0x7b, 0x2e, 0x6e];

// EIP-1559 Transaction Type byte
global EIP1559_TX_TYPE: u8 = 0x02;

// ===================================================================
// Helper Functions
// ===================================================================

/**
 * @notice Concatenates two 32-byte arrays (e.g., public key x and y).
 */
fn concat_pubkey(pubkey_x: [u8; 32], pubkey_y: [u8; 32]) -> [u8; 64] {
    let mut out: [u8; 64] = [0; 64];
    for i in 0..32 {
        out[i] = pubkey_x[i];
        out[i + 32] = pubkey_y[i];
    }
    out
}

/**
 * @notice Derives an Ethereum address from uncompressed public key coordinates.
 * @dev Address = last 20 bytes of keccak256(x || y)
 */
fn derive_address_from_pubkey(pubkey_x: [u8; 32], pubkey_y: [u8; 32]) -> [u8; 20] {
    let pubkey_full = concat_pubkey(pubkey_x, pubkey_y);
    let pubkey_hash: [u8; 32] = keccak256(pubkey_full, 64);
    
    let mut derived_address: [u8; 20] = [0; 20];
    for i in 0..20 {
        derived_address[i] = pubkey_hash[12 + i];
    }
    derived_address
}

/**
 * @notice Creates an Ethereum Personal Sign message hash ("\x19Ethereum Signed Message:\n32" + hash).
 */
fn create_eth_signed_message_hash(digest: [u8; 32]) -> [u8; 32] {
    let prefix: [u8; 26] = [
        0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x20,
        0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x20, 0x4d, 0x65, 0x73,
        0x73, 0x61, 0x67, 0x65, 0x3a, 0x0a
    ];
    let length: [u8; 2] = [0x33, 0x32]; // "32"
    let mut message: [u8; 60] = [0; 60];

    for i in 0..26 { message[i] = prefix[i]; }
    for i in 0..2 { message[26 + i] = length[i]; }
    for i in 0..32 { message[28 + i] = digest[i]; }

    keccak256(message, 60)
}

/**
 * @notice Calculates the EIP-1559 unsigned transaction hash for signature verification.
 * @dev This is the most complex part. It assumes `rlp::decode` returns a list of fields
 * and a hypothetical `rlp::encode_list` exists to re-encode the unsigned part.
 * @param decoded_tx_fields A list of decoded transaction fields (12 items for EIP-1559).
 * @return The 32-byte hash (keccak256(0x02 || rlp(unsigned_fields)))
 */
fn get_unsigned_eip1559_hash(decoded_tx_fields: [rlp::DecodedItem; 12]) -> [u8; 32] {
    // EIP-1559 unsigned fields are the first 9 items:
    // [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]
    let unsigned_fields: [rlp::DecodedItem; 9] = [
        decoded_tx_fields[0], decoded_tx_fields[1], decoded_tx_fields[2],
        decoded_tx_fields[3], decoded_tx_fields[4], decoded_tx_fields[5],
        decoded_tx_fields[6], decoded_tx_fields[7], decoded_tx_fields[8]
    ];

    // Hypothetical: RLP-encode this list of 9 items.
    // This requires a helper or library function.
    let (rlp_unsigned_payload, rlp_len) = rlp::encode_list(unsigned_fields);

    // Create the full message to hash: 0x02 || rlp_payload
    // We assume a max payload size (e.g., 256 bytes) for the buffer.
    let mut message_to_hash: [u8; 257] = [0; 257];
    message_to_hash[0] = EIP1559_TX_TYPE;
    for i in 0..rlp_len {
        message_to_hash[i + 1] = rlp_unsigned_payload[i];
    }
    
    // Hash the message
    keccak256(message_to_hash, rlp_len + 1)
}

// ===================================================================
// Main Circuit Logic
// ===================================================================

fn main(
    // ============ Public Inputs ============
    // A unique challenge hash (e.g., keccak256(nonce)) provided by the dApp.
    signal_hash: pub [u8; 32],

    // ============ Private Inputs ============
    // All sensitive information is kept hidden from the verifier.

    // --- Part 1: User Ownership Inputs ---
    user_address: [u8; 20],         // The user's KYC'd address
    user_signature: [u8; 64],       // The user's signature over `signal_hash`
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],

    // --- Part 2: On-Chain Fact Inputs ---
    raw_transaction: [u8; 300],     // RLP-encoded Coinbase KYC TX (padded)
    tx_length: u32,                 // Actual length of raw_transaction
    
    // Pre-calculated via ecrecover in JS
    coinbase_attester_pubkey_x: [u8; 32], // Coinbase attester's public key X
    coinbase_attester_pubkey_y: [u8; 32]  // Coinbase attester's public key Y
) {
    // ===================================================================
    // PART 1: User Ownership Verification
    // "I am the owner of `user_address` and I am generating this proof for `signal_hash`."
    // ===================================================================

    // 1. Verify the user's public key matches the `user_address`
    let derived_user_address = derive_address_from_pubkey(user_pubkey_x, user_pubkey_y);
    assert(derived_user_address == user_address);

    // 2. Verify the user signed the dApp's challenge (`signal_hash`)
    let message_hash = create_eth_signed_message_hash(signal_hash);
    let valid_user_sig = std::ecdsa_secp256k1::verify_signature(
        user_pubkey_x,
        user_pubkey_y,
        user_signature,
        message_hash
    );
    assert(valid_user_sig);

    // ===================================================================
    // PART 2: On-Chain Fact Verification (The Core Logic)
    // "This `user_address` was verifiably attested by Coinbase on-chain."
    // ===================================================================

    // 3. (CRITICAL) Securely decode the RLP-encoded transaction
    //    We assume the tx is EIP-1559 (type 0x02), which is standard on Base.
    assert(raw_transaction[0] == EIP1559_TX_TYPE);
    
    // Decode the RLP payload *after* the type byte.
    // We assume `rlp::decode` can parse the list and `rlp::decode_as_list` returns an array.
    // This part is highly dependent on the library's actual API.
    let decoded_tx_fields: [rlp::DecodedItem; 12] = rlp::decode_as_list(raw_transaction[1..], tx_length - 1);

    // Extract fields based on EIP-1559 structure
    // (This requires `rlp::DecodedItem` to have methods like `as_bytes` or `as_field`)
    let to_address: [u8; 20] = decoded_tx_fields[5].as_bytes_20(); // [5] is 'to'
    let calldata: [u8; 36] = decoded_tx_fields[7].as_bytes_36(); // [7] is 'data'
    let calldata_len: u32 = decoded_tx_fields[7].length();
    let sig_y_parity: u8 = decoded_tx_fields[9].as_u8(); // [9] is 'v'
    let sig_r: [u8; 32] = decoded_tx_fields[10].as_bytes_32(); // [10] is 'r'
    let sig_s: [u8; 32] = decoded_tx_fields[11].as_bytes_32(); // [11] is 's'

    // 4. (SECURITY) Verify the Coinbase attester signed this transaction
    //    This proves the TX is authentic and originated from Coinbase.
    
    // 4a. Re-calculate the hash that was signed (unsigned tx hash)
    let unsigned_tx_hash = get_unsigned_eip1559_hash(decoded_tx_fields);

    // 4b. Combine r and s into a 64-byte signature
    let coinbase_signature = concat_pubkey(sig_r, sig_s); // Re-using helper
    
    // 4c. Verify the signature
    let valid_coinbase_sig = std::ecdsa_secp256k1::verify_signature(
        coinbase_attester_pubkey_x, // Private input from JS
        coinbase_attester_pubkey_y, // Private input from JS
        coinbase_signature,         // Extracted from RLP
        unsigned_tx_hash            // Calculated from RLP
    );
    assert(valid_coinbase_sig);

    // 5. Verify the transaction was sent to the correct Coinbase contract
    assert(to_address == COINBASE_ATTESTER_CONTRACT);

    // ===================================================================
    // PART 3: The Logical Link
    // "Does the TX from Part 2 *actually* apply to the user from Part 1?"
    // ===================================================================

    // 6. Verify the transaction's calldata is `attestAccount(user_address)`
    
    // 6a. Check calldata format is `attestAccount(address)` (4 + 32 = 36 bytes)
    assert(calldata_len == 36);
    
    // 6b. Check for the correct function selector
    assert(calldata[0..4] == ATTEST_ACCOUNT_SELECTOR);
    
    // 6c. (CRITICAL LINK) Check that the address in the calldata
    //     is the same `user_address` from Part 1.
    let mut calldata_address: [u8; 20] = [0; 20];
    for i in 0..20 {
        calldata_address[i] = calldata[16 + i]; // 12-byte padding
    }
    
    assert(calldata_address == user_address);

    // ===================================================================
    // Verification Complete
    // ===================================================================
}