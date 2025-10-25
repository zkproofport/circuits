// Coinbase KYC Attestation Zero-Knowledge Verifier
// Verifies Coinbase attestation without revealing private data

use dep::std;
use dep::keccak256::keccak256;

// Coinbase Attester address on Base Mainnet
global COINBASE_ATTESTER: [u8; 20] = [
    0x35, 0x74, 0x58, 0x73, 0x9F, 0x90, 0x46, 0x1b,
    0x99, 0x78, 0x93, 0x50, 0x86, 0x8C, 0xD7, 0xCF,
    0x33, 0x0D, 0xd7, 0xEE
];

// Concatenate public key coordinates
fn concat_pubkey(pubkey_x: [u8; 32], pubkey_y: [u8; 32]) -> [u8; 64] {
    let mut out: [u8; 64] = [0; 64];
    for i in 0..32 {
        out[i] = pubkey_x[i];
        out[i + 32] = pubkey_y[i];
    }
    out
}

// Extract 'to' address from transaction (EIP-1559)
fn extract_to_address(raw_tx: [u8; 300]) -> [u8; 20] {
    let mut to_address: [u8; 20] = [0; 20];
    for i in 0..20 {
        to_address[i] = raw_tx[23 + i];
    }
    to_address
}


// Extract recipient from transaction calldata
fn extract_recipient_from_calldata(raw_tx: [u8; 300]) -> [u8; 20] {
    let mut recipient: [u8; 20] = [0; 20];
    for i in 0..20 {
        recipient[i] = raw_tx[61 + i];
    }
    recipient
}

// Extract address from calldata (function selector + padding + address)
fn extract_address_from_calldata(calldata: [u8; 36]) -> [u8; 20] {
    let mut address: [u8; 20] = [0; 20];
    for i in 0..20 {
        address[i] = calldata[16 + i];
    }
    address
}


// Create Ethereum Personal Sign message hash
fn create_eth_signed_message_hash(digest: [u8; 32]) -> [u8; 32] {
    let prefix: [u8; 26] = [
        0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x20,
        0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x20, 0x4d, 0x65, 0x73,
        0x73, 0x61, 0x67, 0x65, 0x3a, 0x0a
    ];
    let length: [u8; 2] = [0x33, 0x32];
    let mut message: [u8; 60] = [0; 60];

    for i in 0..26 {
        message[i] = prefix[i];
    }
    for i in 0..2 {
        message[26 + i] = length[i];
    }
    for i in 0..32 {
        message[28 + i] = digest[i];
    }

    keccak256(message, 60)
}

fn main(
    // Public inputs (visible in proof)
    user_address: pub [u8; 20],
    tx_hash: pub [u8; 32],
    tx_length: pub u32,

    // Private inputs (hidden in proof)
    raw_transaction: [u8; 300],
    calldata: [u8; 36],
    user_signature: [u8; 64],
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],
) {
    // PART 1: User Authorization

    // Verify calldata contains user address
    let calldata_address = extract_address_from_calldata(calldata);
    assert(calldata_address == user_address);

    // Derive address from public key
    let pubkey_full = concat_pubkey(user_pubkey_x, user_pubkey_y);
    let pubkey_hash: [u8; 32] = keccak256(pubkey_full, 64);
    let mut derived_address: [u8; 20] = [0; 20];
    for i in 0..20 {
        derived_address[i] = pubkey_hash[12 + i];
    }
    assert(derived_address == user_address);

    // Verify user signature on calldata
    let calldata_digest: [u8; 32] = keccak256(calldata, 36);
    let message_hash = create_eth_signed_message_hash(calldata_digest);
    let signature_valid = std::ecdsa_secp256k1::verify_signature(
        user_pubkey_x,
        user_pubkey_y,
        user_signature,
        message_hash
    );
    assert(signature_valid);

    // PART 2: Transaction Verification

    // Verify transaction hash
    let computed_tx_hash: [u8; 32] = keccak256(raw_transaction, tx_length);
    assert(computed_tx_hash == tx_hash);

    // Verify sent to Coinbase Attester
    let to_address = extract_to_address(raw_transaction);
    assert(to_address == COINBASE_ATTESTER);

    // Verify transaction recipient
    let recipient = extract_recipient_from_calldata(raw_transaction);
    assert(recipient == user_address);
}

