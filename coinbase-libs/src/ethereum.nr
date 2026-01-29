use dep::keccak256::keccak256;

/// Coinbase Attester Contract address (the 'to' address)
/// 0x357458739F90461b99789350868CD7CF330Dd7EE
pub global COINBASE_ATTESTER_CONTRACT: [u8; 20] = [
    0x35, 0x74, 0x58, 0x73, 0x9F, 0x90, 0x46, 0x1b,
    0x99, 0x78, 0x93, 0x50, 0x86, 0x8C, 0xD7, 0xCF,
    0x33, 0x0D, 0xd7, 0xEE
];

/// Concatenates public key x and y coordinates
pub fn concat_pubkey(pubkey_x: [u8; 32], pubkey_y: [u8; 32]) -> [u8; 64] {
    let mut result: [u8; 64] = [0; 64];
    for i in 0..32 {
        result[i] = pubkey_x[i];
        result[i + 32] = pubkey_y[i];
    }
    result
}

/// Derives an Ethereum address from a public key
/// address = keccak256(pubkey)[12..32]
pub fn derive_address_from_pubkey(pubkey_x: [u8; 32], pubkey_y: [u8; 32]) -> [u8; 20] {
    let pubkey_full = concat_pubkey(pubkey_x, pubkey_y);
    let pubkey_hash: [u8; 32] = keccak256(pubkey_full, 64);
    let mut derived_address: [u8; 20] = [0; 20];
    for i in 0..20 {
        derived_address[i] = pubkey_hash[12 + i];
    }
    derived_address
}

/// Creates the standard "\x19Ethereum Signed Message:\n32" hash
/// Used for personal_sign verification
pub fn create_eth_signed_message_hash(digest: [u8; 32]) -> [u8; 32] {
    // Ethereum signed message prefix: "\x19Ethereum Signed Message:\n32"
    let prefix: [u8; 28] = [
        0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75,
        0x6d, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64,
        0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
        0x3a, 0x0a, 0x33, 0x32  // "\x19Ethereum Signed Message:\n32"
    ];

    let mut message: [u8; 60] = [0; 60]; // 28 + 32

    // Copy prefix
    for i in 0..28 {
        message[i] = prefix[i];
    }

    // Copy digest
    for i in 0..32 {
        message[28 + i] = digest[i];
    }

    keccak256(message, 60)
}
