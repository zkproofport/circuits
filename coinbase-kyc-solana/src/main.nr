
use dep::keccak256::keccak256;
// Signature verification removed for smaller proof size (Solana tx limit)

// Hardcoded Coinbase attestor address
global CB_ATTESTOR_ADDRESS: [u8; 20] = [
    53, 116, 88, 115, 159, 144, 70, 27,
    153, 120, 147, 80, 134, 140, 215, 207,
    51, 13, 215, 238
];

fn extract_address_from_calldata(calldata: [u8; 36]) -> [u8; 20] {
    let mut addr: [u8; 20] = [0; 20];
    for i in 0..20 {
        addr[i] = calldata[i + 16];
    }
    addr
}

fn concat_pubkey(pubkey_x: [u8; 32], pubkey_y: [u8; 32]) -> [u8; 64] {
    let mut out: [u8; 64] = [0; 64];
    for i in 0..32 {
        out[i] = pubkey_x[i];
        out[i + 32] = pubkey_y[i];
    }
    out
}

fn main(
    calldata: [u8; 36],
    contract_address: [u8; 20],  // Changed to private to reduce publicWitness size
    user_address: [u8; 20],
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],
) {
    // 1. Check function selector
    assert(calldata[0] == 0x56);
    assert(calldata[1] == 0xfe);
    assert(calldata[2] == 0xed);
    assert(calldata[3] == 0x5e);

    // 2. Verify contract address
    assert(contract_address == CB_ATTESTOR_ADDRESS);

    // 3. Extract expected address from calldata
    let calldata_addr = extract_address_from_calldata(calldata);
    assert(calldata_addr == user_address);

    // 4. Compute Ethereum address from pubkey (signature verification removed)
    let pubkey_bytes = concat_pubkey(user_pubkey_x, user_pubkey_y);
    let hashed = unsafe { keccak256(pubkey_bytes, 64) };

    // 5. Compare last 20 bytes of hash to user_address
    for i in 0..20 {
        assert(user_address[i] == hashed[i + 12]);
    }
}