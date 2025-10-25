use dep::ecrecover::ecrecover;

// Hardcoded Coinbase attestor address
global CB_ATTESTOR_ADDRESS: [u8; 20] = [
    53, 116, 88, 115, 159, 144, 70, 27,
    153, 120, 147, 80, 134, 140, 215, 207,
    51, 13, 215, 238
];

pub fn extract_address_from_calldata(calldata: [u8; 36]) -> Field {
    let mut addr: Field = 0;
    for i in 0..20 {
        let byte = calldata[i + 16];
        addr = addr * 256.into() + byte.into();
    }
    addr
}

fn main(
    calldata: [u8; 36],
    contract_address: pub [u8; 20],
    digest: [u8; 32],
    user_sig: [u8; 64],
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

     let user_addr = ecrecover(
        user_pubkey_x,
        user_pubkey_y,
        user_sig,
        digest,
    );

    // 3. Extract expected address from calldata
    let calldata_addr = extract_address_from_calldata(calldata);
    assert(calldata_addr == user_addr);

}