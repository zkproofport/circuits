// PoC: smallest possible AES-128-GCM single block circuit
// Goal: measure gate count for one 16-byte block AES-GCM encrypt + tag
// Reference: Pluto Noir-AES-GCM (single block primitive)
// Why: TLS records use AES-GCM (TLS 1.2 + 1.3). Single block gates x N + tag overhead = realistic estimate

use pluto_aes_gcm::aes_gcm::aes_gcm;

fn main(
    key: pub [u8; 16],
    plaintext: pub [u8; 16],
    iv: pub [u8; 12],
    aad: pub [u8; 16],
    expected_ciphertext: pub [u8; 16],
) {
    let (ct, _tag) = aes_gcm(key, plaintext, iv, aad);
    assert(ct == expected_ciphertext);
}

#[test]
fn test_aes_gcm_single_block() {
    let key = [0x31; 16];
    let plaintext = [
        0x74, 0x65, 0x73, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30,
    ];
    let iv = [0x31; 12];
    let aad = [0; 16];
    let expected_ct = [
        0x29, 0x29, 0xd2, 0xbb, 0x1a, 0xe9, 0x48, 0x04, 0x40, 0x2b, 0x8e, 0x77, 0x6e, 0x0d, 0x33,
        0x56,
    ];
    let (ct, _tag) = aes_gcm(key, plaintext, iv, aad);
    assert(ct == expected_ct);
}
