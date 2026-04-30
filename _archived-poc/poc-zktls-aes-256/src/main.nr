// PoC: AES-256 single block (Kakao TLS_AES_256_GCM_SHA384 base primitive)
// Goal: measure AES-256 gate count vs AES-128 (223K)
// Reference: NIST FIPS-197 Appendix C.3 test vector

use pluto_aes_gcm::aes::aes_256;

fn stream_to_block(s: [u8; 16]) -> [[u8; 4]; 4] {
    let mut b: [[u8; 4]; 4] = [[0; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            b[j][i] = s[i * 4 + j];
        }
    }
    b
}

fn block_to_stream(b: [[u8; 4]; 4]) -> [u8; 16] {
    let mut s: [u8; 16] = [0; 16];
    for i in 0..4 {
        for j in 0..4 {
            s[i * 4 + j] = b[j][i];
        }
    }
    s
}

fn main(
    plaintext: pub [u8; 16],
    key: pub [u8; 32],
    expected_ciphertext: pub [u8; 16],
) {
    let block = stream_to_block(plaintext);
    let ct_block = aes_256(block, key);
    let ct = block_to_stream(ct_block);
    for i in 0..16 {
        assert(ct[i] == expected_ciphertext[i]);
    }
}

#[test]
fn test_aes_256_nist() {
    let pt: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let ct: [u8; 16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ];
    main(pt, key, ct);
}
