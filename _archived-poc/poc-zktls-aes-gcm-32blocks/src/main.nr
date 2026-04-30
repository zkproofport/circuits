// PoC: AES-128-GCM 32 blocks - DIFFERENT plaintext each block
// Goal: defeat compiler CSE optimization, get true multi-block gate count

use pluto_aes_gcm::aes_gcm::aes_gcm;

global N_BLOCKS: u32 = 32;

fn main(
    key: pub [u8; 16],
    plaintexts: pub [[u8; 16]; N_BLOCKS],
    iv: pub [u8; 12],
    aad: pub [u8; 16],
    // Public commitment to result (XOR accumulator) - forces use of all ct
    expected_acc: pub [u8; 16],
) {
    let mut acc: [u8; 16] = [0; 16];
    for i in 0..N_BLOCKS {
        let (ct, _tag) = aes_gcm(key, plaintexts[i], iv, aad);
        for j in 0..16 {
            acc[j] = acc[j] ^ ct[j];
        }
    }
    for j in 0..16 {
        assert(acc[j] == expected_acc[j]);
    }
}

#[test]
fn test_32_blocks_distinct() {
    let key = [0x31; 16];
    let iv = [0x31; 12];
    let aad = [0; 16];

    // Each block: different first byte (i), rest same
    let mut plaintexts: [[u8; 16]; N_BLOCKS] = [[0; 16]; N_BLOCKS];
    for i in 0..N_BLOCKS {
        plaintexts[i][0] = i as u8;
        plaintexts[i][1] = 0x65;
        plaintexts[i][2] = 0x73;
        plaintexts[i][3] = 0x74;
    }

    // Compute expected XOR accumulator from all 32 ciphertexts
    let mut acc: [u8; 16] = [0; 16];
    for i in 0..N_BLOCKS {
        let (ct, _tag) = aes_gcm(key, plaintexts[i], iv, aad);
        for j in 0..16 {
            acc[j] = acc[j] ^ ct[j];
        }
    }

    main(key, plaintexts, iv, aad, acc);
}
