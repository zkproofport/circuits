// AES-256 and GCM for measuring their in-circuit cost (probe, not a product
// circuit). Follows FIPS-197 and NIST SP 800-38D. Byte tables are read with
// witness indices, which UltraHonk turns into lookup tables.

global SBOX: [u8; 256] = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22];
global MUL2: [u8; 256] = [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 242, 244, 246, 248, 250, 252, 254, 27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5, 59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37, 91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69, 123, 121, 127, 125, 115, 113, 119, 117, 107, 105, 111, 109, 99, 97, 103, 101, 155, 153, 159, 157, 147, 145, 151, 149, 139, 137, 143, 141, 131, 129, 135, 133, 187, 185, 191, 189, 179, 177, 183, 181, 171, 169, 175, 173, 163, 161, 167, 165, 219, 217, 223, 221, 211, 209, 215, 213, 203, 201, 207, 205, 195, 193, 199, 197, 251, 249, 255, 253, 243, 241, 247, 245, 235, 233, 239, 237, 227, 225, 231, 229];
global MUL3: [u8; 256] = [0, 3, 6, 5, 12, 15, 10, 9, 24, 27, 30, 29, 20, 23, 18, 17, 48, 51, 54, 53, 60, 63, 58, 57, 40, 43, 46, 45, 36, 39, 34, 33, 96, 99, 102, 101, 108, 111, 106, 105, 120, 123, 126, 125, 116, 119, 114, 113, 80, 83, 86, 85, 92, 95, 90, 89, 72, 75, 78, 77, 68, 71, 66, 65, 192, 195, 198, 197, 204, 207, 202, 201, 216, 219, 222, 221, 212, 215, 210, 209, 240, 243, 246, 245, 252, 255, 250, 249, 232, 235, 238, 237, 228, 231, 226, 225, 160, 163, 166, 165, 172, 175, 170, 169, 184, 187, 190, 189, 180, 183, 178, 177, 144, 147, 150, 149, 156, 159, 154, 153, 136, 139, 142, 141, 132, 135, 130, 129, 155, 152, 157, 158, 151, 148, 145, 146, 131, 128, 133, 134, 143, 140, 137, 138, 171, 168, 173, 174, 167, 164, 161, 162, 179, 176, 181, 182, 191, 188, 185, 186, 251, 248, 253, 254, 247, 244, 241, 242, 227, 224, 229, 230, 239, 236, 233, 234, 203, 200, 205, 206, 199, 196, 193, 194, 211, 208, 213, 214, 223, 220, 217, 218, 91, 88, 93, 94, 87, 84, 81, 82, 67, 64, 69, 70, 79, 76, 73, 74, 107, 104, 109, 110, 103, 100, 97, 98, 115, 112, 117, 118, 127, 124, 121, 122, 59, 56, 61, 62, 55, 52, 49, 50, 35, 32, 37, 38, 47, 44, 41, 42, 11, 8, 13, 14, 7, 4, 1, 2, 19, 16, 21, 22, 31, 28, 25, 26];
global RCON: [u8; 8] = [0, 1, 2, 4, 8, 16, 32, 64];

fn sub_word(w: [u8; 4]) -> [u8; 4] {
    [SBOX[w[0] as u32], SBOX[w[1] as u32], SBOX[w[2] as u32], SBOX[w[3] as u32]]
}

/// 15 round keys of 16 bytes, as 240 bytes.
pub fn expand_key(key: [u8; 32]) -> [u8; 240] {
    let mut w = [0 as u8; 240];
    for i in 0..32 { w[i] = key[i]; }
    for i in 8..60 {
        let mut t = [w[4 * (i - 1)], w[4 * (i - 1) + 1], w[4 * (i - 1) + 2], w[4 * (i - 1) + 3]];
        if i % 8 == 0 {
            t = sub_word([t[1], t[2], t[3], t[0]]);
            t[0] = t[0] ^ RCON[i / 8];
        } else if i % 8 == 4 {
            t = sub_word(t);
        }
        for j in 0..4 { w[4 * i + j] = w[4 * (i - 8) + j] ^ t[j]; }
    }
    w
}

pub fn encrypt_block(input: [u8; 16], rk: [u8; 240]) -> [u8; 16] {
    let mut s = [0 as u8; 16];
    for i in 0..16 { s[i] = input[i] ^ rk[i]; }
    for round in 1..15 {
        let mut t = [0 as u8; 16];
        // SubBytes + ShiftRows: state byte (column c, row r) sits at 4c + r.
        for c in 0..4 {
            for r in 0..4 {
                t[4 * c + r] = SBOX[s[4 * ((c + r) % 4) + r] as u32];
            }
        }
        if round != 14 {
            for c in 0..4 {
                let a0 = t[4 * c]; let a1 = t[4 * c + 1]; let a2 = t[4 * c + 2]; let a3 = t[4 * c + 3];
                t[4 * c] = MUL2[a0 as u32] ^ MUL3[a1 as u32] ^ a2 ^ a3;
                t[4 * c + 1] = a0 ^ MUL2[a1 as u32] ^ MUL3[a2 as u32] ^ a3;
                t[4 * c + 2] = a0 ^ a1 ^ MUL2[a2 as u32] ^ MUL3[a3 as u32];
                t[4 * c + 3] = MUL3[a0 as u32] ^ a1 ^ a2 ^ MUL2[a3 as u32];
            }
        }
        for i in 0..16 { s[i] = t[i] ^ rk[16 * round + i]; }
    }
    s
}

fn counter_block(iv: [u8; 12], counter: u32) -> [u8; 16] {
    let mut b = [0 as u8; 16];
    for i in 0..12 { b[i] = iv[i]; }
    b[12] = (counter >> 24) as u8; b[13] = (counter >> 16) as u8; b[14] = (counter >> 8) as u8; b[15] = counter as u8;
    b
}

/// GCM's counter mode for the data: blocks use counters 2, 3, ... (J0 = iv || 1).
pub fn ctr_decrypt<let N: u32>(rk: [u8; 240], iv: [u8; 12], ct: [u8; N]) -> [u8; N] {
    assert(N % 16 == 0);
    let mut pt = [0 as u8; N];
    for b in 0..N / 16 {
        let ks = encrypt_block(counter_block(iv, b + 2), rk);
        for i in 0..16 { pt[16 * b + i] = ct[16 * b + i] ^ ks[i]; }
    }
    pt
}

fn to_u128(b: [u8; 16]) -> u128 {
    let mut x: u128 = 0;
    for i in 0..16 { x = x * 256 + b[i] as u128; }
    x
}

global R: u128 = 0xe1000000000000000000000000000000;

/// Multiplication in GF(2^128), SP 800-38D algorithm 1, bit by bit.
pub fn gf_mul(x: u128, y: u128) -> u128 {
    let mut z: u128 = 0;
    let mut v = y;
    for i in 0..128 {
        if (x >> (127 - i)) & 1 == 1 { z = z ^ v; }
        let lsb = v & 1;
        v = v >> 1;
        if lsb == 1 { v = v ^ R; }
    }
    z
}

/// Decrypts and checks the tag. No additional authenticated data.
pub fn gcm_decrypt<let N: u32>(key: [u8; 32], iv: [u8; 12], ct: [u8; N], tag: [u8; 16]) -> [u8; N] {
    let rk = expand_key(key);
    let h = to_u128(encrypt_block([0; 16], rk));
    let mut y: u128 = 0;
    for b in 0..N / 16 {
        let mut blk = [0 as u8; 16];
        for i in 0..16 { blk[i] = ct[16 * b + i]; }
        y = gf_mul(y ^ to_u128(blk), h);
    }
    y = gf_mul(y ^ ((N as u128) * 8), h); // len(A) = 0 || len(C) in bits
    let t = to_u128(encrypt_block(counter_block(iv, 1), rk)) ^ y;
    assert(t == to_u128(tag), "GCM tag mismatch");
    ctr_decrypt(rk, iv, ct)
}

/// Packs bytes into fields, 31 per field, so a probe can expose its output
/// cheaply and the compiler cannot drop the decryption.
pub fn pack<let N: u32, let M: u32>(b: [u8; N]) -> [Field; M] {
    let mut out = [0; M];
    for i in 0..N { out[i / 31] = out[i / 31] * 256 + b[i] as Field; }
    out
}

// ---- Several fields under one key and one IV, the identity-verification
// result format this probe measures: each field is AES-256-GCM with the same
// key and IV and the key itself as additional authenticated data, so the key
// stream is shared and only the GHASH runs per field.

pub struct Session {
    rk: [u8; 240],
    h: u128,
    tag_mask: u128,
    iv: [u8; 12],
    aad: [u8; 32],
}

pub fn session(key: [u8; 32], iv: [u8; 12]) -> Session {
    let rk = expand_key(key);
    Session {
        rk,
        h: to_u128(encrypt_block([0; 16], rk)),
        tag_mask: to_u128(encrypt_block(counter_block(iv, 1), rk)),
        iv,
        aad: key,
    }
}

/// Key stream for `B` blocks, counters 2.. as GCM uses for data.
pub fn keystream<let B: u32>(s: Session) -> [u8; B * 16] {
    let mut ks = [0 as u8; B * 16];
    for b in 0..B {
        let blk = encrypt_block(counter_block(s.iv, b + 2), s.rk);
        for i in 0..16 { ks[16 * b + i] = blk[i]; }
    }
    ks
}

fn block_at<let N: u32>(data: [u8; N], b: u32) -> u128 {
    let mut blk = [0 as u8; 16];
    for i in 0..16 { if 16 * b + i < N { blk[i] = data[16 * b + i]; } }
    to_u128(blk)
}

/// One field of exactly N bytes (N need not be a multiple of 16): checks its
/// tag, returns its plaintext. `ks` must cover N bytes.
pub fn open_field<let N: u32, let K: u32>(s: Session, ks: [u8; K], ct: [u8; N], tag: [u8; 16]) -> [u8; N] {
    let mut y: u128 = 0;
    y = gf_mul(y ^ block_at(s.aad, 0), s.h);
    y = gf_mul(y ^ block_at(s.aad, 1), s.h);
    for b in 0..(N + 15) / 16 { y = gf_mul(y ^ block_at(ct, b), s.h); }
    let lens: u128 = ((32 * 8) as u128) * 0x10000000000000000 + (N as u128) * 8;
    y = gf_mul(y ^ lens, s.h);
    assert((y ^ s.tag_mask) == to_u128(tag), "GCM tag mismatch");
    let mut pt = [0 as u8; N];
    for i in 0..N { pt[i] = ct[i] ^ ks[i]; }
    pt
}
