// Membership of one trust anchor in a published set.
//
// A trust anchor is a key the verifier accepts as the origin of a "not
// revoked" statement: the Apple App Attestation CA key (app kind) or an AI
// server key (server kind). The set is a fixed-depth binary Merkle tree whose
// root is a public input, so keys can rotate by publishing a new root and the
// proof does not say which kind vouched.
//
//   leaf = H(kind_byte || key_hash32)
//   node = H(left || right)
//
// Two hash choices, measured side by side:
//   keccak256: leaf over the 33 bytes, node over 64 bytes, root as 32 bytes.
//   Poseidon2: leaf = Poseidon2([kind, hi128(key_hash), lo128(key_hash)]),
//              node = Poseidon2([left, right]), root as one Field.
// The 32-byte hash is split into two 128-bit halves because it does not fit
// the BN254 field.
//
// The leaf index is a private input; bit i chooses whether the running hash
// is the left (0) or right (1) child at level i. Indexes past the tree are
// refused so every leaf has exactly one index.

use keccak256::keccak256;
use poseidon::poseidon2::Poseidon2;

mod tests;

pub fn check_index<let DEPTH: u32>(index: u32) {
    assert(index < (1 << DEPTH), "Trust anchor index is outside the tree");
}

pub fn leaf_keccak(kind: u8, key_hash: [u8; 32]) -> [u8; 32] {
    let mut buf: [u8; 33] = [0; 33];
    buf[0] = kind;
    for i in 0..32 {
        buf[1 + i] = key_hash[i];
    }
    keccak256(buf, 33)
}

pub fn node_keccak(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut buf: [u8; 64] = [0; 64];
    for i in 0..32 {
        buf[i] = left[i];
        buf[32 + i] = right[i];
    }
    keccak256(buf, 64)
}

pub fn root_keccak<let DEPTH: u32>(leaf: [u8; 32], index: u32, path: [[u8; 32]; DEPTH]) -> [u8; 32] {
    check_index::<DEPTH>(index);
    let mut h = leaf;
    for i in 0..DEPTH {
        let is_right = ((index >> i) & 1) == 1;
        h = if is_right { node_keccak(path[i], h) } else { node_keccak(h, path[i]) };
    }
    h
}

/// Big-endian bytes [from, from + 16) as a Field (< 2^128).
fn half(bytes: [u8; 32], from: u32) -> Field {
    let mut acc: Field = 0;
    for i in 0..16 {
        acc = acc * 256 + bytes[from + i] as Field;
    }
    acc
}

pub fn leaf_poseidon2(kind: u8, key_hash: [u8; 32]) -> Field {
    Poseidon2::hash([kind as Field, half(key_hash, 0), half(key_hash, 16)], 3)
}

pub fn node_poseidon2(left: Field, right: Field) -> Field {
    Poseidon2::hash([left, right], 2)
}

pub fn root_poseidon2<let DEPTH: u32>(leaf: Field, index: u32, path: [Field; DEPTH]) -> Field {
    check_index::<DEPTH>(index);
    let mut h = leaf;
    for i in 0..DEPTH {
        let is_right = ((index >> i) & 1) == 1;
        h = if is_right { node_poseidon2(path[i], h) } else { node_poseidon2(h, path[i]) };
    }
    h
}
