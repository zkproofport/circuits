// PROTOTYPE -- Coinbase KYC proven against a published snapshot of the
// verified-address set. Not a canonical circuit; no verifier is deployed.
//
// WHY A SNAPSHOT
//
// "Not revoked" cannot be shown by handing over a transaction: there is no
// transaction for something that did not happen. It has to be read from
// current state, and proving EAS storage in-circuit costs ~97k gates per trie
// level, ~1.2M in all (coinbase_eas_storage_poc). Here the state is read
// OUTSIDE the circuit, by a rule anyone can rerun
// (scripts/coinbase-snapshot/build-snapshot.js): at a fixed Base block, every
// address holding an unrevoked, unexpired Coinbase KYC attestation, sorted,
// hashed into a Poseidon tree. The circuit proves membership in that tree.
//
// WHAT THIS PROVES
//
//   1. The wallet signed the request -- personal_sign over signal_hash, or an
//      EIP-712 action -- exactly as giwa_attestation does.
//   2. Poseidon(wallet address) is a leaf of the tree whose root is the public
//      `snapshot_root`.
//   3. One nullifier per wallet per scope.
//
// WHAT IS LEFT TO THE VERIFIER
//
// Accepting `snapshot_root` only if it is a recently published root
// (config.json `acceptedRoots`). An old root is how a revoked wallet would get
// through, so that check is the revocation check.

use dep::std;
use dep::poseidon::poseidon::bn254::{hash_1, hash_2};
use dep::coinbase_libs::nullifier::verify_wallet_nullifier;
use dep::coinbase_libs::signed_message::signed_digest;
use dep::coinbase_libs::ethereum::derive_address_from_pubkey;

/// Must equal config.json `treeDepth`.
global TREE_DEPTH: u32 = 20;

/// keccak256("coinbase_snapshot_poc"), compiled in.
global CIRCUIT_TAG: [u8; 32] = [
    0x9b, 0xcc, 0x09, 0x62, 0x2c, 0x33, 0x8e, 0xed, 0x2f, 0xf0, 0xc9, 0x71, 0x07, 0x1d, 0xa4, 0x77,
    0x60, 0x0e, 0xe3, 0x43, 0x3e, 0xf0, 0xa7, 0xc5, 0x9c, 0x3a, 0x5a, 0xc4, 0x60, 0xe8, 0xa6, 0x29,
];

fn address_field(address: [u8; 20]) -> Field {
    let mut acc: Field = 0;
    for i in 0..20 {
        acc = acc * 256 + address[i] as Field;
    }
    acc
}

/// Root of the tree that holds `leaf` at the position `bits` spell (bit d = 1
/// when the node at depth d is a right child), given the siblings bottom-up.
fn root_from_path(leaf: Field, siblings: [Field; TREE_DEPTH], bits: [u1; TREE_DEPTH]) -> Field {
    let mut node = leaf;
    for d in 0..TREE_DEPTH {
        node = if bits[d] == 1 {
            hash_2([siblings[d], node])
        } else {
            hash_2([node, siblings[d]])
        };
    }
    node
}

fn main(
    // ============ Public Inputs ============
    signal_hash: pub [u8; 32],
    domain_separator: pub [u8; 32],
    action_hash: pub [u8; 32],
    snapshot_root: pub Field,
    scope: pub [u8; 32],
    nullifier: pub [u8; 32],

    // ============ Private Inputs ============
    user_address: [u8; 20],
    user_signature: [u8; 64],
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],
    path_siblings: [Field; TREE_DEPTH],
    path_bits: [u1; TREE_DEPTH],
) {
    // PART 1: this wallet signed this request.
    let derived = derive_address_from_pubkey(user_pubkey_x, user_pubkey_y);
    assert(derived == user_address, "User pubkey does not match address");
    let digest = signed_digest(signal_hash, domain_separator, action_hash);
    assert(
        std::ecdsa_secp256k1::verify_signature(user_pubkey_x, user_pubkey_y, user_signature, digest),
        "Invalid user signature on the signed message",
    );

    // PART 2: that wallet is in the published snapshot.
    let leaf = hash_1([address_field(user_address)]);
    assert(root_from_path(leaf, path_siblings, path_bits) == snapshot_root, "Wallet is not in the snapshot");

    // PART 3: one nullifier per wallet per scope.
    verify_wallet_nullifier(user_address, CIRCUIT_TAG, scope, nullifier);
}

#[test]
fn poseidon_matches_the_tree_builder() {
    // circom BN254 vectors; scripts/coinbase-snapshot/tree.js uses poseidon-lite,
    // which prints these for poseidon1([1]) and poseidon2([1, 2]).
    assert(hash_1([1]) == 0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133);
    assert(hash_2([1, 2]) == 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a);
}

#[test]
fn the_address_is_read_big_endian() {
    let mut a: [u8; 20] = [0; 20];
    a[19] = 0x01;
    a[18] = 0x02;
    assert(address_field(a) == 0x0201);
}

#[test]
fn a_right_child_hashes_on_the_right() {
    // Guards the bit convention: swapping the branch would still compile.
    let mut sib: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    sib[0] = 7;
    let mut left: [u1; TREE_DEPTH] = [0; TREE_DEPTH];
    let mut right = left;
    right[0] = 1;
    let l = root_from_path(5, sib, left);
    let r = root_from_path(5, sib, right);
    assert(l != r);
    let mut expect_r = hash_2([7, 5]);
    for _ in 1..TREE_DEPTH {
        expect_r = hash_2([expect_r, 0]);
    }
    assert(r == expect_r);
}
