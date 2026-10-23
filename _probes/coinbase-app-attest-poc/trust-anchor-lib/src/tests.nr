use crate::{leaf_keccak, leaf_poseidon2, node_keccak, node_poseidon2, root_keccak, root_poseidon2};

// A depth-2 tree of four distinct leaves, built the slow way, then every
// index is checked against the path the membership function walks.
fn hashes() -> [[u8; 32]; 4] {
    let mut out: [[u8; 32]; 4] = [[0; 32]; 4];
    for i in 0..4 {
        for j in 0..32 {
            out[i][j] = (i * 37 + j * 11 + 1) as u8;
        }
    }
    out
}

#[test]
fn keccak_every_index_reaches_the_root() {
    let k = hashes();
    let l = [leaf_keccak(1, k[0]), leaf_keccak(2, k[1]), leaf_keccak(2, k[2]), leaf_keccak(2, k[3])];
    let n0 = node_keccak(l[0], l[1]);
    let n1 = node_keccak(l[2], l[3]);
    let root = node_keccak(n0, n1);
    assert(root_keccak::<2>(l[0], 0, [l[1], n1]) == root);
    assert(root_keccak::<2>(l[1], 1, [l[0], n1]) == root);
    assert(root_keccak::<2>(l[2], 2, [l[3], n0]) == root);
    assert(root_keccak::<2>(l[3], 3, [l[2], n0]) == root);
    // Wrong index for the same path: another root.
    assert(root_keccak::<2>(l[0], 1, [l[1], n1]) != root);
}

#[test]
fn poseidon2_every_index_reaches_the_root() {
    let k = hashes();
    let l = [leaf_poseidon2(1, k[0]), leaf_poseidon2(2, k[1]), leaf_poseidon2(2, k[2]), leaf_poseidon2(2, k[3])];
    let n0 = node_poseidon2(l[0], l[1]);
    let n1 = node_poseidon2(l[2], l[3]);
    let root = node_poseidon2(n0, n1);
    assert(root_poseidon2::<2>(l[0], 0, [l[1], n1]) == root);
    assert(root_poseidon2::<2>(l[1], 1, [l[0], n1]) == root);
    assert(root_poseidon2::<2>(l[2], 2, [l[3], n0]) == root);
    assert(root_poseidon2::<2>(l[3], 3, [l[2], n0]) == root);
    assert(root_poseidon2::<2>(l[0], 1, [l[1], n1]) != root);
}

#[test]
fn kind_byte_separates_leaves() {
    let k = hashes();
    assert(leaf_keccak(1, k[0]) != leaf_keccak(2, k[0]));
    assert(leaf_poseidon2(1, k[0]) != leaf_poseidon2(2, k[0]));
}

#[test(should_fail_with = "Trust anchor index is outside the tree")]
fn keccak_index_past_the_tree_is_refused() {
    let k = hashes();
    let _ = root_keccak::<2>(leaf_keccak(1, k[0]), 4, [[0; 32]; 2]);
}

#[test(should_fail_with = "Trust anchor index is outside the tree")]
fn poseidon2_index_past_the_tree_is_refused() {
    let k = hashes();
    let _ = root_poseidon2::<2>(leaf_poseidon2(1, k[0]), 4, [0; 2]);
}
