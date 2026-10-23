// Fixture helper, not a probe: computes a depth-2 Poseidon2 trust-anchor tree
// so the fixture generator does not need its own Poseidon2. Unused slots are
// the Field 0, which no leaf hash can equal in practice.
//
// Output: [leaf0, leaf1, leaf2, leaf3, node01, node23, root].
use trust_anchor::{leaf_poseidon2, node_poseidon2};

fn main(kinds: [u8; 4], key_hashes: [[u8; 32]; 4], used: [bool; 4]) -> pub [Field; 7] {
    let mut l: [Field; 4] = [0; 4];
    for i in 0..4 {
        if used[i] {
            l[i] = leaf_poseidon2(kinds[i], key_hashes[i]);
        }
    }
    let n0 = node_poseidon2(l[0], l[1]);
    let n1 = node_poseidon2(l[2], l[3]);
    [l[0], l[1], l[2], l[3], n0, n1, node_poseidon2(n0, n1)]
}
