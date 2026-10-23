// Trust-anchor membership alone: Poseidon2 tree of depth 4, root public.
use trust_anchor::{leaf_poseidon2, root_poseidon2};

global DEPTH: u32 = 4;

fn main(trust_anchor_root: pub Field, kind: u8, key_hash: [u8; 32], index: u32, path: [Field; DEPTH]) {
    let leaf = leaf_poseidon2(kind, key_hash);
    assert(root_poseidon2::<DEPTH>(leaf, index, path) == trust_anchor_root, "Trust anchor is not in the published set");
}
