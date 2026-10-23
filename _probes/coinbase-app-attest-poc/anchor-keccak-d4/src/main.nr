// Trust-anchor membership alone: keccak256 tree of depth 4, root public.
use trust_anchor::{leaf_keccak, root_keccak};

global DEPTH: u32 = 4;

fn main(trust_anchor_root: pub [u8; 32], kind: u8, key_hash: [u8; 32], index: u32, path: [[u8; 32]; DEPTH]) {
    let leaf = leaf_keccak(kind, key_hash);
    assert(root_keccak::<DEPTH>(leaf, index, path) == trust_anchor_root, "Trust anchor is not in the published set");
}
