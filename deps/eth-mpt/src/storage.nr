// One storage slot of one contract, proven against that contract's storage root.
//
// Written for this repository on top of the forked eth-proofs trie code, which
// takes the expected value as a left-padded word and strips leading zeros with
// `right_pad`. That is right for a value, and wrong for the KEY: a hashed key
// that begins with a zero byte would lose its first nibbles and the proof would
// be refused. One key in 256 does. So the key is walked here from its 32 bytes
// directly, and the leaf's value is compared against the RLP encoding the trie
// actually stores.

use crate::misc::{bytes::{byte_to_nibbles, byte_value}, fragment::Fragment};
use crate::proof::{extract_hash, Proof, strip_prefix, verify_node_hash};
use crate::rlp::decode::decode_list;
use crate::rlp::types::RlpList;
use dep::keccak256::keccak256;

global KEY_NIBBLES: u32 = 64;
// A storage key is 64 nibbles; the trie helpers expect room for a prefix.
global KEY_NIBBLE_CAPACITY: u32 = 66;
global WORD_LEN: u32 = 32;
// RLP of a non-empty word: one header byte and up to 32 bytes.
global MAX_ENCODED_WORD_LEN: u32 = 33;

fn key_nibbles(slot: [u8; 32]) -> Fragment<KEY_NIBBLE_CAPACITY, u8> {
    let hashed = keccak256(slot, 32);
    let mut nibbles: [u8; KEY_NIBBLE_CAPACITY] = [0; KEY_NIBBLE_CAPACITY];
    for i in 0..32 {
        let (hi, lo) = byte_to_nibbles(hashed[i]);
        nibbles[2 * i] = hi;
        nibbles[2 * i + 1] = lo;
    }
    Fragment::new_with_length(KEY_NIBBLES, nibbles)
}

/// The bytes a storage leaf holds for `word`: RLP of its big-endian form with
/// leading zeros removed. A zero word is never stored, so it is refused here
/// rather than proven -- proving absence is a different proof.
pub fn encode_word(word: [u8; WORD_LEN]) -> ([u8; MAX_ENCODED_WORD_LEN], u32) {
    let trimmed = byte_value(word);
    let len = trimmed.len();
    assert(len != 0, "A zero storage word is absent from the trie, not stored");
    let bytes = trimmed.storage();

    let mut out: [u8; MAX_ENCODED_WORD_LEN] = [0; MAX_ENCODED_WORD_LEN];
    let single = (len == 1) & (bytes[0] < 0x80);
    if single {
        out[0] = bytes[0];
    } else {
        out[0] = 0x80 + len as u8;
        for i in 0..WORD_LEN {
            if i < len {
                out[i + 1] = bytes[i];
            }
        }
    }
    let out_len = if single { 1 } else { len + 1 };
    (out, out_len)
}

/// Asserts that slot `slot` of the contract whose storage root is
/// `storage_root` holds exactly `word`.
pub fn verify_storage_slot<let MAX_DEPTH_NO_LEAF: u32, let MAX_LEAF_LEN: u32>(
    slot: [u8; 32],
    word: [u8; WORD_LEN],
    storage_root: [u8; 32],
    proof: Proof<MAX_DEPTH_NO_LEAF, MAX_LEAF_LEN>,
) {
    let key = key_nibbles(slot);
    let mut key_ptr: u32 = 0;

    assert(proof.depth >= 1, "A proof has at least its leaf");
    assert(proof.depth - 1 <= MAX_DEPTH_NO_LEAF as u64, "Proof deeper than this circuit allows");

    let mut curr_hash = root_fragment(storage_root);
    for i in 0..MAX_DEPTH_NO_LEAF {
        if (i as u64) < proof.depth - 1 {
            verify_node_hash(proof.nodes[i], curr_hash.data);
            curr_hash = extract_hash(proof.nodes[i], key, &mut key_ptr);
        }
    }
    verify_node_hash(proof.leaf, curr_hash.data);

    let leaf_fields: RlpList<2> = decode_list(Fragment::from_array(proof.leaf));
    assert(leaf_fields.len() == 2, "A leaf has two fields");

    let prefixed_path: Fragment<KEY_NIBBLE_CAPACITY, u8> = Fragment::new(
        leaf_fields.get(0).offset,
        leaf_fields.get(0).length,
        proof.leaf,
    )
        .focus();
    let (prefix, _) = byte_to_nibbles(prefixed_path.at(0));
    assert((prefix == 2) | (prefix == 3), "Leaf parity prefix must be 2 or 3");
    let path = strip_prefix(prefixed_path);
    assert(path == key.subfragment(key_ptr, path.length), "Key mismatch in the leaf");
    key_ptr += path.length;
    assert(key_ptr == KEY_NIBBLES, "The leaf must end the key");

    let (expected, expected_len) = encode_word(word);
    let stored = leaf_fields.get(1);
    assert(stored.length == expected_len, "Stored value length differs");
    for i in 0..MAX_ENCODED_WORD_LEN {
        if i < expected_len {
            assert(proof.leaf[stored.offset + i] == expected[i], "Stored value differs");
        }
    }
}

fn root_fragment(root: [u8; 32]) -> Fragment<32, u8> {
    Fragment::from_array(root)
}
