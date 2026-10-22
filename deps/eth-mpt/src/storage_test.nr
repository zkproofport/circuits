// Real Base records, one block, one storage root (storage_test_fixture.nr).
// Regenerate with scripts/coinbase-eas-storage-poc/make-mpt-test-fixture.js.

use crate::proof::Proof;
use crate::storage::{encode_word, verify_storage_slot};
use crate::storage_test_fixture::{
    LIVE_DEPTH, LIVE_LEAF, LIVE_NODES, LIVE_SLOT, LIVE_WORD, REVOKED_DEPTH, REVOKED_LEAF,
    REVOKED_NODES, REVOKED_SLOT, REVOKED_WORD, STORAGE_ROOT,
};

fn live() -> Proof<10, 70> {
    Proof { nodes: LIVE_NODES, leaf: LIVE_LEAF, depth: LIVE_DEPTH }
}

fn revoked() -> Proof<10, 70> {
    Proof { nodes: REVOKED_NODES, leaf: REVOKED_LEAF, depth: REVOKED_DEPTH }
}

/// The third struct word with revocationTime (bytes 8..16) cleared: what a
/// prover claims when it says "never revoked".
fn without_revocation(word: [u8; 32]) -> [u8; 32] {
    let mut w = word;
    for i in 0..16 {
        w[i] = 0;
    }
    w
}

#[test]
fn a_live_record_is_accepted() {
    verify_storage_slot(LIVE_SLOT, LIVE_WORD, STORAGE_ROOT, live());
}

#[test]
fn the_revoked_record_is_accepted_only_with_its_revocation_time() {
    // Guards the next test: if this one failed, the refusal below could be
    // a broken proof rather than the revocation being read.
    verify_storage_slot(REVOKED_SLOT, REVOKED_WORD, STORAGE_ROOT, revoked());
}

#[test(should_fail_with = "Stored value")]
fn a_revoked_record_claimed_as_unrevoked_is_refused() {
    verify_storage_slot(REVOKED_SLOT, without_revocation(REVOKED_WORD), STORAGE_ROOT, revoked());
}

#[test(should_fail_with = "Stored value")]
fn a_different_time_is_refused() {
    let mut w = LIVE_WORD;
    w[31] = w[31] ^ 1;
    verify_storage_slot(LIVE_SLOT, w, STORAGE_ROOT, live());
}

#[test(should_fail_with = "Invalid node hash")]
fn another_storage_root_is_refused() {
    let mut root = STORAGE_ROOT;
    root[0] = root[0] ^ 1;
    verify_storage_slot(LIVE_SLOT, LIVE_WORD, root, live());
}

#[test(should_fail)]
fn a_proof_for_another_slot_is_refused() {
    // The live record's proof, presented as proof of the revoked record's slot.
    verify_storage_slot(REVOKED_SLOT, LIVE_WORD, STORAGE_ROOT, live());
}

#[test(should_fail)]
fn a_tampered_leaf_is_refused() {
    let mut p = live();
    p.leaf[p.leaf.len() - 1] = 0;
    p.leaf[5] = p.leaf[5] ^ 1;
    verify_storage_slot(LIVE_SLOT, LIVE_WORD, STORAGE_ROOT, p);
}

#[test(should_fail)]
fn a_shortened_proof_is_refused() {
    let mut p = live();
    p.depth = p.depth - 1;
    verify_storage_slot(LIVE_SLOT, LIVE_WORD, STORAGE_ROOT, p);
}

#[test(should_fail_with = "Proof deeper than this circuit allows")]
fn a_proof_deeper_than_the_circuit_is_refused() {
    let mut p = live();
    p.depth = 12;
    verify_storage_slot(LIVE_SLOT, LIVE_WORD, STORAGE_ROOT, p);
}

#[test(should_fail_with = "A zero storage word is absent from the trie")]
fn a_zero_word_is_refused() {
    verify_storage_slot(LIVE_SLOT, [0; 32], STORAGE_ROOT, live());
}

#[test]
fn words_encode_as_the_trie_stores_them() {
    // One byte below 0x80 is its own encoding.
    let mut w: [u8; 32] = [0; 32];
    w[31] = 0x7f;
    let (e, n) = encode_word(w);
    assert(n == 1);
    assert(e[0] == 0x7f);

    // 0x80 and above take a header.
    w[31] = 0x80;
    let (e, n) = encode_word(w);
    assert(n == 2);
    assert((e[0] == 0x81) & (e[1] == 0x80));

    // A trailing zero byte is part of the value, not padding.
    let mut t: [u8; 32] = [0; 32];
    t[28] = 0x6a;
    t[31] = 0x00;
    let (e, n) = encode_word(t);
    assert(n == 5);
    assert((e[0] == 0x84) & (e[1] == 0x6a) & (e[4] == 0x00));

    // A full word.
    let full: [u8; 32] = [0xff; 32];
    let (e, n) = encode_word(full);
    assert(n == 33);
    assert((e[0] == 0xa0) & (e[32] == 0xff));
}
