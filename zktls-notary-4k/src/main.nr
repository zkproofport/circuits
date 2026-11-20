// zkTLS claim circuit, 4k tier: the committed prefix is at most 4096 bytes.
// See ../zktls-notary-libs/src/lib.nr for what is proved.

use zktls_notary_libs::{Assert, BLINDER_LEN, Hint, KEY_MAX, SCOPE_LEN, verify_claim};

mod tests;

global TIER: u32 = 4096;
// Assertions this circuit checks (ANDed). The claim encoding always has A_MAX = 3
// slots, so the claim_hash is the same whichever capacity proves a claim.
global A: u32 = 3;

fn main(
    // Private: the committed prefix and its blinder, the claim, and where its tokens sit.
    prefix: [u8; TIER],
    prefix_len: u32,
    blinder: [u8; BLINDER_LEN],
    root: u32,
    cont: [u32; TIER],
    n_asserts: u32,
    asserts: [Assert; A],
    hints: [Hint; A],
    nf_key: [u8; KEY_MAX],
    nf_key_len: u32,
    nf_kind: u32,
    nf_hint: Hint,
    scope: [u8; SCOPE_LEN],
    // Public: what the verifier signed, the claim and request the proof answers, the day.
    commitment: pub [u8; 32],
    whole: pub bool,
    claim_hash: pub [u8; 32],
    request_hash: pub [u8; 32],
    proof_year: pub u32,
    proof_month: pub u32,
    proof_day: pub u32,
    nullifier: pub [u8; 32],
) {
    // request_hash is carried unchanged: the relying party compares it with the hash of
    // its own proof request (see the library header).
    let _ = request_hash;
    verify_claim::<TIER, A>(
        prefix,
        prefix_len,
        blinder,
        root,
        cont,
        n_asserts,
        asserts,
        hints,
        nf_key,
        nf_key_len,
        nf_kind,
        nf_hint,
        scope,
        commitment,
        whole,
        claim_hash,
        proof_year,
        proof_month,
        proof_day,
        nullifier,
    );
}
