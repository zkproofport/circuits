use dep::keccak256::keccak256;
use crate::ethereum::{create_eip712_digest, create_eth_signed_message_hash};

/// True when all 32 bytes are zero. Summing cannot overflow: 32 * 255 = 8160.
pub fn is_zero_32(v: [u8; 32]) -> bool {
    let mut acc: u32 = 0;
    for i in 0..32 {
        acc += v[i] as u32;
    }
    acc == 0
}

/// The digest the wallet must have signed, and the check that the request
/// asked for exactly one of the two things it can ask for.
///
/// With an action: keccak(0x19 0x01 ++ domain_separator ++ action_hash), which
/// is what a wallet computes for eth_signTypedData_v4 and what the person sees
/// rendered field by field.
/// Without one: the EIP-191 personal_sign digest over signal_hash.
///
/// Both are computed and one is selected. A circuit has no branches to skip --
/// the selection is what the constraint system sees, and the cost is one extra
/// small keccak either way.
///
/// WHY THE MODES ARE MUTUALLY EXCLUSIVE. If a prover could fill every field,
/// two verifiers reading the same proof could disagree about what was
/// authorized: one comparing the action hash, the other treating it as a plain
/// attestation. Zero bytes are what "absent" looks like here, because a
/// circuit has no null.
///
/// SHARED, not copied. `arc_eligibility` and `giwa_attestation` both branch
/// this way; two copies of one rule is how the app, the SDK and the circuit
/// came to disagree about what a wallet had signed.
pub fn signed_digest(
    signal_hash: [u8; 32],
    domain_separator: [u8; 32],
    action_hash: [u8; 32],
) -> [u8; 32] {
    let action_mode = !(is_zero_32(domain_separator) & is_zero_32(action_hash));

    if action_mode {
        // Half an action is a caller that built a message the wallet never saw
        // whole -- the shape that produced a valid proof of the wrong thing.
        assert(!is_zero_32(domain_separator), "action mode needs a domain separator");
        assert(!is_zero_32(action_hash), "action mode needs an action hash");
        assert(is_zero_32(signal_hash), "signal_hash must be empty in action mode");
    } else {
        assert(!is_zero_32(signal_hash), "signal_hash is required when no action is bound");
    }

    let action_digest = create_eip712_digest(domain_separator, action_hash);
    let signal_digest = create_eth_signed_message_hash(signal_hash);
    let mut digest: [u8; 32] = [0; 32];
    for i in 0..32 {
        digest[i] = if action_mode { action_digest[i] } else { signal_digest[i] };
    }
    digest
}

#[test]
fn action_mode_returns_the_eip712_digest() {
    let ds: [u8; 32] = [7; 32];
    let ah: [u8; 32] = [9; 32];
    let empty: [u8; 32] = [0; 32];
    assert(signed_digest(empty, ds, ah) == create_eip712_digest(ds, ah));
}

#[test]
fn no_action_returns_the_personal_sign_digest() {
    let sh: [u8; 32] = [3; 32];
    let empty: [u8; 32] = [0; 32];
    assert(signed_digest(sh, empty, empty) == create_eth_signed_message_hash(sh));
}

#[test]
fn the_two_digests_differ_for_the_same_bytes() {
    // Guards the selection itself: if both branches produced the same value
    // the tests above would pass with the branch deleted.
    let x: [u8; 32] = [5; 32];
    let empty: [u8; 32] = [0; 32];
    assert(signed_digest(empty, x, x) != signed_digest(x, empty, empty));
}

#[test(should_fail_with = "signal_hash must be empty in action mode")]
fn an_action_and_a_signal_hash_together_are_refused() {
    let x: [u8; 32] = [1; 32];
    let _ = signed_digest(x, x, x);
}

#[test(should_fail_with = "action mode needs an action hash")]
fn a_domain_without_an_action_is_refused() {
    let ds: [u8; 32] = [1; 32];
    let empty: [u8; 32] = [0; 32];
    let _ = signed_digest(empty, ds, empty);
}

#[test(should_fail_with = "action mode needs a domain separator")]
fn an_action_without_a_domain_is_refused() {
    let ah: [u8; 32] = [1; 32];
    let empty: [u8; 32] = [0; 32];
    let _ = signed_digest(empty, empty, ah);
}

#[test(should_fail_with = "signal_hash is required when no action is bound")]
fn an_empty_request_is_refused() {
    let empty: [u8; 32] = [0; 32];
    let _ = signed_digest(empty, empty, empty);
}
