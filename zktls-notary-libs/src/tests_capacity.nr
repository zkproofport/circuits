// The assertion capacity A (verify_claim's second generic): what a circuit with fewer
// slots than a claim has assertions must do, and that one claim has one claim_hash
// whichever capacity proves it. The rest of the suite runs at every capacity through
// #[capacities] (testkit.nr).

use crate::{A_MAX, Assert, compute_claim_hash, Hint, KIND_LITERAL, KIND_STRING, OP_EQ, Path, verify_claim};
use crate::testkit::{
    and, assertion, claim_hash_of, Claim, cont_of, fit_asserts, fit_hints, hints_multi, no_assert,
    nullifier_of, p_any, p_key, p_new, pad_to, root_of, single, zero_hint,
};
use crate::vectors::BLINDER;
use crate::vectors_deep::{DEEP, DEEP_C, DEEP_ID, DEEP_TYPE, DEEP_ZKP};

global T: u32 = 1024;

fn owner_path<let L: u32>(leaf: str<L>) -> Path {
    p_key(p_key(p_any(p_key(p_key(p_new(), "data"), "items")), "owner"), leaf)
}

fn login() -> Claim {
    single(assertion(owner_path("login"), KIND_STRING, OP_EQ, "zkproofport"), "id", KIND_LITERAL, "7")
}

fn login_and_type() -> Claim {
    and(login(), assertion(owner_path("type"), KIND_STRING, OP_EQ, "Organization"))
}

fn honest_hints(c: Claim) -> ([Hint; A_MAX], Hint) {
    hints_multi::<T, _>(DEEP, DEEP.as_bytes().len(), c, [[DEEP_ZKP, 11], [DEEP_TYPE, 12], [0, 0]], DEEP_ID)
}

// A capacity-A circuit run with every input given: the assertion count, the slots it
// has, and the public claim_hash the relying party computed for `c`.
fn run_at<let A: u32>(c: Claim, n_asserts: u32, asserts: [Assert; A], hints: [Hint; A], nf: Hint, claim_hash: [u8; 32]) {
    let len = DEEP.as_bytes().len();
    verify_claim::<T, A>(
        pad_to(DEEP.as_bytes(), len),
        len,
        BLINDER,
        root_of(DEEP.as_bytes()),
        cont_of(DEEP, len),
        n_asserts,
        asserts,
        hints,
        c.nf_key,
        c.nf_key_len,
        c.nf_kind,
        nf,
        c.scope,
        DEEP_C,
        true,
        claim_hash,
        2026,
        11,
        16,
        nullifier_of(c),
    );
}

// Positive control for the two refusals below: the same claim and hints prove at
// capacity 2 when given exactly the way the refused runs give them.
#[test]
fn test_two_assertions_prove_at_capacity_two() {
    let c = login_and_type();
    let (h, nf) = honest_hints(c);
    run_at::<2>(c, 2, fit_asserts::<2>(c.asserts), fit_hints::<2>(h), nf, claim_hash_of(c, T));
}

// A two-assertion claim given to a one-slot circuit: the count is refused, so the
// second assertion cannot go unchecked.
#[test(should_fail_with = "bad assertion count")]
fn test_capacity_one_refuses_two_assertions() {
    let c = login_and_type();
    let (h, nf) = honest_hints(c);
    run_at::<1>(c, 2, [c.asserts[0]], [h[0]], nf, claim_hash_of(c, T));
}

// ... and claiming one assertion instead does not produce the two-assertion claim's
// hash: the relying party's claim_hash covers the count and both assertions.
#[test(should_fail_with = "claim hash mismatch")]
fn test_capacity_one_cannot_drop_the_second_assertion() {
    let c = login_and_type();
    let (h, nf) = honest_hints(c);
    run_at::<1>(c, 1, [c.asserts[0]], [h[0]], nf, claim_hash_of(c, T));
}

#[test(should_fail_with = "bad assertion count")]
fn test_capacity_two_refuses_three_assertions() {
    let c = and(login_and_type(), assertion(owner_path("login"), KIND_STRING, OP_EQ, "zkproofport"));
    let (h, nf) = honest_hints(login_and_type());
    run_at::<2>(c, 3, fit_asserts::<2>(login_and_type().asserts), fit_hints::<2>(h), nf, claim_hash_of(c, T));
}

#[test(should_fail_with = "bad assertion count")]
fn test_capacity_one_refuses_zero_assertions() {
    let c = login();
    let (h, nf) = honest_hints(c);
    run_at::<1>(c, 0, [no_assert()], [h[0]], nf, claim_hash_of(c, T));
}

#[test(should_fail_with = "bad assertion count")]
fn test_capacity_two_refuses_zero_assertions() {
    let c = login();
    let (h, nf) = honest_hints(c);
    run_at::<2>(c, 0, [no_assert(); 2], [h[0], zero_hint()], nf, claim_hash_of(c, T));
}

// A full-capacity circuit (every circuit the tiers build) refuses a count past A_MAX:
// the claim encoding has no fourth slot, so a fourth assertion would go unchecked.
#[test(should_fail_with = "bad assertion count")]
fn test_capacity_three_refuses_four_assertions() {
    let c = login_and_type();
    let (h, nf) = honest_hints(c);
    run_at::<3>(c, 4, c.asserts, h, nf, claim_hash_of(c, T));
}

// The claim_hash is the same at every capacity: slots past A are encoded as zero, and
// an unused slot must be zero anyway.
#[test]
fn test_claim_hash_is_the_same_at_every_capacity() {
    let one = login();
    let h3 = claim_hash_of(one, T);
    assert(compute_claim_hash(T, 1, fit_asserts::<1>(one.asserts), one.nf_key, one.nf_key_len, one.nf_kind, one.scope) == h3);
    assert(compute_claim_hash(T, 1, fit_asserts::<2>(one.asserts), one.nf_key, one.nf_key_len, one.nf_kind, one.scope) == h3);
    let two = login_and_type();
    let h3 = claim_hash_of(two, T);
    assert(compute_claim_hash(T, 2, fit_asserts::<2>(two.asserts), two.nf_key, two.nf_key_len, two.nf_kind, two.scope) == h3);
    assert(h3 != claim_hash_of(one, T));
}
