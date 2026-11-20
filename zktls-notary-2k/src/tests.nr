// This tier through its own main: the body whose age_range sits past 1 KB
// (which the 1 KB tier rejects) proves here as a whole body.

use super::{A, TIER};
use zktls_notary_libs::testkit::{
    age19, at, me_age_range_claim, nullifier_of, ok_whole, run_full, claim_hash_of,
};
use zktls_notary_libs::vectors::{
    BLINDER, ME_LONG, ME_LONG_AGE_RANGE, ME_LONG_C, ME_LONG_ID, ME_LONG_KA, OIDC_TAIL,
    OIDC_TAIL_BIRTHDATE, OIDC_TAIL_C, OIDC_TAIL_SUB,
};

#[test]
fn test_member_past_1k_proves_in_this_tier() {
    ok_whole::<TIER, _, A>(
        ME_LONG,
        ME_LONG_C,
        me_age_range_claim("20"),
        at(ME_LONG_KA, ME_LONG_AGE_RANGE, 5, ME_LONG_ID),
    );
}

#[test]
fn test_long_oidc_whole_body() {
    ok_whole::<TIER, _, A>(
        OIDC_TAIL,
        OIDC_TAIL_C,
        age19(),
        at(0, OIDC_TAIL_BIRTHDATE, 10, OIDC_TAIL_SUB),
    );
}

#[test(should_fail_with = "claim hash mismatch")]
fn test_1k_schema_hash_rejected() {
    let c = age19();
    run_full::<TIER, _, A>(
        OIDC_TAIL,
        OIDC_TAIL.as_bytes().len(),
        true,
        OIDC_TAIL_C,
        BLINDER,
        c,
        at(0, OIDC_TAIL_BIRTHDATE, 10, OIDC_TAIL_SUB),
        claim_hash_of(c, 1024),
        nullifier_of(c),
    );
}
