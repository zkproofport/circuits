// The 1 KB tier through its own main: a body that fits, a longer body whose
// members sit in the first 1 KB, and a member past 1 KB that must fail.

use super::{A, TIER};
use zktls_notary_libs::testkit::{age19, at, me_age_range_claim, ok_prefix, ok_whole};
use zktls_notary_libs::vectors::{
    ME_30, ME_30_AGE_RANGE, ME_30_C, ME_30_ID, ME_30_KA, ME_LONG, ME_LONG_AGE_RANGE, ME_LONG_ID,
    ME_LONG_KA, ME_LONG_P1024_C, OIDC_TAIL, OIDC_TAIL_BIRTHDATE, OIDC_TAIL_P1024_C, OIDC_TAIL_SUB,
};

#[test]
fn test_1k_whole_body() {
    ok_whole::<TIER, _, A>(
        ME_30,
        ME_30_C,
        me_age_range_claim("20"),
        at(ME_30_KA, ME_30_AGE_RANGE, 5, ME_30_ID),
    );
}

#[test]
fn test_1k_prefix_of_longer_body() {
    ok_prefix::<TIER, _, A>(
        OIDC_TAIL,
        OIDC_TAIL_P1024_C,
        age19(),
        at(0, OIDC_TAIL_BIRTHDATE, 10, OIDC_TAIL_SUB),
    );
}

#[test(should_fail_with = "segment token past prefix")]
fn test_1k_member_past_tier_fails() {
    ok_prefix::<TIER, _, A>(
        ME_LONG,
        ME_LONG_P1024_C,
        me_age_range_claim("20"),
        at(ME_LONG_KA, ME_LONG_AGE_RANGE, 5, ME_LONG_ID),
    );
}
