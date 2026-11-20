// Library tests, run against a 1 KB tier unless a test names another size.
// Bodies, commitments and offsets are in vectors.nr.

use crate::{KIND_LITERAL, KIND_STRING, OP_AGE_GTE, OP_EQ};
use crate::testkit::capacities;
use crate::testkit::{
    age19, at, me_age_range_claim, nullifier_of, oidc_claim, ok_prefix, ok_whole, pad32, run_full,
    claim_hash_of,
};
use crate::vectors::{
    BLINDER, CUT_INSIDE_FALSE_C, CUT_INSIDE_FALSE_N, CUT_LITERAL_C, CUT_LITERAL_N, CUT_STRING_C,
    CUT_STRING_N, ME_15, ME_15_AGE_RANGE, ME_15_C, ME_15_ID, ME_15_KA, ME_15_PROPS, ME_30,
    ME_30_AGE_RANGE, ME_30_C, ME_30_ID, ME_30_KA, ME_30_PROPS, ME_90, ME_90_AGE_RANGE, ME_90_C,
    ME_90_ID, ME_90_KA, ME_90_PROPS, ME_FORGED_PROPS, ME_FORGED_PROPS_AGE_RANGE, ME_FORGED_PROPS_C,
    ME_FORGED_PROPS_FAKE, ME_FORGED_PROPS_ID, ME_FORGED_PROPS_KA, ME_FORGED_PROPS_PROPS,
    ME_FORGED_TOP, ME_FORGED_TOP_AGE_RANGE, ME_FORGED_TOP_C, ME_FORGED_TOP_FAKE, ME_FORGED_TOP_ID,
    ME_FORGED_TOP_KA, ME_FORGED_TOP_PROPS, ME_LONG, ME_LONG_AGE_RANGE, ME_LONG_C, ME_LONG_ID,
    ME_LONG_KA, ME_LONG_P1024_C, ME_LONG_PROPS, ME_NICKATTACK, ME_NICKATTACK_AGE_RANGE,
    ME_NICKATTACK_C, ME_NICKATTACK_FAKE, ME_NICKATTACK_ID, ME_NICKATTACK_KA, ME_NICKATTACK_PROPS,
    ME_NOTILDE, ME_NOTILDE_AGE_RANGE, ME_NOTILDE_C, ME_NOTILDE_ID, ME_NOTILDE_KA, ME_NOTILDE_PROPS,
    OIDC_ADULT, OIDC_ADULT_BIRTHDATE, OIDC_ADULT_C, OIDC_ADULT_EMAIL_VERIFIED, OIDC_ADULT_GENDER,
    OIDC_ADULT_SUB, OIDC_BRACKETS, OIDC_BRACKETS_BIRTHDATE, OIDC_BRACKETS_C,
    OIDC_BRACKETS_EMAIL_VERIFIED, OIDC_BRACKETS_GENDER, OIDC_BRACKETS_SUB, OIDC_DAYSHORT,
    OIDC_DAYSHORT_BIRTHDATE, OIDC_DAYSHORT_C, OIDC_DAYSHORT_EMAIL_VERIFIED, OIDC_DAYSHORT_GENDER,
    OIDC_DAYSHORT_SUB, OIDC_EXACT19, OIDC_EXACT19_BIRTHDATE, OIDC_EXACT19_C,
    OIDC_EXACT19_EMAIL_VERIFIED, OIDC_EXACT19_GENDER, OIDC_EXACT19_SUB, OIDC_FEMALE,
    OIDC_FEMALE_BIRTHDATE, OIDC_FEMALE_C, OIDC_FEMALE_EMAIL_VERIFIED, OIDC_FEMALE_GENDER,
    OIDC_FEMALE_SUB, OIDC_MINOR, OIDC_MINOR_BIRTHDATE, OIDC_MINOR_C, OIDC_MINOR_EMAIL_VERIFIED,
    OIDC_MINOR_GENDER, OIDC_MINOR_SUB, OIDC_NESTED, OIDC_NESTED_BIRTHDATE, OIDC_NESTED_C,
    OIDC_NESTED_EMAIL_VERIFIED, OIDC_NESTED_FAKE, OIDC_NESTED_GENDER, OIDC_NESTED_SUB,
    OIDC_NICKATTACK, OIDC_NICKATTACK_BIRTHDATE, OIDC_NICKATTACK_C, OIDC_NICKATTACK_EMAIL_VERIFIED,
    OIDC_NICKATTACK_FAKE, OIDC_NICKATTACK_GENDER, OIDC_NICKATTACK_SUB, OIDC_TAIL,
    OIDC_TAIL_BIRTHDATE, OIDC_TAIL_C, OIDC_TAIL_EMAIL_VERIFIED, OIDC_TAIL_GENDER, OIDC_TAIL_P1024_C,
    OIDC_TAIL_SUB, OIDC_UNVERIFIED, OIDC_UNVERIFIED_BIRTHDATE, OIDC_UNVERIFIED_C,
    OIDC_UNVERIFIED_EMAIL_VERIFIED, OIDC_UNVERIFIED_GENDER, OIDC_UNVERIFIED_SUB, OIDC_YEARONLY,
    OIDC_YEARONLY_BIRTHDATE, OIDC_YEARONLY_C, OIDC_YEARONLY_EMAIL_VERIFIED, OIDC_YEARONLY_GENDER,
    OIDC_YEARONLY_SUB, OIDC_ZEROYEAR, OIDC_ZEROYEAR_BIRTHDATE, OIDC_ZEROYEAR_C,
    OIDC_ZEROYEAR_EMAIL_VERIFIED, OIDC_ZEROYEAR_GENDER, OIDC_ZEROYEAR_SUB,
};

global T: u32 = 1024;

// ---- /v2/user/me: kakao_account.age_range ------------------------------

#[capacities(1, "")]
fn test_me_age_range_30_passes_min_20<let A: u32>() {
    ok_whole::<T, _, A>(
        ME_30,
        ME_30_C,
        me_age_range_claim("20"),
        at(ME_30_KA, ME_30_AGE_RANGE, 5, ME_30_ID),
    );
}

#[capacities(1, "")]
fn test_me_open_range_90<let A: u32>() {
    ok_whole::<T, _, A>(
        ME_90,
        ME_90_C,
        me_age_range_claim("20"),
        at(ME_90_KA, ME_90_AGE_RANGE, 3, ME_90_ID),
    );
}

#[capacities(1, "range has no tilde")]
fn test_me_age_range_without_tilde_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        ME_NOTILDE,
        ME_NOTILDE_C,
        me_age_range_claim("20"),
        at(ME_NOTILDE_KA, ME_NOTILDE_AGE_RANGE, 2, ME_NOTILDE_ID),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_me_age_range_under_20_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        ME_15,
        ME_15_C,
        me_age_range_claim("20"),
        at(ME_15_KA, ME_15_AGE_RANGE, 5, ME_15_ID),
    );
}

#[capacities(1, "key name mismatch")]
fn test_me_escaped_age_range_in_nickname_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        ME_NICKATTACK,
        ME_NICKATTACK_C,
        me_age_range_claim("20"),
        at(ME_NICKATTACK_KA, ME_NICKATTACK_FAKE, 5, ME_NICKATTACK_ID),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_me_nickname_body_real_value_is_under_20<let A: u32>() {
    ok_whole::<T, _, A>(
        ME_NICKATTACK,
        ME_NICKATTACK_C,
        me_age_range_claim("20"),
        at(
            ME_NICKATTACK_KA,
            ME_NICKATTACK_AGE_RANGE,
            5,
            ME_NICKATTACK_ID,
        ),
    );
}

#[capacities(1, "key name mismatch")]
fn test_me_forged_properties_age_range_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        ME_FORGED_PROPS,
        ME_FORGED_PROPS_C,
        me_age_range_claim("20"),
        at(
            ME_FORGED_PROPS_KA,
            ME_FORGED_PROPS_FAKE,
            5,
            ME_FORGED_PROPS_ID,
        ),
    );
}

#[capacities(1, "key name mismatch")]
fn test_me_properties_as_parent_fails<let A: u32>() {
    // Pointing the parent at "properties" while the schema names kakao_account.
    ok_whole::<T, _, A>(
        ME_FORGED_PROPS,
        ME_FORGED_PROPS_C,
        me_age_range_claim("20"),
        at(
            ME_FORGED_PROPS_PROPS,
            ME_FORGED_PROPS_FAKE,
            5,
            ME_FORGED_PROPS_ID,
        ),
    );
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_me_forged_top_level_age_range_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        ME_FORGED_TOP,
        ME_FORGED_TOP_C,
        me_age_range_claim("20"),
        at(ME_FORGED_TOP_KA, ME_FORGED_TOP_FAKE, 5, ME_FORGED_TOP_ID),
    );
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_me_top_level_schema_rejects_nested_value<let A: u32>() {
    // A schema without a parent cannot read kakao_account.age_range.
    let mut c = me_age_range_claim("20");
    c.asserts[0].path = crate::testkit::p1("age_range");
    ok_whole::<T, _, A>(ME_30, ME_30_C, c, at(0, ME_30_AGE_RANGE, 5, ME_30_ID));
}

#[capacities(1, "literal not closed")]
fn test_me_id_truncated_fails<let A: u32>() {
    let mut c = me_age_range_claim("20");
    c.nf_value = pad32("123456789".as_bytes());
    c.nf_value_len = 9;
    ok_whole::<T, _, A>(
        ME_30,
        ME_30_C,
        c,
        at(ME_30_KA, ME_30_AGE_RANGE, 5, ME_30_ID),
    );
}

#[capacities(1, "value not closed")]
fn test_me_age_range_truncated_fails<let A: u32>() {
    // Reading "30" of "30~39" as if it were the whole value.
    ok_whole::<T, _, A>(
        ME_30,
        ME_30_C,
        me_age_range_claim("20"),
        at(ME_30_KA, ME_30_AGE_RANGE, 2, ME_30_ID),
    );
}

// ---- /v1/oidc/userinfo: gender, email_verified ------------------------

#[capacities(1, "")]
fn test_oidc_gender_male<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT_C,
        oidc_claim("gender", KIND_STRING, OP_EQ, "male"),
        at(0, OIDC_ADULT_GENDER, 4, OIDC_ADULT_SUB),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_oidc_gender_mismatch_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_FEMALE,
        OIDC_FEMALE_C,
        oidc_claim("gender", KIND_STRING, OP_EQ, "male"),
        at(0, OIDC_FEMALE_GENDER, 6, OIDC_FEMALE_SUB),
    );
}

#[capacities(1, "")]
fn test_oidc_email_verified_true<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT_C,
        oidc_claim("email_verified", KIND_LITERAL, OP_EQ, "true"),
        at(0, OIDC_ADULT_EMAIL_VERIFIED, 4, OIDC_ADULT_SUB),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_oidc_email_verified_false_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_UNVERIFIED,
        OIDC_UNVERIFIED_C,
        oidc_claim("email_verified", KIND_LITERAL, OP_EQ, "true"),
        at(0, OIDC_UNVERIFIED_EMAIL_VERIFIED, 5, OIDC_UNVERIFIED_SUB),
    );
}

#[capacities(1, "literal not closed")]
fn test_oidc_literal_prefix_fails<let A: u32>() {
    // "fals" is not the whole literal "false".
    ok_whole::<T, _, A>(
        OIDC_UNVERIFIED,
        OIDC_UNVERIFIED_C,
        oidc_claim("email_verified", KIND_LITERAL, OP_EQ, "true"),
        at(0, OIDC_UNVERIFIED_EMAIL_VERIFIED, 4, OIDC_UNVERIFIED_SUB),
    );
}

#[capacities(1, "no colon after key")]
fn test_oidc_kind_string_on_literal_fails<let A: u32>() {
    // The schema says string; the member is the bare literal true, so the
    // key token would have to start one byte earlier, where there is a comma.
    ok_whole::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT_C,
        oidc_claim("email_verified", KIND_STRING, OP_EQ, "true"),
        at(0, OIDC_ADULT_EMAIL_VERIFIED, 4, OIDC_ADULT_SUB),
    );
}

#[capacities(1, "unknown value kind")]
fn test_unknown_value_kind_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT_C,
        oidc_claim("gender", 2, OP_EQ, "male"),
        at(0, OIDC_ADULT_GENDER, 4, OIDC_ADULT_SUB),
    );
}

#[capacities(1, "unknown operator")]
fn test_unknown_operator_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT_C,
        oidc_claim("gender", KIND_STRING, 200, "1"),
        at(0, OIDC_ADULT_GENDER, 4, OIDC_ADULT_SUB),
    );
}

// ---- /v1/oidc/userinfo: birthdate, AGE_GTE ----------------------------

#[capacities(1, "")]
fn test_age_adult<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT_C,
        age19(),
        at(0, OIDC_ADULT_BIRTHDATE, 10, OIDC_ADULT_SUB),
    );
}

#[capacities(1, "")]
fn test_age_year_only<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_YEARONLY,
        OIDC_YEARONLY_C,
        age19(),
        at(0, OIDC_YEARONLY_BIRTHDATE, 4, OIDC_YEARONLY_SUB),
    );
}

#[capacities(1, "")]
fn test_age_turns_19_on_proof_date<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_EXACT19,
        OIDC_EXACT19_C,
        age19(),
        at(0, OIDC_EXACT19_BIRTHDATE, 10, OIDC_EXACT19_SUB),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_age_one_day_short_of_19_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_DAYSHORT,
        OIDC_DAYSHORT_C,
        age19(),
        at(0, OIDC_DAYSHORT_BIRTHDATE, 10, OIDC_DAYSHORT_SUB),
    );
}

#[capacities(1, "value not closed")]
fn test_age_truncated_to_year_fails<let A: u32>() {
    // Reading only "2007" of "2007-11-17" would switch to the year-only rule and pass.
    ok_whole::<T, _, A>(
        OIDC_DAYSHORT,
        OIDC_DAYSHORT_C,
        age19(),
        at(0, OIDC_DAYSHORT_BIRTHDATE, 4, OIDC_DAYSHORT_SUB),
    );
}

#[capacities(1, "predicate does not hold")]
fn test_age_under_age_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_MINOR,
        OIDC_MINOR_C,
        age19(),
        at(0, OIDC_MINOR_BIRTHDATE, 10, OIDC_MINOR_SUB),
    );
}

#[capacities(1, "birth year missing (0000)")]
fn test_age_zero_year_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_ZEROYEAR,
        OIDC_ZEROYEAR_C,
        age19(),
        at(0, OIDC_ZEROYEAR_BIRTHDATE, 10, OIDC_ZEROYEAR_SUB),
    );
}

#[capacities(1, "key quote is inside a string")]
fn test_age_date_inside_nickname_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_NICKATTACK,
        OIDC_NICKATTACK_C,
        age19(),
        at(0, OIDC_NICKATTACK_FAKE, 10, OIDC_NICKATTACK_SUB),
    );
}

#[capacities(1, "segment is not directly inside the previous value")]
fn test_age_nested_birthdate_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_NESTED,
        OIDC_NESTED_C,
        age19(),
        at(0, OIDC_NESTED_FAKE, 10, OIDC_NESTED_SUB),
    );
}

#[capacities(1, "")]
fn test_brackets_inside_string_ignored<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_BRACKETS,
        OIDC_BRACKETS_C,
        age19(),
        at(0, OIDC_BRACKETS_BIRTHDATE, 10, OIDC_BRACKETS_SUB),
    );
}

#[capacities(1, "key quote is inside a string")]
fn test_offset_shifted_by_one_fails<let A: u32>() {
    ok_whole::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT_C,
        age19(),
        at(0, OIDC_ADULT_BIRTHDATE + 1, 10, OIDC_ADULT_SUB),
    );
}

#[capacities(1, "key name mismatch")]
fn test_wrong_key_fails<let A: u32>() {
    let c = oidc_claim("birthyear", KIND_STRING, OP_AGE_GTE, "19");
    ok_whole::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT_C,
        c,
        at(0, OIDC_ADULT_BIRTHDATE, 10, OIDC_ADULT_SUB),
    );
}

// ---- commitment, nullifier, schema, size ------------------------------

#[capacities(1, "prefix does not open the commitment")]
fn test_body_changed_fails<let A: u32>() {
    // Minor's body presented with the adult's commitment.
    ok_whole::<T, _, A>(
        OIDC_MINOR,
        OIDC_ADULT_C,
        age19(),
        at(0, OIDC_MINOR_BIRTHDATE, 10, OIDC_MINOR_SUB),
    );
}

#[capacities(1, "prefix does not open the commitment")]
fn test_wrong_blinder_fails<let A: u32>() {
    let c = age19();
    let mut blinder = BLINDER;
    blinder[15] = 0;
    run_full::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT.as_bytes().len(),
        true,
        OIDC_ADULT_C,
        blinder,
        c,
        at(0, OIDC_ADULT_BIRTHDATE, 10, OIDC_ADULT_SUB),
        claim_hash_of(c, T),
        nullifier_of(c),
    );
}

#[capacities(1, "nullifier mismatch")]
fn test_nullifier_mismatch_fails<let A: u32>() {
    let c = age19();
    let mut nf = nullifier_of(c);
    nf[0] = nf[0] ^ 1;
    run_full::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT.as_bytes().len(),
        true,
        OIDC_ADULT_C,
        BLINDER,
        c,
        at(0, OIDC_ADULT_BIRTHDATE, 10, OIDC_ADULT_SUB),
        claim_hash_of(c, T),
        nf,
    );
}

#[capacities(1, "claim hash mismatch")]
fn test_schema_hash_mismatch_fails<let A: u32>() {
    // Operand 19 in the public inputs, schema hash made for operand 18.
    let c = age19();
    let schema = claim_hash_of(oidc_claim("birthdate", KIND_STRING, OP_AGE_GTE, "18"), T);
    run_full::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT.as_bytes().len(),
        true,
        OIDC_ADULT_C,
        BLINDER,
        c,
        at(0, OIDC_ADULT_BIRTHDATE, 10, OIDC_ADULT_SUB),
        schema,
        nullifier_of(c),
    );
}

#[capacities(1, "claim hash mismatch")]
fn test_schema_hash_covers_parent<let A: u32>() {
    // Same child key, schema hash made for a different parent.
    let c = me_age_range_claim("20");
    let mut other = me_age_range_claim("20");
    other.asserts[0].path = crate::testkit::p2("properties", "age_range");
    run_full::<T, _, A>(
        ME_30,
        ME_30.as_bytes().len(),
        true,
        ME_30_C,
        BLINDER,
        c,
        at(ME_30_KA, ME_30_AGE_RANGE, 5, ME_30_ID),
        claim_hash_of(other, T),
        nullifier_of(c),
    );
}

#[capacities(1, "prefix longer than the tier")]
fn test_prefix_len_over_tier_fails<let A: u32>() {
    let c = age19();
    run_full::<T, _, A>(
        OIDC_ADULT,
        T + 1,
        true,
        OIDC_ADULT_C,
        BLINDER,
        c,
        at(0, OIDC_ADULT_BIRTHDATE, 10, OIDC_ADULT_SUB),
        claim_hash_of(c, T),
        nullifier_of(c),
    );
}

// ---- prefix commitments -------------------------------------------------

#[capacities(1, "")]
fn test_prefix_of_longer_body_proves_age<let A: u32>() {
    // OIDC_TAIL is longer than the tier; every member the claim uses sits
    // in the first T bytes, and the prefix ends inside a long string.
    ok_prefix::<T, _, A>(
        OIDC_TAIL,
        OIDC_TAIL_P1024_C,
        age19(),
        at(0, OIDC_TAIL_BIRTHDATE, 10, OIDC_TAIL_SUB),
    );
}

#[capacities(1, "")]
fn test_prefix_of_longer_body_proves_literal<let A: u32>() {
    let c = oidc_claim("email_verified", KIND_LITERAL, OP_EQ, "true");
    ok_prefix::<T, _, A>(
        OIDC_TAIL,
        OIDC_TAIL_P1024_C,
        c,
        at(0, OIDC_TAIL_EMAIL_VERIFIED, 4, OIDC_TAIL_SUB),
    );
}

#[capacities(1, "segment token past prefix")]
fn test_member_beyond_prefix_fails<let A: u32>() {
    // ME_LONG's age_range sits past byte 1024.
    ok_prefix::<T, _, A>(
        ME_LONG,
        ME_LONG_P1024_C,
        me_age_range_claim("20"),
        at(ME_LONG_KA, ME_LONG_AGE_RANGE, 5, ME_LONG_ID),
    );
}

#[capacities(1, "value runs past prefix")]
fn test_literal_cut_at_prefix_end_fails<let A: u32>() {
    // "true" ends at the last prefix byte; the comma that closes it is outside.
    let c = oidc_claim("email_verified", KIND_LITERAL, OP_EQ, "true");
    ok_prefix::<CUT_LITERAL_N, _, A>(
        OIDC_ADULT,
        CUT_LITERAL_C,
        c,
        at(0, OIDC_ADULT_EMAIL_VERIFIED, 4, OIDC_ADULT_SUB),
    );
}

#[capacities(1, "value runs past prefix")]
fn test_string_cut_at_prefix_end_fails<let A: u32>() {
    // The birthdate ends at the last prefix byte; its closing quote is outside.
    ok_prefix::<CUT_STRING_N, _, A>(
        OIDC_ADULT,
        CUT_STRING_C,
        age19(),
        at(0, OIDC_ADULT_BIRTHDATE, 10, OIDC_ADULT_SUB),
    );
}

#[capacities(1, "literal not closed")]
fn test_literal_shortened_to_fit_prefix_fails<let A: u32>() {
    // The prefix ends inside "false"; reading "fal" so that it fits is not the whole literal.
    let c = oidc_claim("email_verified", KIND_LITERAL, OP_EQ, "fal");
    ok_prefix::<CUT_INSIDE_FALSE_N, _, A>(
        OIDC_UNVERIFIED,
        CUT_INSIDE_FALSE_C,
        c,
        at(0, OIDC_UNVERIFIED_EMAIL_VERIFIED, 3, OIDC_UNVERIFIED_SUB),
    );
}

#[capacities(1, "a partial prefix must be exactly the tier size")]
fn test_partial_prefix_shorter_than_tier_fails<let A: u32>() {
    let c = age19();
    run_full::<T, _, A>(
        OIDC_TAIL,
        1000,
        false,
        OIDC_TAIL_P1024_C,
        BLINDER,
        c,
        at(0, OIDC_TAIL_BIRTHDATE, 10, OIDC_TAIL_SUB),
        claim_hash_of(c, T),
        nullifier_of(c),
    );
}

#[capacities(1, "unterminated JSON string")]
fn test_truncated_prefix_claimed_whole_fails<let A: u32>() {
    // The verifier sets `whole` only when the commitment covers the entire body.
    let c = age19();
    run_full::<T, _, A>(
        OIDC_TAIL,
        T,
        true,
        OIDC_TAIL_P1024_C,
        BLINDER,
        c,
        at(0, OIDC_TAIL_BIRTHDATE, 10, OIDC_TAIL_SUB),
        claim_hash_of(c, T),
        nullifier_of(c),
    );
}

#[capacities(1, "prefix does not open the commitment")]
fn test_whole_body_commitment_with_prefix_fails<let A: u32>() {
    ok_prefix::<T, _, A>(
        OIDC_TAIL,
        OIDC_TAIL_C,
        age19(),
        at(0, OIDC_TAIL_BIRTHDATE, 10, OIDC_TAIL_SUB),
    );
}

#[capacities(1, "claim hash mismatch")]
fn test_schema_hash_covers_tier<let A: u32>() {
    // A schema hash made for the 2 KB tier does not verify in this one.
    let c = age19();
    run_full::<T, _, A>(
        OIDC_ADULT,
        OIDC_ADULT.as_bytes().len(),
        true,
        OIDC_ADULT_C,
        BLINDER,
        c,
        at(0, OIDC_ADULT_BIRTHDATE, 10, OIDC_ADULT_SUB),
        claim_hash_of(c, 2048),
        nullifier_of(c),
    );
}
