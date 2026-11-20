// What a secret header value proof accepts and refuses, at a 512-byte tier.

use super::{BLINDER_LEN, pad, verify_secret_value};
use super::vectors::{
    BEARER, BEARER_C, BLINDER, CR, CR_C, CRLF_HDR, CRLF_HDR_C, DEL, DEL_C, FULL512, FULL512_C,
    LF, LF_C, NUL, NUL_C, OBS, OBS_C, OTHER_BLINDER, TAB, TAB_C,
};

global N: u32 = 512;

fn check<let M: u32>(v: [u8; M], blinder: [u8; BLINDER_LEN], c: [u8; 32]) {
    let (value, len) = pad::<M, N>(v);
    verify_secret_value::<N>(value, len, blinder, c);
}

#[test]
fn test_bearer_token_accepted() {
    check(BEARER, BLINDER, BEARER_C);
}

#[test]
fn test_tab_accepted() {
    check(TAB, BLINDER, TAB_C);
}

#[test]
fn test_obs_text_accepted() {
    check(OBS, BLINDER, OBS_C);
}

#[test]
fn test_exactly_the_limit_accepted() {
    check(FULL512, BLINDER, FULL512_C);
}

#[test(should_fail_with = "control byte in a header value")]
fn test_cr_refused() {
    check(CR, BLINDER, CR_C);
}

#[test(should_fail_with = "control byte in a header value")]
fn test_lf_refused() {
    check(LF, BLINDER, LF_C);
}

#[test(should_fail_with = "control byte in a header value")]
fn test_crlf_and_injected_header_refused() {
    check(CRLF_HDR, BLINDER, CRLF_HDR_C);
}

#[test(should_fail_with = "control byte in a header value")]
fn test_nul_refused() {
    check(NUL, BLINDER, NUL_C);
}

#[test(should_fail_with = "control byte in a header value")]
fn test_del_refused() {
    check(DEL, BLINDER, DEL_C);
}

#[test(should_fail_with = "secret value does not open the commitment")]
fn test_wrong_blinder_refused() {
    check(BEARER, OTHER_BLINDER, BEARER_C);
}

#[test(should_fail_with = "secret value does not open the commitment")]
fn test_changed_byte_refused() {
    let (mut value, len) = pad::<_, N>(BEARER);
    value[10] = value[10] + 1;
    verify_secret_value::<N>(value, len, BLINDER, BEARER_C);
}

#[test(should_fail_with = "secret value does not open the commitment")]
fn test_truncated_length_refused() {
    let (value, len) = pad::<_, N>(BEARER);
    verify_secret_value::<N>(value, len - 1, BLINDER, BEARER_C);
}

#[test(should_fail_with = "empty secret value")]
fn test_length_zero_refused() {
    let (value, _) = pad::<_, N>(BEARER);
    verify_secret_value::<N>(value, 0, BLINDER, BEARER_C);
}

#[test(should_fail_with = "secret value longer than the tier")]
fn test_limit_plus_one_refused() {
    let (value, _) = pad::<_, N>(FULL512);
    verify_secret_value::<N>(value, N + 1, BLINDER, FULL512_C);
}

#[test(should_fail_with = "secret value does not open the commitment")]
fn test_commitment_of_another_value_refused() {
    check(BEARER, BLINDER, TAB_C);
}
