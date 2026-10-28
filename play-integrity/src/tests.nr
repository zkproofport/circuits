// A REAL Google-signed verdict (zkPassport's app, UNRECOGNIZED_VERSION) and
// synthetic verdicts signed with the INSECURE test key, one field changed each.
use crate::{IntegrityToken, verify_integrity_token};
use crate::test_vectors::{
    BASIC_ONLY_LEN, BASIC_ONLY_PAYLOAD, BASIC_ONLY_SIG, NO_VERDICT_LEN, NO_VERDICT_PAYLOAD,
    NO_VERDICT_SIG, NONCE, NONCE_PADDED_RAW_LEN, NONCE_PADDED_RAW_PAYLOAD, NONCE_PADDED_RAW_SIG,
    OK_ALL_THREE_LEN, OK_ALL_THREE_PAYLOAD, OK_ALL_THREE_SIG, OK_DEVICE_LEN, OK_DEVICE_PAYLOAD,
    OK_DEVICE_SIG, OK_PADDED_NONCE_LEN, OK_PADDED_NONCE_PAYLOAD, OK_PADDED_NONCE_SIG,
    OK_STRONG_ONLY_LEN, OK_STRONG_ONLY_PAYLOAD, OK_STRONG_ONLY_SIG, OTHER_APP_PACKAGE_LEN,
    OTHER_APP_PACKAGE_PAYLOAD, OTHER_APP_PACKAGE_SIG, OTHER_NONCE_LEN, OTHER_NONCE_PAYLOAD,
    OTHER_NONCE_SIG, OTHER_REQUEST_PACKAGE_LEN, OTHER_REQUEST_PACKAGE_PAYLOAD,
    OTHER_REQUEST_PACKAGE_SIG, REAL_KEY, REAL_LEN, REAL_PACKAGE, REAL_PAYLOAD, REAL_SIG, TEST_KEY,
    UNRECOGNIZED_LEN, UNRECOGNIZED_PAYLOAD, UNRECOGNIZED_SIG,
};

global OUR_PACKAGE: [u8; 25] = [
    0x63, 0x6f, 0x6d, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x2e, 0x7a, 0x6b,
    0x70, 0x72, 0x6f, 0x6f, 0x66, 0x70, 0x6f, 0x72, 0x74,
];

fn split(k: [u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut x: [u8; 32] = [0; 32];
    let mut y: [u8; 32] = [0; 32];
    for i in 0..32 {
        x[i] = k[i];
        y[i] = k[32 + i];
    }
    (x, y)
}

fn check(p: [u8; 1368], len: u32, sig: [u8; 64]) {
    let (x, y) = split(TEST_KEY);
    verify_integrity_token(
        IntegrityToken { payload_b64: p, payload_b64_len: len, signature: sig },
        x,
        y,
        OUR_PACKAGE,
        NONCE,
    );
}

// ---- the real verdict ---------------------------------------------------------

#[test(should_fail_with = "App is not recognized by Google Play")]
fn googles_real_signature_verifies_and_its_unrecognized_app_is_refused() {
    let (x, y) = split(REAL_KEY);
    verify_integrity_token(
        IntegrityToken {
            payload_b64: REAL_PAYLOAD,
            payload_b64_len: REAL_LEN,
            signature: REAL_SIG,
        },
        x,
        y,
        REAL_PACKAGE,
        NONCE,
    );
}

#[test(should_fail_with = "Integrity verdict was requested by another app")]
fn a_real_verdict_for_another_app_is_not_ours() {
    let (x, y) = split(REAL_KEY);
    verify_integrity_token(
        IntegrityToken {
            payload_b64: REAL_PAYLOAD,
            payload_b64_len: REAL_LEN,
            signature: REAL_SIG,
        },
        x,
        y,
        OUR_PACKAGE,
        NONCE,
    );
}

#[test(should_fail_with = "Integrity verdict is not signed by Google Play")]
fn one_changed_character_of_a_real_verdict_is_refused() {
    let (x, y) = split(REAL_KEY);
    let mut p = REAL_PAYLOAD;
    p[100] = if p[100] == 0x41 { 0x42 } else { 0x41 };
    verify_integrity_token(
        IntegrityToken { payload_b64: p, payload_b64_len: REAL_LEN, signature: REAL_SIG },
        x,
        y,
        REAL_PACKAGE,
        NONCE,
    );
}

#[test(should_fail_with = "Integrity verdict is not signed by Google Play")]
fn a_real_verdict_under_another_key_is_refused() {
    let (x, y) = split(TEST_KEY);
    verify_integrity_token(
        IntegrityToken {
            payload_b64: REAL_PAYLOAD,
            payload_b64_len: REAL_LEN,
            signature: REAL_SIG,
        },
        x,
        y,
        REAL_PACKAGE,
        NONCE,
    );
}

// ---- accepted ---------------------------------------------------------------------

#[test]
fn device_integrity_is_accepted() {
    check(OK_DEVICE_PAYLOAD, OK_DEVICE_LEN, OK_DEVICE_SIG);
}

#[test]
fn strong_integrity_alone_is_accepted() {
    check(
        OK_STRONG_ONLY_PAYLOAD,
        OK_STRONG_ONLY_LEN,
        OK_STRONG_ONLY_SIG,
    );
}

#[test]
fn all_three_verdicts_are_accepted() {
    check(OK_ALL_THREE_PAYLOAD, OK_ALL_THREE_LEN, OK_ALL_THREE_SIG);
}

#[test]
fn a_nonce_echoed_with_an_escaped_pad_is_accepted() {
    check(
        OK_PADDED_NONCE_PAYLOAD,
        OK_PADDED_NONCE_LEN,
        OK_PADDED_NONCE_SIG,
    );
}

// ---- refused ----------------------------------------------------------------------

#[test(should_fail_with = "Device does not meet Play device integrity")]
fn basic_integrity_alone_is_refused() {
    check(BASIC_ONLY_PAYLOAD, BASIC_ONLY_LEN, BASIC_ONLY_SIG);
}

#[test(should_fail_with = "Device does not meet Play device integrity")]
fn no_device_verdict_is_refused() {
    check(NO_VERDICT_PAYLOAD, NO_VERDICT_LEN, NO_VERDICT_SIG);
}

#[test(should_fail_with = "App is not recognized by Google Play")]
fn an_unrecognized_version_is_refused() {
    check(UNRECOGNIZED_PAYLOAD, UNRECOGNIZED_LEN, UNRECOGNIZED_SIG);
}

#[test(should_fail_with = "Integrity verdict was requested by another app")]
fn a_request_from_another_package_is_refused() {
    check(
        OTHER_REQUEST_PACKAGE_PAYLOAD,
        OTHER_REQUEST_PACKAGE_LEN,
        OTHER_REQUEST_PACKAGE_SIG,
    );
}

#[test(should_fail_with = "Integrity verdict is for another app")]
fn a_verdict_for_another_package_is_refused() {
    check(
        OTHER_APP_PACKAGE_PAYLOAD,
        OTHER_APP_PACKAGE_LEN,
        OTHER_APP_PACKAGE_SIG,
    );
}

#[test(should_fail_with = "Integrity verdict nonce is not this statement's")]
fn another_statements_verdict_is_refused() {
    check(OTHER_NONCE_PAYLOAD, OTHER_NONCE_LEN, OTHER_NONCE_SIG);
}

#[test(should_fail_with = "Integrity verdict nonce is not this statement's")]
fn a_raw_pad_character_is_refused() {
    check(
        NONCE_PADDED_RAW_PAYLOAD,
        NONCE_PADDED_RAW_LEN,
        NONCE_PADDED_RAW_SIG,
    );
}

#[test(should_fail_with = "Integrity token padding is not zero")]
fn bytes_after_the_payload_are_refused() {
    let mut p = OK_DEVICE_PAYLOAD;
    p[OK_DEVICE_LEN] = 0x41;
    check(p, OK_DEVICE_LEN, OK_DEVICE_SIG);
}

#[test(should_fail_with = "Integrity verdict is not signed by Google Play")]
fn a_high_s_signature_is_refused() {
    let n: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut sig = OK_DEVICE_SIG;
    let mut borrow: i16 = 0;
    for j in 0..32 {
        let i = 31 - j;
        let mut d = (n[i] as i16) - (sig[32 + i] as i16) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        sig[32 + i] = d as u8;
    }
    check(OK_DEVICE_PAYLOAD, OK_DEVICE_LEN, sig);
}

#[test(should_fail_with = "Integrity token payload length out of range")]
fn an_empty_token_is_refused() {
    check([0; 1368], 0, OK_DEVICE_SIG);
}
