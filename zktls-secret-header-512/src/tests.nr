// The 512 tier through its own main: a bearer token, a value of exactly 512 bytes,
// an injected header line, and one byte past the tier.

use super::{main, TIER};
use zktls_secret_header_libs::pad;
use zktls_secret_header_libs::vectors::{BEARER, BEARER_C, BLINDER, CRLF_HDR, CRLF_HDR_C, FULL512, FULL512_C};

#[test]
fn test_512_bearer_token() {
    let (value, len) = pad::<_, TIER>(BEARER);
    main(value, len, BLINDER, BEARER_C);
}

#[test]
fn test_512_exactly_the_tier() {
    let (value, len) = pad::<_, TIER>(FULL512);
    main(value, len, BLINDER, FULL512_C);
}

#[test(should_fail_with = "control byte in a header value")]
fn test_512_injected_header_refused() {
    let (value, len) = pad::<_, TIER>(CRLF_HDR);
    main(value, len, BLINDER, CRLF_HDR_C);
}

#[test(should_fail_with = "secret value longer than the tier")]
fn test_512_one_byte_past_the_tier_refused() {
    let (value, _) = pad::<_, TIER>(FULL512);
    main(value, TIER + 1, BLINDER, FULL512_C);
}
