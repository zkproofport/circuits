// X.509 UTCTime -> unix seconds, for the validity checks.
//
// Only UTCTime ("YYMMDDHHMMSSZ", tag 0x17, 13 bytes) is accepted, and only
// years 2000-2049: every certificate whose validity this library checks
// (Droid CA2, Droid CA3, the RKP attestation-key certificate) is issued by
// Google in that range. RFC 5280 says UTCTime YY >= 50 means 19YY and dates
// from 2050 must be GeneralizedTime; both are refused here by name rather
// than misread.

/// The two-digit decimal at `pos`, each byte asserted to be '0'..'9'.
fn two_digits<let N: u32>(buf: [u8; N], pos: u32) -> u64 {
    let a = buf[pos];
    let b = buf[pos + 1];
    assert(
        (a >= 0x30) & (a <= 0x39) & (b >= 0x30) & (b <= 0x39),
        "Certificate time is not decimal",
    );
    ((a - 0x30) as u64) * 10 + ((b - 0x30) as u64)
}

/// Days from 1970-01-01 to the civil date y-m-d, for 2000 <= y < 2050
/// (Howard Hinnant's days_from_civil, without negative intermediates).
pub fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The UTCTime element starting at `pos` (its tag byte), as unix seconds.
pub fn utc_time<let N: u32>(buf: [u8; N], pos: u32) -> u64 {
    assert((buf[pos] == 0x17) & (buf[pos + 1] == 13), "Certificate time is not a UTCTime");
    assert(buf[pos + 14] == 0x5a, "Certificate time is not in UTC");
    let p = pos + 2;
    let yy = two_digits(buf, p);
    assert(yy < 50, "Certificate time is outside 2000-2049");
    let month = two_digits(buf, p + 2);
    let day = two_digits(buf, p + 4);
    let hour = two_digits(buf, p + 6);
    let minute = two_digits(buf, p + 8);
    let second = two_digits(buf, p + 10);
    assert((month >= 1) & (month <= 12), "Certificate time has no such month");
    assert((day >= 1) & (day <= 31), "Certificate time has no such day");
    assert((hour < 24) & (minute < 60) & (second < 60), "Certificate time has no such time of day");
    days_from_civil(2000 + yy, month, day) * 86400 + hour * 3600 + minute * 60 + second
}

#[test]
fn known_dates() {
    assert(days_from_civil(2000, 1, 1) == 10957);
    assert(days_from_civil(2000, 3, 1) == 11017); // 2000 is a leap year
    assert(days_from_civil(2026, 2, 22) == 20506);
    assert(days_from_civil(2049, 12, 31) == 29219);
}

#[test]
fn a_real_not_after() {
    // "260308002600Z": the RKP attestation-key certificate in tests.nr
    // (tegu, Android 16) expires 2026-03-08 00:26:00 UTC = 1772929560.
    let t: [u8; 15] =
        [0x17, 0x0d, 0x32, 0x36, 0x30, 0x33, 0x30, 0x38, 0x30, 0x30, 0x32, 0x36, 0x30, 0x30, 0x5a];
    assert(utc_time(t, 0) == 1772929560);
}

#[test(should_fail_with = "Certificate time is outside 2000-2049")]
fn the_1900s_are_refused() {
    let t: [u8; 15] =
        [0x17, 0x0d, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a];
    let _ = utc_time(t, 0);
}

#[test(should_fail_with = "Certificate time is not a UTCTime")]
fn generalized_time_is_refused() {
    let t: [u8; 17] = [
        0x18, 0x0f, 0x32, 0x30, 0x35, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x5a,
    ];
    let _ = utc_time(t, 0);
}

#[test(should_fail_with = "Certificate time has no such month")]
fn month_13_is_refused() {
    let t: [u8; 15] =
        [0x17, 0x0d, 0x32, 0x36, 0x31, 0x33, 0x30, 0x38, 0x30, 0x30, 0x32, 0x36, 0x30, 0x30, 0x5a];
    let _ = utc_time(t, 0);
}
