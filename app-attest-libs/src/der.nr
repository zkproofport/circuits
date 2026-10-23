// Bounded DER reading at witness-chosen positions.
//
// Every read here is at an offset the prover supplies indirectly (through the
// bytes of a certificate), so every function asserts what it relies on rather
// than trusting the shape. Only the length forms an App Attest credential
// certificate uses are accepted: short form, 0x81 and 0x82. A longer form is
// refused, never misread.

/// Length field starting at `pos`: (bytes the length field occupies, content length).
pub fn der_length<let N: u32>(buf: [u8; N], pos: u32) -> (u32, u32) {
    let b = buf[pos];
    let mut field_len: u32 = 1;
    let mut content_len: u32 = b as u32;
    if b == 0x81 {
        field_len = 2;
        content_len = buf[pos + 1] as u32;
        assert(content_len >= 0x80, "DER length is not minimal");
    } else if b == 0x82 {
        field_len = 3;
        content_len = (buf[pos + 1] as u32) * 256 + (buf[pos + 2] as u32);
        assert(content_len >= 0x100, "DER length is not minimal");
    } else {
        assert(b < 0x80, "Unsupported DER length form");
    }
    (field_len, content_len)
}

/// A one-byte-tag element at `pos`: (header length, content length), with the
/// tag checked.
pub fn der_element<let N: u32>(buf: [u8; N], pos: u32, tag: u8) -> (u32, u32) {
    assert(buf[pos] == tag, "Unexpected DER tag");
    let (field_len, content_len) = der_length(buf, pos + 1);
    (1 + field_len, content_len)
}

/// True when `want` sits at `pos`.
pub fn bytes_at<let N: u32, let M: u32>(buf: [u8; N], pos: u32, want: [u8; M]) -> bool {
    let mut same = true;
    for i in 0..M {
        same &= buf[pos + i] == want[i];
    }
    same
}

/// M bytes from `pos`.
pub fn slice_at<let N: u32, let M: u32>(buf: [u8; N], pos: u32) -> [u8; M] {
    let mut out: [u8; M] = [0; M];
    for i in 0..M {
        out[i] = buf[pos + i];
    }
    out
}

#[test]
fn short_and_long_lengths() {
    let buf: [u8; 8] = [0x30, 0x05, 0x30, 0x81, 0x90, 0x30, 0x82, 0x01];
    assert(der_length(buf, 1) == (1, 5));
    assert(der_length(buf, 3) == (2, 0x90));
}

#[test(should_fail_with = "DER length is not minimal")]
fn a_long_form_short_length_is_refused() {
    let buf: [u8; 3] = [0x30, 0x81, 0x05];
    let _ = der_length(buf, 1);
}

#[test(should_fail_with = "Unsupported DER length form")]
fn a_three_byte_length_is_refused() {
    let buf: [u8; 6] = [0x30, 0x83, 0x01, 0x00, 0x00, 0x00];
    let _ = der_length(buf, 1);
}
