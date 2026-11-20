// A hidden secret header value is a single, well-formed header value.
//
// In a zkTLS session the verifier sees every request byte except the values of the
// secret headers the proof request names (Authorization, Cookie). Without this proof a
// prover could put `\r\n` and extra header lines inside its own credential bytes (a
// method override, a second Host) and change what the server does, while the revealed
// bytes still match the definition exactly.
//
// The prover therefore commits each hidden value range with TLSNotary, in the same
// format as the body commitment, and proves here that
//   1. `value[0..len]` opens `commitment` = SHA-256(value[0..len] || blinder[16]), and
//   2. every byte of it is a header-value byte: HTAB (0x09), or 0x20..=0xFF except
//      DEL (0x7F). That excludes CR, LF, NUL and every other control byte, so the value
//      cannot end its header line or start another one. Bytes 0x80..=0xFF (obs-text in
//      RFC 9110 section 5.5) are allowed.
//
// The verifier binds `commitment` to the hidden range: it requires exactly one sent
// commitment per hidden range, covering that range exactly, and signs its hash into the
// session result. The relying party checks that this proof's public `commitment` equals
// the signed one.

use sha256::sha256_var;

pub mod vectors;
mod tests;

pub global BLINDER_LEN: u32 = 16;

/// `v` zero-padded to `T` bytes, with its length: the form a tier's `value` input takes.
pub fn pad<let M: u32, let T: u32>(v: [u8; M]) -> ([u8; T], u32) {
    assert(M <= T, "value longer than the tier");
    let mut out = [0; T];
    for i in 0..M {
        out[i] = v[i];
    }
    (out, M)
}

/// Whether `c` may appear in a header value.
pub fn is_value_byte(c: u8) -> bool {
    (c == 9) | ((c >= 32) & (c != 127))
}

/// Asserts that `value[0..len]` opens `commitment` and holds only header-value bytes.
/// Bytes of `value` at or past `len` are ignored.
pub fn verify_secret_value<let N: u32>(
    value: [u8; N],
    len: u32,
    blinder: [u8; BLINDER_LEN],
    commitment: [u8; 32],
) {
    assert(len > 0, "empty secret value");
    assert(len <= N, "secret value longer than the tier");
    let mut buf: [u8; N + BLINDER_LEN] = [0; N + BLINDER_LEN];
    for i in 0..N {
        if i < len {
            let c = value[i];
            assert(is_value_byte(c), "control byte in a header value");
            buf[i] = c;
        }
    }
    for j in 0..BLINDER_LEN {
        buf[len + j] = blinder[j];
    }
    let digest = sha256_var(buf, len + BLINDER_LEN);
    assert(digest == commitment, "secret value does not open the commitment");
}
