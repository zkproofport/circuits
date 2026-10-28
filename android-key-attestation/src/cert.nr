// One X.509 TBSCertificate, walked field by field with bounded DER (no
// pattern search), the way app-attest-libs walks Apple's certificates.
//
// FORMAT ASSUMPTIONS, each read from real Google chains (android/keyattestation
// testdata, see tests.nr): version v3, a serial of 1..20 bytes, the signature
// AlgorithmIdentifier, issuer / validity / subject in that order, the SPKI,
// then [3] extensions and nothing after them. Issuer and subject names are
// not compared: the issuer's signature over the TBS is what binds them.

use crate::time::utc_time;
use app_attest::der::{bytes_at, der_element, der_length};

/// At most this many extensions are walked. Droid CA3 has 6, the others fewer.
global MAX_EXTENSIONS: u32 = 8;

/// [0] { INTEGER 2 } -- X.509 v3.
global VERSION_V3: [u8; 5] = [0xa0, 0x03, 0x02, 0x01, 0x02];

/// AlgorithmIdentifier ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
pub global SIG_ALG_ECDSA_SHA256: [u8; 12] =
    [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// AlgorithmIdentifier ecdsa-with-SHA384 (1.2.840.10045.4.3.3).
pub global SIG_ALG_ECDSA_SHA384: [u8; 12] =
    [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

/// AlgorithmIdentifier sha256WithRSAEncryption (1.2.840.113549.1.1.11), NULL
/// parameters: how Google's RSA root signs factory intermediates.
pub global SIG_ALG_SHA256_RSA: [u8; 15] =
    [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00];

/// SubjectPublicKeyInfo of an uncompressed P-256 key, through the 0x04 marker.
pub global SPKI_P256_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
/// SubjectPublicKeyInfo of an uncompressed P-384 key, through the 0x04 marker.
pub global SPKI_P384_PREFIX: [u8; 24] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
];

/// OBJECT IDENTIFIER 2.5.29.19 (basicConstraints), tag and length included.
pub global OID_BASIC_CONSTRAINTS: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x13];
/// OBJECT IDENTIFIER 1.3.6.1.4.1.11129.2.1.17, the key attestation extension.
pub global OID_KEY_ATTESTATION: [u8; 12] =
    [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11];
/// OBJECT IDENTIFIER 1.3.6.1.4.1.11129.2.1.30, the provisioning information
/// extension Google's Remote Key Provisioning server puts on the
/// attestation-key certificate.
pub global OID_PROVISIONING_INFO: [u8; 12] =
    [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x1e];

/// Where a walked TBS keeps what the chain checks need.
pub struct Tbs {
    pub not_before: u64,
    pub not_after: u64,
    /// Offset of the SubjectPublicKeyInfo SEQUENCE.
    pub spki: u32,
    /// The extension list's content: [ext_start, ext_end), ext_end == length.
    pub ext_start: u32,
    pub ext_end: u32,
}

/// Walk the TBS: its own length, zero padding, v3, the serial, the
/// signature algorithm (`sig_alg`, the one its issuer used), the validity
/// (as unix seconds when `read_validity`, zeros otherwise), and the bounds of
/// the SPKI and the extension list.
pub fn walk_tbs<let N: u32, let K: u32>(
    tbs: [u8; N],
    tbs_len: u32,
    sig_alg: [u8; K],
    read_validity: bool,
) -> Tbs {
    assert(tbs_len <= N, "Certificate TBS longer than the circuit allows");
    let (outer_hl, outer_cl) = der_element(tbs, 0, 0x30);
    assert(outer_hl + outer_cl == tbs_len, "Certificate TBS length does not match its header");
    for i in 0..N {
        if i >= tbs_len {
            assert(tbs[i] == 0, "Certificate TBS padding is not zero");
        }
    }
    let mut pos = outer_hl;

    assert(bytes_at(tbs, pos, VERSION_V3), "Certificate is not X.509 v3");
    pos += 5;

    let (shl, scl) = der_element(tbs, pos, 0x02);
    assert((scl >= 1) & (scl <= 20), "Certificate serial length out of range");
    pos += shl + scl;

    assert(bytes_at(tbs, pos, sig_alg), "Certificate is signed with another algorithm");
    pos += K;

    // issuer
    let (ihl, icl) = der_element(tbs, pos, 0x30);
    pos += ihl + icl;

    // validity ::= SEQUENCE { notBefore Time, notAfter Time }
    let (vhl, vcl) = der_element(tbs, pos, 0x30);
    let mut not_before: u64 = 0;
    let mut not_after: u64 = 0;
    if read_validity {
        assert(vcl == 30, "Certificate validity is not two UTCTimes");
        not_before = utc_time(tbs, pos + vhl);
        not_after = utc_time(tbs, pos + vhl + 15);
    }
    pos += vhl + vcl;

    // subject
    let (jhl, jcl) = der_element(tbs, pos, 0x30);
    pos += jhl + jcl;

    let spki = pos;
    let (khl, kcl) = der_element(tbs, pos, 0x30);
    pos += khl + kcl;

    // [3] { SEQUENCE OF Extension }, ending exactly at the end of the TBS.
    let (ehl, ecl) = der_element(tbs, pos, 0xa3);
    let ext_end = pos + ehl + ecl;
    assert(ext_end == tbs_len, "Certificate extensions are not the last TBS field");
    pos += ehl;
    let (lhl, lcl) = der_element(tbs, pos, 0x30);
    assert(pos + lhl + lcl == ext_end, "Certificate extension list length mismatch");

    Tbs { not_before, not_after, spki, ext_start: pos + lhl, ext_end }
}

/// How many extensions carry `oid` (tag and length included), and the
/// content of the last one's extnValue OCTET STRING: (count, start, length).
/// Every extension is walked by its own length and must end where it says.
pub fn find_extension<let N: u32, let K: u32>(
    tbs: [u8; N],
    t: Tbs,
    oid: [u8; K],
) -> (u32, u32, u32) {
    let mut pos = t.ext_start;
    let mut count: u32 = 0;
    let mut start: u32 = 0;
    let mut len: u32 = 0;
    for _ in 0..MAX_EXTENSIONS {
        if pos < t.ext_end {
            // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
            let (hl, cl) = der_element(tbs, pos, 0x30);
            let next = pos + hl + cl;
            let oid_pos = pos + hl;
            let (ohl, ocl) = der_element(tbs, oid_pos, 0x06);
            let same = (ohl + ocl == K) & bytes_at(tbs, oid_pos, oid);
            let mut v = oid_pos + ohl + ocl;
            if tbs[v] == 0x01 {
                let (bhl, bcl) = der_element(tbs, v, 0x01);
                v += bhl + bcl;
            }
            let (xhl, xcl) = der_element(tbs, v, 0x04);
            assert(v + xhl + xcl == next, "Certificate extension length mismatch");
            if same {
                count += 1;
                start = v + xhl;
                len = xcl;
            }
            pos = next;
        }
    }
    assert(pos == t.ext_end, "Certificate has more extensions than the circuit walks");
    (count, start, len)
}

/// Exactly one basicConstraints, and it says cA = TRUE.
pub fn assert_ca<let N: u32>(tbs: [u8; N], t: Tbs) {
    let (count, start, len) = find_extension(tbs, t, OID_BASIC_CONSTRAINTS);
    // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen OPTIONAL }:
    // cA present and TRUE is 30 len 01 01 FF.
    let (shl, _) = der_element(tbs, start, 0x30);
    assert(
        (count == 1) & (len >= 5) & bytes_at(tbs, start + shl, [0x01, 0x01, 0xff]),
        "Certificate is not a CA certificate",
    );
}

/// The uncompressed P-256 key at `t.spki`, X and Y.
pub fn p256_key<let N: u32>(tbs: [u8; N], t: Tbs) -> ([u8; 32], [u8; 32]) {
    assert(
        bytes_at(tbs, t.spki, SPKI_P256_PREFIX),
        "Certificate key is not an uncompressed P-256 key",
    );
    let mut x: [u8; 32] = [0; 32];
    let mut y: [u8; 32] = [0; 32];
    for i in 0..32 {
        x[i] = tbs[t.spki + 27 + i];
        y[i] = tbs[t.spki + 59 + i];
    }
    (x, y)
}

/// The uncompressed P-384 key at `t.spki`, X and Y.
pub fn p384_key<let N: u32>(tbs: [u8; N], t: Tbs) -> ([u8; 48], [u8; 48]) {
    assert(
        bytes_at(tbs, t.spki, SPKI_P384_PREFIX),
        "Certificate key is not an uncompressed P-384 key",
    );
    let mut x: [u8; 48] = [0; 48];
    let mut y: [u8; 48] = [0; 48];
    for i in 0..48 {
        x[i] = tbs[t.spki + 24 + i];
        y[i] = tbs[t.spki + 72 + i];
    }
    (x, y)
}

/// `now` lies within [notBefore, notAfter].
pub fn assert_valid_at(t: Tbs, now: u64) {
    assert(t.not_before <= now, "Certificate is not valid yet at now");
    assert(now <= t.not_after, "Certificate has expired at now");
}

/// A context-specific tag at `pos`: (tag number, tag bytes). Low form
/// (A0..BE) or the high form with one or two base-128 bytes (BF xx / BF xx
/// yy), which is what AuthorizationList entries use ([709] = BF 85 45).
pub fn context_tag<let N: u32>(buf: [u8; N], pos: u32) -> (u32, u32) {
    let b = buf[pos];
    assert((b & 0xe0) == 0xa0, "Authorization entry is not a context-specific constructed tag");
    let mut number = (b & 0x1f) as u32;
    let mut size: u32 = 1;
    if (b & 0x1f) == 0x1f {
        let b1 = buf[pos + 1];
        assert(b1 != 0x80, "Authorization tag is not minimal");
        if (b1 & 0x80) == 0 {
            assert(b1 >= 31, "Authorization tag is not minimal");
            number = b1 as u32;
            size = 2;
        } else {
            let b2 = buf[pos + 2];
            assert((b2 & 0x80) == 0, "Unsupported authorization tag form");
            number = ((b1 & 0x7f) as u32) * 128 + (b2 as u32);
            size = 3;
        }
    }
    (number, size)
}

/// One TLV with a context tag at `pos`: (tag number, header length, content length).
pub fn context_element<let N: u32>(buf: [u8; N], pos: u32) -> (u32, u32, u32) {
    let (number, size) = context_tag(buf, pos);
    let (fl, cl) = der_length(buf, pos + size);
    (number, size + fl, cl)
}
