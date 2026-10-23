// The App Attest credential certificate: Apple's statement that a P-256 key
// lives in a device's Secure Enclave and belongs to one app.
//
// WHAT IS CHECKED HERE
//
//   1. The TBS is signed by the App Attest intermediate CA key, ECDSA P-384
//      over SHA-256 of the TBS. (Not SHA-384: Apple's credential certificates
//      carry ecdsa-with-SHA256 -- read from a real one, see tests.nr. Only the
//      root -> intermediate link uses SHA-384, and that link is verified
//      outside the circuit.)
//   2. The TBS is walked field by field (bounded DER, no pattern search) to:
//      - the signature algorithm, which must be ecdsa-with-SHA256,
//      - the SubjectPublicKeyInfo, which must be an uncompressed P-256 key,
//      - the extensions, of which exactly one must be Apple's app-identity
//        extension (1.2.840.113635.100.8.5) naming THIS app, and exactly one
//        Apple's nonce extension (1.2.840.113635.100.8.2).
//
// FORMAT ASSUMPTIONS, each from a real certificate (zkPassport's iOS test
// vector, issued 2025-08-26, verified against Apple's published root):
//   - version v3, a serial of 1..20 bytes, issuer/validity/subject in that
//     order, then SPKI, then [3] extensions and nothing after them;
//   - the app id is item [1204] (tag BF 89 34) of the 8.5 extension's
//     SEQUENCE, holding an OCTET STRING of the App ID. Apple does not
//     document this extension; zkPassport reads the same item.
//   - the nonce extension value is SEQUENCE { [1] { OCTET STRING (32) } },
//     which Apple does document ("a DER-encoded ASN.1 sequence ... the single
//     octet string that it contains").
// Positions are never fixed offsets: the serial length and every name length
// are read from the bytes.

use crate::der::{bytes_at, der_element, der_length, slice_at};
use bignum::bignum::BigNum;
use bignum::fields::secp384r1Fq::Secp384r1_Fq;
use bignum::fields::secp384r1Fr::Secp384r1_Fr;
use ecdsa::ecdsa::verify_secp384r1_ecdsa;

/// Room for a credential TBS. The real one measured 852 bytes.
pub global CREDENTIAL_TBS_MAX_LEN: u32 = 1000;

/// At most this many extensions are walked. The real certificate has 5.
global MAX_EXTENSIONS: u32 = 8;
/// At most this many items in the app-identity extension. The real one has 13.
global MAX_APP_ID_ITEMS: u32 = 20;

/// [0] { INTEGER 2 } -- X.509 v3.
global VERSION_V3: [u8; 5] = [0xa0, 0x03, 0x02, 0x01, 0x02];

/// AlgorithmIdentifier ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
global SIG_ALG_ECDSA_SHA256: [u8; 12] =
    [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// SubjectPublicKeyInfo header for id-ecPublicKey / prime256v1, through the
/// BIT STRING's unused-bits byte and the 0x04 uncompressed-point marker.
global SPKI_P256_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

/// OBJECT IDENTIFIER 1.2.840.113635.100.8 -- Apple's App Attest arc -- with
/// its tag and length; the last arc follows.
global APPLE_ATTEST_OID_PREFIX: [u8; 10] =
    [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08];
global OID_LAST_NONCE: u8 = 0x02;
global OID_LAST_APP_ID: u8 = 0x05;

/// SEQUENCE { [1] { OCTET STRING (32) } }, the nonce extension's value.
global NONCE_VALUE_PREFIX: [u8; 6] = [0x30, 0x24, 0xa1, 0x22, 0x04, 0x20];

/// Tag of the app-identity item inside the 8.5 extension.
global APP_ID_ITEM_TAG: [u8; 3] = [0xbf, 0x89, 0x34];

pub struct CredentialKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
    /// What Apple wrote into extension 1.2.840.113635.100.8.2:
    /// SHA256(attestation authData || attestation clientDataHash).
    pub nonce: [u8; 32],
}

/// The TBS length, from its own header; everything past it must be zero so
/// the array has exactly one meaning.
fn tbs_length<let N: u32>(tbs: [u8; N], tbs_len: u32) {
    assert(tbs_len <= N, "TBS longer than the circuit allows");
    let (hl, cl) = der_element(tbs, 0, 0x30);
    assert(hl + cl == tbs_len, "TBS length does not match its header");
    for i in 0..N {
        if i >= tbs_len {
            assert(tbs[i] == 0, "TBS padding is not zero");
        }
    }
}

/// Walk the app-identity extension's value and require exactly one [1204]
/// item, holding exactly `app_id`.
fn check_app_id<let N: u32, let A: u32>(tbs: [u8; N], start: u32, end: u32, app_id: [u8; A]) {
    let (hl, cl) = der_element(tbs, start, 0x30);
    assert(start + hl + cl == end, "App id extension length mismatch");
    let mut q = start + hl;
    let mut found: u32 = 0;
    for _ in 0..MAX_APP_ID_ITEMS {
        if q < end {
            // Context tags are one byte (A4) or, for numbers >= 31, three
            // (BF 89 34): Apple's items stop below 2^14. Anything else is
            // refused rather than skipped by a guess.
            let first = tbs[q];
            let mut tag_len: u32 = 1;
            if (first & 0x1f) == 0x1f {
                assert((tbs[q + 1] & 0x80) != 0, "Unsupported DER tag form");
                assert((tbs[q + 2] & 0x80) == 0, "Unsupported DER tag form");
                tag_len = 3;
            }
            let (fl, item_len) = der_length(tbs, q + tag_len);
            let content = q + tag_len + fl;
            if (tag_len == 3) & bytes_at(tbs, q, APP_ID_ITEM_TAG) {
                assert(item_len == 2 + A, "Credential certificate is for another app");
                assert(tbs[content] == 0x04, "App id item is not an OCTET STRING");
                assert(tbs[content + 1] as u32 == A, "Credential certificate is for another app");
                assert(bytes_at(tbs, content + 2, app_id), "Credential certificate is for another app");
                found += 1;
            }
            q = content + item_len;
        }
    }
    assert(q == end, "App id extension has more items than the circuit walks");
    assert(found == 1, "Credential certificate is for another app");
}

/// Walk the TBS and return the credential key and Apple's nonce, refusing
/// anything that is not shaped as an App Attest credential certificate for
/// `app_id`.
pub fn parse_credential_tbs<let N: u32, let A: u32>(
    tbs: [u8; N],
    tbs_len: u32,
    app_id: [u8; A],
) -> CredentialKey {
    tbs_length(tbs, tbs_len);
    let (outer_hl, _) = der_element(tbs, 0, 0x30);
    let mut pos = outer_hl;

    assert(bytes_at(tbs, pos, VERSION_V3), "Certificate is not X.509 v3");
    pos += 5;

    let (shl, scl) = der_element(tbs, pos, 0x02);
    assert((scl >= 1) & (scl <= 20), "Certificate serial length out of range");
    pos += shl + scl;

    assert(bytes_at(tbs, pos, SIG_ALG_ECDSA_SHA256), "Certificate is not signed with ecdsa-with-SHA256");
    pos += 12;

    // issuer, validity, subject: skipped by their own lengths. The issuer is
    // not compared -- the CA key's signature is what binds it.
    for _ in 0..3 {
        let (hl, cl) = der_element(tbs, pos, 0x30);
        pos += hl + cl;
    }

    assert(bytes_at(tbs, pos, SPKI_P256_PREFIX), "Credential key is not an uncompressed P-256 key");
    let x: [u8; 32] = slice_at(tbs, pos + 27);
    let y: [u8; 32] = slice_at(tbs, pos + 59);
    pos += 91;

    // [3] { SEQUENCE OF Extension }, ending exactly at the end of the TBS.
    let (ehl, ecl) = der_element(tbs, pos, 0xa3);
    let ext_end = pos + ehl + ecl;
    assert(ext_end == tbs_len, "Extensions are not the last TBS field");
    pos += ehl;
    let (shl2, scl2) = der_element(tbs, pos, 0x30);
    assert(pos + shl2 + scl2 == ext_end, "Extension list length mismatch");
    pos += shl2;

    let mut nonce_count: u32 = 0;
    let mut app_id_count: u32 = 0;
    let mut nonce_pos: u32 = 0;
    let mut nonce_len: u32 = 0;
    let mut app_id_start: u32 = 0;
    let mut app_id_end: u32 = 0;

    for _ in 0..MAX_EXTENSIONS {
        if pos < ext_end {
            // Extension ::= SEQUENCE { OID, critical BOOLEAN OPTIONAL, OCTET STRING }
            let (hl, cl) = der_element(tbs, pos, 0x30);
            let ext_next = pos + hl + cl;
            let oid_pos = pos + hl;
            let (ohl, ocl) = der_element(tbs, oid_pos, 0x06);
            let is_apple = bytes_at(tbs, oid_pos, APPLE_ATTEST_OID_PREFIX);
            let last = tbs[oid_pos + 10];
            let mut v = oid_pos + ohl + ocl;
            if tbs[v] == 0x01 {
                let (bhl, bcl) = der_element(tbs, v, 0x01);
                v += bhl + bcl;
            }
            let (vhl, vcl) = der_element(tbs, v, 0x04);
            assert(v + vhl + vcl == ext_next, "Extension length mismatch");
            if is_apple & (last == OID_LAST_NONCE) {
                nonce_count += 1;
                nonce_pos = v + vhl;
                nonce_len = vcl;
            }
            if is_apple & (last == OID_LAST_APP_ID) {
                app_id_count += 1;
                app_id_start = v + vhl;
                app_id_end = v + vhl + vcl;
            }
            pos = ext_next;
        }
    }
    assert(pos == ext_end, "Certificate has more extensions than the circuit walks");

    assert(nonce_count == 1, "Credential certificate has no single nonce extension");
    assert(nonce_len == 38, "Nonce extension is not one 32-byte OCTET STRING");
    assert(bytes_at(tbs, nonce_pos, NONCE_VALUE_PREFIX), "Nonce extension is not one 32-byte OCTET STRING");
    let nonce: [u8; 32] = slice_at(tbs, nonce_pos + 6);

    assert(app_id_count == 1, "Credential certificate is for another app");
    check_app_id(tbs, app_id_start, app_id_end, app_id);

    CredentialKey { x, y, nonce }
}

/// ECDSA P-384 over SHA-256 of the TBS, by the CA key. `sig_s` must be the
/// low form (s <= n/2): the library refuses the other, and the prover
/// replaces Apple's s with n - s when needed -- the same signature.
pub fn verify_credential_signature<let N: u32>(
    ca_x: [u8; 48],
    ca_y: [u8; 48],
    tbs: [u8; N],
    tbs_len: u32,
    sig_r: [u8; 48],
    sig_s: [u8; 48],
) -> bool {
    let digest = sha256::sha256_var(tbs, tbs_len);
    let px: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(ca_x);
    let py: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(ca_y);
    let r: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(sig_r);
    let s: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(sig_s);
    verify_secp384r1_ecdsa(px, py, digest, (r, s))
}
