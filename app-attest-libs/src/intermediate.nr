// The App Attest intermediate CA certificate ("Apple App Attestation CA 1"
// today): Apple's root says "this P-384 key may issue App Attest credential
// certificates".
//
// Verified in the circuit, as zkPassport does for FaceMatch, so that the only
// pinned key is Apple's ROOT (valid to 2045-03-15). When Apple replaces the
// intermediate (CA 1 expires 2030-03-13), devices present the new one and
// nothing here, in a verifier, or in a deployed contract changes.
//
// WHAT IS CHECKED HERE
//
//   1. The root key signed the TBS: ECDSA P-384 over SHA-384 of the TBS
//      (ecdsa-with-SHA384, read from the real certificate; see tests.nr).
//   2. The TBS is walked with bounded DER to:
//      - the signature algorithm, which must be ecdsa-with-SHA384;
//      - the SubjectPublicKeyInfo, which must be an uncompressed P-384 key
//        (returned: it is the key that must have signed the credential);
//      - the extensions, of which exactly one must be basicConstraints with
//        cA = TRUE. A root-signed certificate that is not a CA is refused,
//        so a leaf Apple's root might sign can never act as an intermediate.
//
// NOT CHECKED: the validity dates (the circuit has no trusted clock; the
// public attested_at is the prover's claim), the issuer / subject names (the
// root's signature is what binds them), the key identifiers, key usage.
//
// FORMAT ASSUMPTIONS, from the real certificate (Apple App Attestation CA 1,
// 460-byte TBS, verified against apple.com's root by
// scripts/coinbase-attestation-v2/check-apple-vector.js): version v3, a serial
// of 1..20 bytes, issuer/validity/subject in that order, SPKI, then [3]
// extensions and nothing after them.

use crate::der::{bytes_at, der_element, slice_at};
use bignum::bignum::BigNum;
use bignum::fields::secp384r1Fq::Secp384r1_Fq;
use bignum::fields::secp384r1Fr::Secp384r1_Fr;
use ecdsa::ecdsa::verify_secp384r1_ecdsa;

/// Room for an intermediate TBS. CA 1's is 460 bytes. SHA-384 pads to
/// 128-byte blocks, so 600 costs the same five blocks as 512 and leaves room
/// for a successor with longer names.
pub global INTERMEDIATE_TBS_MAX_LEN: u32 = 600;

/// At most this many extensions are walked. CA 1 has 4.
global MAX_EXTENSIONS: u32 = 8;

/// [0] { INTEGER 2 } -- X.509 v3.
global VERSION_V3: [u8; 5] = [0xa0, 0x03, 0x02, 0x01, 0x02];

/// AlgorithmIdentifier ecdsa-with-SHA384 (1.2.840.10045.4.3.3).
global SIG_ALG_ECDSA_SHA384: [u8; 12] =
    [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

/// SubjectPublicKeyInfo header for id-ecPublicKey / secp384r1, through the
/// BIT STRING's unused-bits byte and the 0x04 uncompressed-point marker.
global SPKI_P384_PREFIX: [u8; 24] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
];

/// OBJECT IDENTIFIER 2.5.29.19 (basicConstraints), with its tag and length.
global OID_BASIC_CONSTRAINTS: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x13];

pub struct IntermediateKey {
    pub x: [u8; 48],
    pub y: [u8; 48],
}

/// Walk the TBS and return the intermediate's P-384 key, refusing anything
/// that is not shaped as an ECDSA-SHA384-signed CA certificate over a P-384 key.
pub fn parse_intermediate_tbs<let N: u32>(tbs: [u8; N], tbs_len: u32) -> IntermediateKey {
    assert(tbs_len <= N, "Intermediate TBS longer than the circuit allows");
    let (outer_hl, outer_cl) = der_element(tbs, 0, 0x30);
    assert(outer_hl + outer_cl == tbs_len, "Intermediate TBS length does not match its header");
    for i in 0..N {
        if i >= tbs_len {
            assert(tbs[i] == 0, "Intermediate TBS padding is not zero");
        }
    }
    let mut pos = outer_hl;

    assert(bytes_at(tbs, pos, VERSION_V3), "Intermediate is not X.509 v3");
    pos += 5;

    let (shl, scl) = der_element(tbs, pos, 0x02);
    assert((scl >= 1) & (scl <= 20), "Intermediate serial length out of range");
    pos += shl + scl;

    assert(bytes_at(tbs, pos, SIG_ALG_ECDSA_SHA384), "Intermediate is not signed with ecdsa-with-SHA384");
    pos += 12;

    for _ in 0..3 {
        let (hl, cl) = der_element(tbs, pos, 0x30);
        pos += hl + cl;
    }

    assert(bytes_at(tbs, pos, SPKI_P384_PREFIX), "Intermediate key is not an uncompressed P-384 key");
    let x: [u8; 48] = slice_at(tbs, pos + 24);
    let y: [u8; 48] = slice_at(tbs, pos + 72);
    pos += 120;

    let (ehl, ecl) = der_element(tbs, pos, 0xa3);
    let ext_end = pos + ehl + ecl;
    assert(ext_end == tbs_len, "Intermediate extensions are not the last TBS field");
    pos += ehl;
    let (shl2, scl2) = der_element(tbs, pos, 0x30);
    assert(pos + shl2 + scl2 == ext_end, "Intermediate extension list length mismatch");
    pos += shl2;

    let mut ca_count: u32 = 0;
    let mut basic_count: u32 = 0;
    for _ in 0..MAX_EXTENSIONS {
        if pos < ext_end {
            let (hl, cl) = der_element(tbs, pos, 0x30);
            let ext_next = pos + hl + cl;
            let oid_pos = pos + hl;
            let (ohl, ocl) = der_element(tbs, oid_pos, 0x06);
            let is_basic = bytes_at(tbs, oid_pos, OID_BASIC_CONSTRAINTS);
            let mut v = oid_pos + ohl + ocl;
            if tbs[v] == 0x01 {
                let (bhl, bcl) = der_element(tbs, v, 0x01);
                v += bhl + bcl;
            }
            let (vhl, vcl) = der_element(tbs, v, 0x04);
            assert(v + vhl + vcl == ext_next, "Intermediate extension length mismatch");
            if is_basic {
                basic_count += 1;
                // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }:
                // cA present and TRUE is 30 len 01 01 FF.
                let b = v + vhl;
                let (bshl, _) = der_element(tbs, b, 0x30);
                if bytes_at(tbs, b + bshl, [0x01, 0x01, 0xff]) {
                    ca_count += 1;
                }
            }
            pos = ext_next;
        }
    }
    assert(pos == ext_end, "Intermediate has more extensions than the circuit walks");
    assert((basic_count == 1) & (ca_count == 1), "Intermediate is not a CA certificate");

    IntermediateKey { x, y }
}

/// ECDSA P-384 over SHA-384 of the TBS, by the root key. `sig_s` must be
/// the low form (s <= n/2): the library refuses the other, and the prover
/// replaces Apple's s with n - s when needed -- the same signature.
pub fn verify_intermediate_signature<let N: u32>(
    root_x: [u8; 48],
    root_y: [u8; 48],
    tbs: [u8; N],
    tbs_len: u32,
    sig_r: [u8; 48],
    sig_s: [u8; 48],
) -> bool {
    let digest = sha512::sha384::sha384_var(BoundedVec::from_parts(tbs, tbs_len));
    let px: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(root_x);
    let py: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(root_y);
    let r: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(sig_r);
    let s: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(sig_s);
    verify_secp384r1_ecdsa(px, py, digest, (r, s))
}
