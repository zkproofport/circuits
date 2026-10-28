// The provider-key statement: "at `now`, this RSA modulus was in `provider`'s
// published key list", signed by the phone (App Attest) or the AI server
// (Cloud KMS) through ../statement-signer.
//
// WHY. pubkey_modulus_limbs is a public input, and the RSA check only says the
// token was signed by THAT key. A prover who generates their own key and signs
// their own token proves any email they like unless someone compares the
// modulus with Google's / Microsoft's published keys. Off-chain, our core/SDK
// does (live JWKS). On-chain nothing can fetch a JWKS, and the key lists carry
// no signature of their own, so the circuit instead requires a signer we
// trust to have done that comparison (decided 2026-10-23, fix list item 12 in
// .claude/agents/circuits-dev.md).
//
// Fixed length, fixed positions, binary, built here from public inputs only:
// the signer and the circuit write the same 313 bytes, and nothing in it is a
// prover hint. README.md "Provider-key statement" is the spec.
//
//   off  len  field
//     0   16  MAGIC "ZKProofport/PK/1"
//    16   32  CIRCUIT_TAG = keccak256("oidc_domain_attestation")
//    48    1  provider (0 Google, 1 Microsoft) = public `provider`
//    49    8  unix seconds, big-endian = public `now`
//    57  256  the RSA modulus n, big-endian (the JWKS `n`, base64url-decoded)
//   313       total
//
// The magic, the tag and the length differ from coinbase_attestation's
// 225-byte "ZKProofport/AA/1" statement, which the same keys sign: neither
// can be passed off as the other short of a SHA-256 collision.

pub global STATEMENT_LEN: u32 = 313;
global MODULUS_LEN: u32 = 256;
global LIMBS: u32 = 18;
global LIMB_BYTES: u32 = 15; // 120-bit limbs
global WIDE_LEN: u32 = 270; // LIMBS * LIMB_BYTES

/// "ZKProofport/PK/1"
pub global MAGIC: [u8; 16] =
    [0x5a, 0x4b, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x50, 0x4b, 0x2f, 0x31];

/// keccak256("oidc_domain_attestation"), the canonical circuit id.
pub global CIRCUIT_TAG: [u8; 32] = [
    0x90, 0xbb, 0x37, 0x9d, 0xf4, 0xb0, 0xdd, 0xe7, 0x94, 0xc1, 0x69, 0x17, 0xc2, 0xdf, 0x39, 0xa3,
    0x98, 0xdc, 0x7e, 0x34, 0x81, 0xb2, 0xf5, 0x0d, 0x03, 0x1d, 0xfe, 0x49, 0x0a, 0x8e, 0x06, 0x2b,
];

/// The modulus as 256 big-endian bytes, from the circuit's 18 little-endian
/// 120-bit limbs. Each limb is range-checked to 120 bits (to_be_bytes) and the
/// 14 bytes above bit 2048 must be zero, so exactly one limb array maps to
/// each byte string: the key the signer vouched for is the key the RSA check
/// used.
pub fn modulus_bytes(limbs: [u128; LIMBS]) -> [u8; MODULUS_LEN] {
    let mut wide: [u8; WIDE_LEN] = [0; WIDE_LEN];
    for i in 0..LIMBS {
        let bytes: [u8; LIMB_BYTES] = (limbs[i] as Field).to_be_bytes();
        for j in 0..LIMB_BYTES {
            wide[WIDE_LEN - LIMB_BYTES * (i + 1) + j] = bytes[j];
        }
    }
    for k in 0..(WIDE_LEN - MODULUS_LEN) {
        assert(wide[k] == 0, "RSA modulus is wider than 2048 bits");
    }
    let mut out: [u8; MODULUS_LEN] = [0; MODULUS_LEN];
    for k in 0..MODULUS_LEN {
        out[k] = wide[WIDE_LEN - MODULUS_LEN + k];
    }
    out
}

fn u64_be(x: u64) -> [u8; 8] {
    let mut out: [u8; 8] = [0; 8];
    let mut v = x;
    for j in 0..8 {
        out[7 - j] = v as u8;
        v = v >> 8;
    }
    out
}

/// The 313 bytes the signer must have signed for this proof.
pub fn statement(provider: u8, now: u64, limbs: [u128; LIMBS]) -> [u8; STATEMENT_LEN] {
    let mut s: [u8; STATEMENT_LEN] = [0; STATEMENT_LEN];
    for i in 0..16 {
        s[i] = MAGIC[i];
    }
    for i in 0..32 {
        s[16 + i] = CIRCUIT_TAG[i];
    }
    s[48] = provider;
    let t = u64_be(now);
    for i in 0..8 {
        s[49 + i] = t[i];
    }
    let n = modulus_bytes(limbs);
    for i in 0..MODULUS_LEN {
        s[57 + i] = n[i];
    }
    s
}

// ---- tests: what the statement is, byte for byte ---------------------------

// limbs of n = 2^2047 + 0x0102: limb 0 = 0x0102, limb 17 holds bit 2047 - 2040 = 7.
fn sample_limbs() -> [u128; LIMBS] {
    let mut l: [u128; LIMBS] = [0; LIMBS];
    l[0] = 0x0102;
    l[17] = 0x80;
    l
}

#[test]
fn the_modulus_is_big_endian_256_bytes() {
    let n = modulus_bytes(sample_limbs());
    assert(n[0] == 0x80);
    for i in 1..254 {
        assert(n[i] == 0);
    }
    assert(n[254] == 0x01);
    assert(n[255] == 0x02);
}

#[test]
fn a_limb_maps_to_its_15_bytes() {
    // limb 1 = 2^119 is bit 239 of n: byte 255 - 29 = 226, value 0x80.
    let mut l: [u128; LIMBS] = [0; LIMBS];
    l[1] = 1 << 119;
    let n = modulus_bytes(l);
    for i in 0..256 {
        if i == 226 {
            assert(n[i] == 0x80);
        } else {
            assert(n[i] == 0);
        }
    }
}

#[test(should_fail_with = "RSA modulus is wider than 2048 bits")]
fn a_modulus_past_2048_bits_is_refused() {
    let mut l = sample_limbs();
    l[17] = 0x100; // bit 2048
    let _ = modulus_bytes(l);
}

// A limb of 121 bits would let two limb arrays name one byte string; the
// 15-byte decomposition refuses it.
#[test(should_fail)]
fn a_limb_wider_than_120_bits_is_refused() {
    let mut l = sample_limbs();
    l[3] = 1 << 120;
    let _ = modulus_bytes(l);
}

#[test]
fn the_statement_layout() {
    let s = statement(1, 0x0102030405060708, sample_limbs());
    for i in 0..16 {
        assert(s[i] == MAGIC[i]);
    }
    for i in 0..32 {
        assert(s[16 + i] == CIRCUIT_TAG[i]);
    }
    assert(s[48] == 1);
    for i in 0..8 {
        assert(s[49 + i] == (i as u8) + 1);
    }
    assert(s[57] == 0x80);
    assert(s[311] == 0x01);
    assert(s[312] == 0x02);
}

#[test]
fn the_tag_is_the_circuit_id_and_not_coinbase() {
    let coinbase_tag: [u8; 32] = keccak256::keccak256("coinbase_attestation".as_bytes(), 20);
    let own: [u8; 32] = keccak256::keccak256("oidc_domain_attestation".as_bytes(), 23);
    assert(own == CIRCUIT_TAG);
    assert(coinbase_tag != CIRCUIT_TAG);
}
