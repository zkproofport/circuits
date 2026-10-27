// The digest Human Passport's issuer signs, rebuilt byte for byte.
//
// Source: GitcoinVerifier.sol (passportxyz/eas-proxy). verifyAndAttest() takes
// a PassportAttestationRequest and the issuer's v/r/s, and accepts it only
// when ECDSA.recover(toTypedDataHash(DOMAIN_SEPARATOR, hash), v, r, s) is the
// contract's `issuer`. The hash is EIP-712's hashStruct:
//
//   entry  = keccak(abi.encode(STAMP_TYPEHASH, recipient, expirationTime,
//                              revocable, refUID, keccak(data), value))
//   multi  = keccak(abi.encode(MULTI_TYPEHASH, schema,
//                              keccak(abi.encodePacked([entry]))))
//   struct = keccak(abi.encode(PASSPORT_TYPEHASH,
//                              keccak(abi.encodePacked([multi])), nonce, fee))
//   digest = keccak(0x1901 ++ domainSeparator ++ struct)
//
// ONE REQUEST WITH ONE ENTRY, BY CONSTRUCTION. Every scoreV2 issuance read on
// Base has that shape (one MultiAttestationRequest, one AttestationRequestData).
// The array hashes above are hashes of exactly one element, so a request the
// issuer signed with two entries cannot be presented here without a keccak
// collision -- there is no index a prover could choose to pick the
// convenient entry out of a larger signed batch.

use ::keccak256::keccak256;
use ::coinbase_libs::ethereum::create_eip712_digest;

/// keccak256("AttestationRequestData(address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value)")
global STAMP_TYPEHASH: [u8; 32] = [
    0xd1, 0x83, 0xf8, 0x90, 0x34, 0x5d, 0x44, 0xab,
    0x79, 0x55, 0x5f, 0x4f, 0xbe, 0x54, 0xbb, 0xd5,
    0xe1, 0xd5, 0x54, 0x42, 0x00, 0x09, 0xef, 0xb2,
    0xb8, 0x42, 0x98, 0x2f, 0xad, 0x97, 0x79, 0xd5,
];

/// keccak256("MultiAttestationRequest(bytes32 schema,AttestationRequestData[] data)AttestationRequestData(...)")
global MULTI_TYPEHASH: [u8; 32] = [
    0xc8, 0x5e, 0xc0, 0xe2, 0xb4, 0xab, 0xf2, 0xa8,
    0xf3, 0x54, 0xa8, 0x52, 0x60, 0x48, 0x77, 0x05,
    0x64, 0x85, 0xcd, 0x77, 0xc2, 0xab, 0x27, 0x0f,
    0x97, 0x09, 0xbd, 0x19, 0x8e, 0x91, 0x87, 0x35,
];

/// keccak256("PassportAttestationRequest(MultiAttestationRequest[] multiAttestationRequest,uint256 nonce,uint256 fee)AttestationRequestData(...)MultiAttestationRequest(...)")
global PASSPORT_TYPEHASH: [u8; 32] = [
    0x0f, 0xd0, 0x04, 0x50, 0x07, 0x47, 0x19, 0x00,
    0x61, 0x1e, 0xfb, 0x46, 0x09, 0x70, 0xc7, 0xa3,
    0xa1, 0xec, 0xbb, 0xbb, 0xd5, 0xab, 0xcf, 0xb7,
    0xe4, 0x3e, 0x7c, 0xc2, 0xfe, 0x96, 0x35, 0x07,
];

/// The signed fields of the one AttestationRequestData, plus the request's
/// nonce and fee. Everything the issuer signed except `data`, which is passed
/// separately because its length varies.
pub struct PassportRequest {
    pub schema: [u8; 32],
    pub recipient: [u8; 20],
    pub expiration_time: u64,
    pub revocable: bool,
    pub ref_uid: [u8; 32],
    pub value: [u8; 32],
    pub nonce: [u8; 32],
    pub fee: [u8; 32],
}

fn put32<let M: u32>(buf: &mut [u8; M], at: u32, v: [u8; 32]) {
    for i in 0..32 {
        buf[at + i] = v[i];
    }
}

fn hash32(v: [u8; 32]) -> [u8; 32] {
    keccak256(v, 32)
}

/// hashStruct(PassportAttestationRequest) for a one-request, one-entry request.
pub fn passport_struct_hash<let N: u32>(
    req: PassportRequest,
    data: [u8; N],
    data_len: u32,
) -> [u8; 32] {
    let data_hash = keccak256(data, data_len);

    // abi.encode(STAMP_TYPEHASH, recipient, expirationTime, revocable, refUID,
    //            keccak(data), value): seven words.
    let mut entry: [u8; 224] = [0; 224];
    put32(&mut entry, 0, STAMP_TYPEHASH);
    for i in 0..20 {
        entry[32 + 12 + i] = req.recipient[i];
    }
    let exp_bytes: [u8; 8] = (req.expiration_time as Field).to_be_bytes();
    for i in 0..8 {
        entry[64 + 24 + i] = exp_bytes[i];
    }
    entry[96 + 31] = if req.revocable { 1 } else { 0 };
    put32(&mut entry, 128, req.ref_uid);
    put32(&mut entry, 160, data_hash);
    put32(&mut entry, 192, req.value);
    let entry_hash = keccak256(entry, 224);

    let mut multi: [u8; 96] = [0; 96];
    put32(&mut multi, 0, MULTI_TYPEHASH);
    put32(&mut multi, 32, req.schema);
    put32(&mut multi, 64, hash32(entry_hash));
    let multi_hash = keccak256(multi, 96);

    let mut outer: [u8; 128] = [0; 128];
    put32(&mut outer, 0, PASSPORT_TYPEHASH);
    put32(&mut outer, 32, hash32(multi_hash));
    put32(&mut outer, 64, req.nonce);
    put32(&mut outer, 96, req.fee);
    keccak256(outer, 128)
}

/// The 32 bytes the issuer's key signed.
pub fn passport_digest<let N: u32>(
    passport_domain_separator: [u8; 32],
    req: PassportRequest,
    data: [u8; N],
    data_len: u32,
) -> [u8; 32] {
    create_eip712_digest(passport_domain_separator, passport_struct_hash(req, data, data_len))
}
