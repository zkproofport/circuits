// The clientData the app asks App Attest to sign, right after it has looked
// the Coinbase attestation up and found it unrevoked.
//
// Fixed length, fixed positions, binary. No JSON and no CBOR: a parser is
// where two readers come to disagree about one message, and every field here
// has exactly one size. README.md in this directory is the spec; the offsets
// below must match it.
//
//   off  len  field
//     0   16  MAGIC "ZKProofport/AA/1" -- what this message is, and its version
//    16   32  CIRCUIT_TAG -- keccak256("coinbase_attestation"), the statement kind
//    48   20  wallet -- must equal the circuit's user_address
//    68    8  timestamp, unix seconds, big-endian -- must equal public attested_at
//    76   32  EAS schema uid -- must be the Coinbase Verified Account schema
//   108   20  EAS attester -- must be Coinbase's attester contract
//   128   32  attestation uid -- what the app found; carried, not checked here
//   160    1  revoked -- 0x00 means the app found it unrevoked; anything else refused
//   161   32  request digest -- the exact digest the wallet signed (EIP-191 over
//             signal_hash, or the EIP-712 digest of the action)
//   193   32  scope
//   225       total

use coinbase_libs::ethereum::COINBASE_ATTESTER_CONTRACT;

pub global CLIENT_DATA_LEN: u32 = 225;

/// "ZKProofport/AA/1"
global MAGIC: [u8; 16] =
    [0x5a, 0x4b, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x41, 0x41, 0x2f, 0x31];

/// Coinbase Verified Account schema on Base.
global KYC_SCHEMA: [u8; 32] = [
    0xf8, 0xb0, 0x5c, 0x79, 0xf0, 0x90, 0x97, 0x9b, 0xf4, 0xa8, 0x02, 0x70, 0xab, 0xa2, 0x32, 0xdf,
    0xf1, 0x1a, 0x10, 0xd9, 0xca, 0x55, 0xc4, 0xf8, 0x8d, 0xe9, 0x53, 0x17, 0x97, 0x0f, 0x0d, 0xe9,
];

fn same<let N: u32, let M: u32>(buf: [u8; N], pos: u32, want: [u8; M]) -> bool {
    let mut ok = true;
    for i in 0..M {
        ok &= buf[pos + i] == want[i];
    }
    ok
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

/// Every field the circuit can check, checked. Order matters only for which
/// message a malformed clientData is refused with.
pub fn check_client_data(
    client_data: [u8; CLIENT_DATA_LEN],
    circuit_tag: [u8; 32],
    user_address: [u8; 20],
    attested_at: u64,
    request_digest: [u8; 32],
    scope: [u8; 32],
) {
    assert(same(client_data, 0, MAGIC), "clientData is not a ZKProofport App Attest statement");
    assert(same(client_data, 16, circuit_tag), "clientData is for another circuit");
    assert(same(client_data, 48, user_address), "clientData wallet is not the proven wallet");
    assert(same(client_data, 68, u64_be(attested_at)), "clientData timestamp is not the public timestamp");
    assert(same(client_data, 76, KYC_SCHEMA), "clientData names another EAS schema");
    assert(same(client_data, 108, COINBASE_ATTESTER_CONTRACT), "clientData names another attester");
    assert(client_data[160] == 0, "clientData says the attestation is revoked");
    assert(same(client_data, 161, request_digest), "clientData does not bind this request");
    assert(same(client_data, 193, scope), "clientData does not bind this scope");
}
