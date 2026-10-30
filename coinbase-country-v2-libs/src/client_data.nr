// The statement a signer makes, right after it has looked the wallet's
// Coinbase Verified Country attestation up and found it unrevoked.
//
// coinbase_attestation v2's 225-byte layout (../coinbase-v2-libs
// client_data.nr) with this circuit's tag and schema, plus the country the
// signer read from that attestation, so the statement cannot vouch for a
// country the wallet no longer holds. Fixed length, fixed positions, binary.
//
//   off  len  field
//     0   16  MAGIC "ZKProofport/AA/1"
//    16   32  CIRCUIT_TAG -- keccak256("coinbase_country_attestation")
//    48   20  wallet -- must equal the circuit's user_address
//    68    8  timestamp, unix seconds, big-endian -- must equal public attested_at
//    76   32  EAS schema uid -- must be the Coinbase Verified Country schema
//   108   20  EAS attester -- must be Coinbase's attester contract
//   128   32  attestation uid -- what the signer found; carried, not checked here
//   160    1  revoked -- 0x00 means the signer found it unrevoked; anything else refused
//   161   32  request digest -- the exact digest the wallet signed (EIP-191 over
//             signal_hash, or the EIP-712 digest of the action)
//   193   32  scope
//   225    2  country -- the attestation's verifiedCountry, two ASCII bytes;
//             must equal the country in the proven attestCountry transaction
//   227       total
//
// WHY THE COUNTRY IS IN THE STATEMENT. A wallet whose country changed holds an
// old attestCountry transaction (old country, attestation since revoked) and a
// new one. "Some Country attestation of this wallet is unrevoked" would let
// the OLD transaction pass with the NEW attestation's statement. The circuit
// cannot tie the attestation uid to the transaction, but it can require that
// the transaction's country is the one the signer saw unrevoked.

use coinbase_libs::ethereum::COINBASE_ATTESTER_CONTRACT;

pub global COUNTRY_CLIENT_DATA_LEN: u32 = 227;

/// "ZKProofport/AA/1"
global MAGIC: [u8; 16] =
    [0x5a, 0x4b, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x41, 0x41, 0x2f, 0x31];

/// Coinbase Verified Country schema on Base.
global COUNTRY_SCHEMA: [u8; 32] = [
    0x18, 0x01, 0x90, 0x1f, 0xab, 0xd0, 0xe6, 0x18, 0x93, 0x56, 0xb4, 0xfb, 0x52, 0xbb, 0x0a, 0xb8,
    0x55, 0x27, 0x6d, 0x84, 0xf7, 0xec, 0x14, 0x08, 0x39, 0xfb, 0xd1, 0xf6, 0x80, 0x1c, 0xa0, 0x65,
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

/// Every field the circuit can check, checked. The messages are
/// coinbase_attestation v2's, so both circuits refuse a bad statement in the
/// same words; the country check is the one addition.
pub fn check_country_client_data(
    client_data: [u8; COUNTRY_CLIENT_DATA_LEN],
    circuit_tag: [u8; 32],
    user_address: [u8; 20],
    attested_at: u64,
    request_digest: [u8; 32],
    scope: [u8; 32],
    country_code: [u8; 2],
) {
    assert(same(client_data, 0, MAGIC), "clientData is not a ZKProofport App Attest statement");
    assert(same(client_data, 16, circuit_tag), "clientData is for another circuit");
    assert(same(client_data, 48, user_address), "clientData wallet is not the proven wallet");
    assert(same(client_data, 68, u64_be(attested_at)), "clientData timestamp is not the public timestamp");
    assert(same(client_data, 76, COUNTRY_SCHEMA), "clientData names another EAS schema");
    assert(same(client_data, 108, COINBASE_ATTESTER_CONTRACT), "clientData names another attester");
    assert(client_data[160] == 0, "clientData says the attestation is revoked");
    assert(same(client_data, 161, request_digest), "clientData does not bind this request");
    assert(same(client_data, 193, scope), "clientData does not bind this scope");
    assert(same(client_data, 225, country_code), "clientData names another country");
}
