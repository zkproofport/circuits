// PROTOTYPE -- measures what proving a Coinbase KYC attestation from EAS
// STORAGE costs. Not a canonical circuit; no verifier is deployed for it.
//
// WHY STORAGE AND NOT THE TRANSACTION
//
// coinbase_attestation proves that Coinbase once sent attestAccount(me). That
// stays true after Coinbase revokes the attestation: on Base, 409,691 of
// 723,692 Coinbase KYC attestations are revoked (EAS explorer, 2026-10-20),
// and 56 of 60 recently revoked recipients held no live attestation at all.
// A revocation is a later write to EAS storage, so only a statement about
// storage can see it.
//
// WHAT THIS PROVES
//
//   1. The wallet signed the request -- personal_sign over signal_hash, or an
//      EIP-712 action -- exactly as giwa_attestation does.
//   2. An EAS attestation exists with recipient = that wallet, attester =
//      Coinbase's attester contract, schema = Coinbase Verified Account,
//      data = true, no expiration, and it is NOT revoked, in the EAS storage
//      whose root is the public `eas_storage_root`.
//   3. One nullifier per wallet per scope.
//
// HOW ONE SLOT IS ENOUGH
//
// The uid is keccak(schema ++ recipient ++ attester ++ time ++ expirationTime
// ++ revocable ++ refUID ++ data ++ bump), so recomputing it here binds every
// one of those fields. The record lives at keccak(uid ++ 50) in the EAS
// predeploy; its third word packs time | expirationTime | revocationTime as
// uint64s, low bytes first. Proving that word equals exactly `time` says three
// things at once: the record exists (an absent record reads zero, and time is
// non-zero), it never expires, and it was never revoked.
//
// WHAT IS LEFT TO THE VERIFIER
//
// `eas_storage_root` is public, and nothing here ties it to a block. The
// verifier must check it: block hash (EIP-2935 or blockhash) -> header ->
// state root -> account proof of 0x4200...0021 -> storage root. None of that
// is private, so it is kept out of the circuit, where an account proof alone
// costs more than the rest of this circuit.

use dep::std;
use dep::keccak256::keccak256;
use dep::coinbase_libs::nullifier::verify_wallet_nullifier;
use dep::coinbase_libs::signed_message::signed_digest;
use dep::coinbase_libs::ethereum::derive_address_from_pubkey;
use dep::eth_mpt::proof::{MAX_NODE_LEN, Proof};
use dep::eth_mpt::storage::verify_storage_slot;

/// Coinbase Verified Account schema on Base.
global KYC_SCHEMA: [u8; 32] = [
    0xf8, 0xb0, 0x5c, 0x79, 0xf0, 0x90, 0x97, 0x9b, 0xf4, 0xa8, 0x02, 0x70, 0xab, 0xa2, 0x32, 0xdf,
    0xf1, 0x1a, 0x10, 0xd9, 0xca, 0x55, 0xc4, 0xf8, 0x8d, 0xe9, 0x53, 0x17, 0x97, 0x0f, 0x0d, 0xe9,
];

/// The EAS attester of every Coinbase KYC attestation on Base:
/// 0x357458739F90461b99789350868CD7CF330Dd7EE.
global COINBASE_ATTESTER: [u8; 20] = [
    0x35, 0x74, 0x58, 0x73, 0x9F, 0x90, 0x46, 0x1b, 0x99, 0x78,
    0x93, 0x50, 0x86, 0x8C, 0xD7, 0xCF, 0x33, 0x0D, 0xd7, 0xEE,
];

/// Storage slot of EAS `_db` in the OP-stack predeploy (contracts-bedrock
/// storage layout snapshot; read back on Base 2026-10-22).
global EAS_DB_SLOT: u8 = 50;

/// keccak256("coinbase_eas_storage_poc"), compiled in.
global CIRCUIT_TAG: [u8; 32] = [
    0x4f, 0xb1, 0xb3, 0x21, 0x74, 0xdb, 0xec, 0xb1, 0x34, 0x38, 0xc5, 0x07, 0xc9, 0xc6, 0xd3, 0xfe,
    0xb4, 0xa1, 0xce, 0xa3, 0x0f, 0x8e, 0x7e, 0x30, 0x99, 0x31, 0xbb, 0x37, 0xf6, 0x67, 0x8b, 0xb8,
];

/// Measured 7 internal nodes on Base, 2026-10-22; three spare levels.
global MAX_DEPTH_NO_LEAF: u32 = 10;
/// List header 2 + path 34 + value 34.
global MAX_LEAF_LEN: u32 = 70;

global UID_PREIMAGE_LEN: u32 = 157;

fn u64_be(x: u64) -> [u8; 8] {
    let mut out: [u8; 8] = [0; 8];
    let mut v = x;
    for j in 0..8 {
        out[7 - j] = v as u8;
        v = v >> 8;
    }
    out
}

fn u32_be(x: u32) -> [u8; 4] {
    let mut out: [u8; 4] = [0; 4];
    let mut v = x;
    for j in 0..4 {
        out[3 - j] = v as u8;
        v = v >> 8;
    }
    out
}

fn attestation_uid(
    recipient: [u8; 20],
    time: u64,
    revocable: bool,
    ref_uid: [u8; 32],
    bump: u32,
) -> [u8; 32] {
    let mut p: [u8; UID_PREIMAGE_LEN] = [0; UID_PREIMAGE_LEN];
    for i in 0..32 {
        p[i] = KYC_SCHEMA[i];
    }
    for i in 0..20 {
        p[32 + i] = recipient[i];
        p[52 + i] = COINBASE_ATTESTER[i];
    }
    let time_be = u64_be(time);
    for i in 0..8 {
        p[72 + i] = time_be[i];
    }
    // expirationTime: bytes 80..88 stay zero -- Coinbase sets none, and the
    // stored word below would differ if it had.
    p[88] = revocable as u8;
    for i in 0..32 {
        p[89 + i] = ref_uid[i];
    }
    // data = abi.encode(true): 31 zero bytes, then 0x01.
    p[152] = 0x01;
    let bump_be = u32_be(bump);
    for i in 0..4 {
        p[153 + i] = bump_be[i];
    }
    keccak256(p, UID_PREIMAGE_LEN)
}

/// keccak(uid ++ uint256(50)) + 2, as a 256-bit big-endian sum.
fn timestamps_slot(uid: [u8; 32]) -> [u8; 32] {
    let mut key: [u8; 64] = [0; 64];
    for i in 0..32 {
        key[i] = uid[i];
    }
    key[63] = EAS_DB_SLOT;
    let base = keccak256(key, 64);

    let mut slot: [u8; 32] = [0; 32];
    let mut carry: u32 = 2;
    for j in 0..32 {
        let i = 31 - j;
        let sum = base[i] as u32 + carry;
        slot[i] = sum as u8;
        carry = sum >> 8;
    }
    slot
}

fn main(
    // ============ Public Inputs ============
    signal_hash: pub [u8; 32],
    domain_separator: pub [u8; 32],
    action_hash: pub [u8; 32],
    eas_storage_root: pub [u8; 32],
    scope: pub [u8; 32],
    nullifier: pub [u8; 32],

    // ============ Private Inputs ============
    user_address: [u8; 20],
    user_signature: [u8; 64],
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],

    attestation_time: u64,
    attestation_revocable: bool,
    attestation_ref_uid: [u8; 32],
    attestation_bump: u32,

    proof_nodes: [[u8; MAX_NODE_LEN]; MAX_DEPTH_NO_LEAF],
    proof_leaf: [u8; MAX_LEAF_LEN],
    proof_depth: u64,
) {
    // PART 1: this wallet signed this request.
    let derived = derive_address_from_pubkey(user_pubkey_x, user_pubkey_y);
    assert(derived == user_address, "User pubkey does not match address");
    let digest = signed_digest(signal_hash, domain_separator, action_hash);
    assert(
        std::ecdsa_secp256k1::verify_signature(user_pubkey_x, user_pubkey_y, user_signature, digest),
        "Invalid user signature on the signed message",
    );

    // PART 2: a live Coinbase attestation to this wallet is in EAS storage.
    assert(attestation_time != 0, "An attestation time of zero is an absent record");
    let uid = attestation_uid(
        user_address,
        attestation_time,
        attestation_revocable,
        attestation_ref_uid,
        attestation_bump,
    );
    let slot = timestamps_slot(uid);

    // revocationTime | expirationTime | time, high to low: only time is set.
    let mut word: [u8; 32] = [0; 32];
    let time_be = u64_be(attestation_time);
    for i in 0..8 {
        word[24 + i] = time_be[i];
    }
    verify_storage_slot(
        slot,
        word,
        eas_storage_root,
        Proof { nodes: proof_nodes, leaf: proof_leaf, depth: proof_depth },
    );

    // PART 3: one nullifier per wallet per scope.
    verify_wallet_nullifier(user_address, CIRCUIT_TAG, scope, nullifier);
}
