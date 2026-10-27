// "Human Passport's issuer signed a scoreV2 attestation for `recipient`, its
// score is at least `min_score` under scorer `scorer_id`, and it has not
// expired at `now`."
//
// Everything except the wallet. `human_passport_score` adds the wallet's own
// signature and the nullifier; `human-passport-real-issuer-check` runs this alone against an
// issuance read from Base, whose recipient key nobody here holds.
//
// WHO COUNTS AS THE ISSUER. The verifier publishes a Merkle root over leaves
//
//   keccak256(issuer_address[20] ++ passport_domain_separator[32] ++ schema_uid[32])
//
// one per (issuer key, GitcoinVerifier deployment, scoreV2 schema). All three
// belong in the leaf:
//   - the issuer key, because it is the only thing that signs;
//   - the domain separator, because it names the chain and the GitcoinVerifier
//     contract the signature was made for -- the same key signs on every chain;
//   - the schema uid, because it is derived from the resolver address and so
//     differs per chain, and because the `data` layout read below is only the
//     scoreV2 layout. A signature over another schema's data must not be read
//     as a score.
// A list rather than a constant so a rotated issuer key or a new chain is a
// new root the verifier publishes, not a new circuit.

use std;
use ::keccak256::keccak256;
use ::coinbase_libs::merkle;
use ::coinbase_libs::ethereum::derive_address_from_pubkey;
use crate::request::{PassportRequest, passport_digest};
use crate::score_data::parse_score_head;

pub fn issuer_leaf(
    issuer: [u8; 20],
    passport_domain_separator: [u8; 32],
    schema_uid: [u8; 32],
) -> [u8; 32] {
    let mut pre: [u8; 84] = [0; 84];
    for i in 0..20 {
        pre[i] = issuer[i];
    }
    for i in 0..32 {
        pre[20 + i] = passport_domain_separator[i];
        pre[52 + i] = schema_uid[i];
    }
    keccak256(pre, 84)
}

pub fn verify_score_statement<let N: u32>(
    // what the verifier reads
    signer_list_merkle_root: [u8; 32],
    min_score: u32,
    scorer_id: Field,
    now: u64,
    // what the issuer signed
    passport_domain_separator: [u8; 32],
    req: PassportRequest,
    data: [u8; N],
    data_len: u32,
    issuer_signature: [u8; 64],
    issuer_pubkey_x: [u8; 32],
    issuer_pubkey_y: [u8; 32],
    issuer_merkle_proof: [[u8; 32]; 8],
    issuer_leaf_index: u32,
    issuer_merkle_depth: u32,
) {
    // 0. The head first: it also bounds data_len, which keccak256 would
    //    otherwise refuse with no message at all.
    let head = parse_score_head(data, data_len);

    // 1. The issuer key signed exactly this request.
    let digest = passport_digest(passport_domain_separator, req, data, data_len);
    let valid = std::ecdsa_secp256k1::verify_signature(
        issuer_pubkey_x,
        issuer_pubkey_y,
        issuer_signature,
        digest,
    );
    assert(valid, "Invalid issuer signature");

    // 2. That key, on that deployment, for that schema, is one the verifier
    //    accepts. The key is supplied by the prover; it is trusted only because
    //    the signature above verifies against it AND its leaf is in the list.
    let issuer = derive_address_from_pubkey(issuer_pubkey_x, issuer_pubkey_y);
    let leaf = issuer_leaf(issuer, passport_domain_separator, req.schema);
    let root = merkle::verify_merkle_proof(
        leaf,
        issuer_leaf_index,
        issuer_merkle_proof,
        issuer_merkle_depth,
    );
    assert(root == signer_list_merkle_root, "Issuer not in valid list");

    // 3. Not expired. EAS reads expirationTime 0 as "never"; Passport always
    //    sets one (90 days), and a statement about freshness cannot rest on an
    //    attestation that claims to last forever. `now < 0` is false for every
    //    u64, so this one comparison also refuses 0 -- a separate `!= 0` guard
    //    was unreachable (scripts/human-passport/mutation-check.sh showed it).
    assert(now < req.expiration_time, "Attestation expired");

    // 4. The score, read as the resolver reads it.
    assert(head.scorer_id == scorer_id, "Scorer id mismatch");
    assert(head.score >= min_score, "Score below threshold");
}

#[test]
fn leaf_binds_all_three_parts() {
    let a: [u8; 20] = [1; 20];
    let d: [u8; 32] = [2; 32];
    let s: [u8; 32] = [3; 32];
    let base = issuer_leaf(a, d, s);
    assert(base != issuer_leaf([4; 20], d, s));
    assert(base != issuer_leaf(a, [4; 32], s));
    assert(base != issuer_leaf(a, d, [4; 32]));
}
