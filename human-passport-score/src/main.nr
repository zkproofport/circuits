// ZKProofport: human_passport_score
//
// "The wallet that signed this request holds a Human Passport scoreV2
//  attestation, signed by an issuer the verifier accepts, scored at least
//  `min_score` by scorer `scorer_id`, and not expired at `now`."
//
// The wallet, the attestation, its exact score and its stamps stay private.
// The design, the trust assumptions and what this does NOT prove (revocation,
// a newer lower score) are in ../README.md.
//
// SHAPE. giwa_attestation's public inputs, in its order (the wallet's request,
// the issuer root, then the OPRF nullifier's four), then three more. The
// wallet part (EIP-712 action or personal_sign over signal_hash) is the shared
// code giwa_attestation uses; the nullifier is ../oprf-nullifier-libs, as in
// every wallet credential circuit. The issuer part lives in human-passport-libs
// so the real-chain check (../human-passport-real-issuer-check/) runs the same
// code.

use std;
use ::coinbase_libs::signed_message::signed_digest;
use ::coinbase_libs::ethereum::derive_address_from_pubkey;
use ::human_passport_libs::request::PassportRequest;
use ::human_passport_libs::issuer::verify_score_statement;
use ::oprf_nullifier_libs::{OprfAnswer, verify_oprf_nullifier};

/// The largest scoreV2 `data` this circuit hashes. The issuer signs
/// keccak256(data) and data carries every stamp, so this cap decides which
/// passports can be proved at all. Why this number: ../README.md, "Data cap".
global MAX_DATA_BYTES: u32 = 10240;

fn main(
    // ============ Public inputs (order is the ABI) ============

    // personal_sign challenge when no action is bound; zero in action mode.
    signal_hash: pub [u8; 32],
    // EIP-712 action the wallet signed, or zeros. See signed_message.nr.
    domain_separator: pub [u8; 32],
    action_hash: pub [u8; 32],
    // Root over keccak(issuer ++ passport_domain_separator ++ schema_uid).
    signer_list_merkle_root: pub [u8; 32],
    // The OPRF nullifier (../oprf-nullifier-libs): the hash of the OPRF key the
    // verifier pins for this proof type, the nullifier's domain and scope
    // (keccak256(string) mod p each), and the nullifier, one per wallet per
    // (domain, scope) under that key.
    oprf_key_hash: pub Field,
    domain: pub Field,
    scope: pub Field,
    nullifier: pub Field,
    // Threshold in Passport's units: score * 10^4 (20.0 -> 200000).
    min_score: pub u32,
    // Passport scorer ("community") id the score was computed by.
    scorer_id: pub Field,
    // Unix seconds the attestation must still be valid at. The verifier
    // checks this is close to its own clock; the circuit cannot.
    now: pub u64,

    // ============ Private inputs ============

    user_address: [u8; 20],
    user_signature: [u8; 64], // r ++ s
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],

    passport_domain_separator: [u8; 32],
    schema_uid: [u8; 32],
    expiration_time: u64,
    revocable: bool,
    ref_uid: [u8; 32],
    attestation_value: [u8; 32],
    request_nonce: [u8; 32],
    request_fee: [u8; 32],
    score_data: [u8; MAX_DATA_BYTES],
    score_data_len: u32,

    issuer_signature: [u8; 64], // r ++ s
    issuer_pubkey_x: [u8; 32],
    issuer_pubkey_y: [u8; 32],
    issuer_merkle_proof: [[u8; 32]; 8],
    issuer_leaf_index: u32,
    issuer_merkle_depth: u32,

    // The OPRF nodes' answer for this wallet's query, and the blinding factor.
    oprf_public_key_x: Field,
    oprf_public_key_y: Field,
    oprf_beta: Field,
    oprf_dlog_e: Field,
    oprf_dlog_s: Field,
    oprf_response_x: Field,
    oprf_response_y: Field,
) {
    // PART 1: this wallet signed this request.
    let derived = derive_address_from_pubkey(user_pubkey_x, user_pubkey_y);
    assert(derived == user_address, "User pubkey does not match address");
    let message_hash = signed_digest(signal_hash, domain_separator, action_hash);
    let valid_user_sig = std::ecdsa_secp256k1::verify_signature(
        user_pubkey_x,
        user_pubkey_y,
        user_signature,
        message_hash,
    );
    assert(valid_user_sig, "Invalid user signature on the signed message");

    // PART 2: Human Passport's issuer attested a high-enough, unexpired score
    // for THIS wallet. The recipient is a field of the signed request, so
    // setting it to user_address here is what ties the score to the signer.
    let req = PassportRequest {
        schema: schema_uid,
        recipient: user_address,
        expiration_time,
        revocable,
        ref_uid,
        value: attestation_value,
        nonce: request_nonce,
        fee: request_fee,
    };
    verify_score_statement(
        signer_list_merkle_root,
        min_score,
        scorer_id,
        now,
        passport_domain_separator,
        req,
        score_data,
        score_data_len,
        issuer_signature,
        issuer_pubkey_x,
        issuer_pubkey_y,
        issuer_merkle_proof,
        issuer_leaf_index,
        issuer_merkle_depth,
    );

    // PART 3: one nullifier per wallet per (domain, scope), from the OPRF.
    verify_oprf_nullifier(
        user_address,
        domain,
        scope,
        oprf_key_hash,
        nullifier,
        OprfAnswer {
            public_key_x: oprf_public_key_x,
            public_key_y: oprf_public_key_y,
            beta: oprf_beta,
            dlog_e: oprf_dlog_e,
            dlog_s: oprf_dlog_s,
            response_x: oprf_response_x,
            response_y: oprf_response_y,
        },
    );
}
