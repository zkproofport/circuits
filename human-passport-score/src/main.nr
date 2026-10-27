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
// SHAPE. GIWA's six public inputs, unchanged in meaning and order, then three
// more. The wallet part (EIP-712 action or personal_sign over signal_hash, and
// the wallet + circuit-tag nullifier) is the shared code giwa_attestation
// uses. The issuer part lives in human-passport-libs so the real-chain check
// (../human-passport-real-issuer-check/) runs the same code.

use std;
use ::coinbase_libs::nullifier::verify_wallet_nullifier;
use ::coinbase_libs::signed_message::signed_digest;
use ::coinbase_libs::ethereum::derive_address_from_pubkey;
use ::human_passport_libs::request::PassportRequest;
use ::human_passport_libs::issuer::verify_score_statement;

/// The largest scoreV2 `data` this circuit hashes. The issuer signs
/// keccak256(data) and data carries every stamp, so this cap decides which
/// passports can be proved at all. Why this number: ../README.md, "Data cap".
global MAX_DATA_BYTES: u32 = 10240;

/// keccak256("human_passport_score"). Compiled in: the nullifier has no input
/// the prover can vary.
global CIRCUIT_TAG: [u8; 32] = [
    0x21, 0x84, 0x73, 0xb2, 0xbf, 0x29, 0xe7, 0xda,
    0x0a, 0xed, 0x1e, 0x31, 0xdc, 0x0c, 0xc1, 0x12,
    0xbf, 0xdd, 0x2e, 0xee, 0x2d, 0xa1, 0xdf, 0x4b,
    0x85, 0x0e, 0x79, 0x8f, 0x60, 0x93, 0x96, 0x07,
];

fn main(
    // ============ Public inputs (order is the ABI) ============

    // personal_sign challenge when no action is bound; zero in action mode.
    signal_hash: pub [u8; 32],
    // EIP-712 action the wallet signed, or zeros. See signed_message.nr.
    domain_separator: pub [u8; 32],
    action_hash: pub [u8; 32],
    // Root over keccak(issuer ++ passport_domain_separator ++ schema_uid).
    signer_list_merkle_root: pub [u8; 32],
    // Sybil domain; nullifier = keccak(keccak(wallet ++ CIRCUIT_TAG) ++ scope).
    scope: pub [u8; 32],
    nullifier: pub [u8; 32],
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

    // PART 3: one nullifier per wallet per scope.
    verify_wallet_nullifier(user_address, CIRCUIT_TAG, scope, nullifier);
}
