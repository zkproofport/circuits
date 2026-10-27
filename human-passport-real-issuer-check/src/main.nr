// The issuer half of human_passport_score, run against a REAL scoreV2
// issuance read from Base -- the real issuer's real signature over real data.
//
// Why a separate program. The full circuit also needs the attested wallet to
// sign, and nobody here holds the key of a wallet with a Passport score. This
// runs the SAME library function the circuit calls (verify_score_statement),
// so the EIP-712 rebuild, the issuer recovery and the head parsing are checked
// against bytes the chain holds, not only against bytes our fixture generator
// produced. The wallet half is the shared code giwa_attestation already uses.
//
// Not a shipped circuit: no verifier, no SRS, never downloaded. It is executed
// (nargo execute), not proved.

use ::human_passport_libs::request::PassportRequest;
use ::human_passport_libs::issuer::verify_score_statement;

global MAX_DATA_BYTES: u32 = 10240;

fn main(
    signer_list_merkle_root: pub [u8; 32],
    min_score: pub u32,
    scorer_id: pub Field,
    now: pub u64,
    recipient: pub [u8; 20],
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
    issuer_signature: [u8; 64],
    issuer_pubkey_x: [u8; 32],
    issuer_pubkey_y: [u8; 32],
    issuer_merkle_proof: [[u8; 32]; 8],
    issuer_leaf_index: u32,
    issuer_merkle_depth: u32,
) {
    let req = PassportRequest {
        schema: schema_uid,
        recipient,
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
}
