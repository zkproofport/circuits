// coinbase_attestation v2 -- the Android package.
//
// The same circuit id (`coinbase_attestation`), public inputs, 225-byte
// statement ("ZKProofport/AA/1", ../coinbase-v2-libs client_data.nr) and
// nullifier as ../coinbase-attestation-v2; only who signed the statement
// differs: an Android phone's hardware-backed key, proven by Android key
// attestation (../statement-signer verify_statement_android,
// ../android-key-attestation). A separate package because that chain is
// 1,167,923 gates and would make every iPhone and server proof 2^21 as a
// third signer kind (decided 2026-10-28, .claude/agents/circuits-dev.md
// "Android signer").
//
// attested_at -- the statement's time, which the verifier bounds against its
// own clock -- is also the time the chain's certificates must be valid at.

use coinbase_libs::nullifier::verify_wallet_nullifier;
use coinbase_v2_libs::{check_request_and_tx, CIRCUIT_TAG};
use coinbase_v2_libs::client_data::{check_client_data, CLIENT_DATA_LEN};
use statement_signer::{
    AndroidChain, ATT_TBS_MAX_LEN, CA2_TBS_MAX_LEN, CA3_TBS_MAX_LEN, LEAF_TBS_MAX_LEN,
    verify_statement_android,
};

fn main(
    // ============ Public Inputs (giwa_attestation's six, in its order) ============
    signal_hash: pub [u8; 32],
    domain_separator: pub [u8; 32],
    action_hash: pub [u8; 32],
    signer_list_merkle_root: pub [u8; 32],
    scope: pub [u8; 32],
    nullifier: pub [u8; 32],
    // ============ Public Input (the statement's time) ============
    // When the signer saw the attestation unrevoked (unix seconds). The
    // verifier enforces freshness against its own clock.
    attested_at: pub u64,
    // ============ Private Inputs ============
    user_address: [u8; 20],
    user_signature: [u8; 64],
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],
    raw_transaction: [u8; 300],
    tx_length: u32,
    coinbase_attester_pubkey_x: [u8; 32],
    coinbase_attester_pubkey_y: [u8; 32],
    coinbase_signer_merkle_proof: [[u8; 32]; 8],
    coinbase_signer_leaf_index: u32,
    merkle_proof_depth: u32,
    // The statement, and who signed it.
    client_data: [u8; CLIENT_DATA_LEN],
    // P-256 r || s, s in low form: an Android key's SHA256withECDSA
    // signature over client_data, and the Android key attestation chain below
    // Google's pinned root that vouches for that key
    // (../statement-signer verify_statement_android).
    statement_sig: [u8; 64],
    ca2_tbs: [u8; CA2_TBS_MAX_LEN],
    ca2_tbs_len: u32,
    ca2_sig: [u8; 96],
    ca3_tbs: [u8; CA3_TBS_MAX_LEN],
    ca3_tbs_len: u32,
    ca3_sig: [u8; 96],
    att_tbs: [u8; ATT_TBS_MAX_LEN],
    att_tbs_len: u32,
    att_sig: [u8; 64],
    leaf_tbs: [u8; LEAF_TBS_MAX_LEN],
    leaf_tbs_len: u32,
    leaf_sig: [u8; 64],
) {
    // PARTS 1-2: this wallet signed THIS request; Coinbase's attestAccount
    let message_hash = check_request_and_tx(
        signal_hash,
        domain_separator,
        action_hash,
        signer_list_merkle_root,
        user_address,
        user_signature,
        user_pubkey_x,
        user_pubkey_y,
        raw_transaction,
        tx_length,
        coinbase_attester_pubkey_x,
        coinbase_attester_pubkey_y,
        coinbase_signer_merkle_proof,
        coinbase_signer_leaf_index,
        merkle_proof_depth,
    );

    // PART 3: an Android phone running our app said, at attested_at, that
    //         this wallet's Coinbase attestation was unrevoked
    check_client_data(
        client_data,
        CIRCUIT_TAG,
        user_address,
        attested_at,
        message_hash,
        scope,
    );
    verify_statement_android(
        client_data,
        statement_sig,
        AndroidChain {
            ca2_tbs,
            ca2_tbs_len,
            ca2_sig,
            ca3_tbs,
            ca3_tbs_len,
            ca3_sig,
            att_tbs,
            att_tbs_len,
            att_sig,
            leaf_tbs,
            leaf_tbs_len,
            leaf_sig,
        },
        attested_at,
    );

    // PART 4: one nullifier per wallet per scope
    verify_wallet_nullifier(user_address, CIRCUIT_TAG, scope, nullifier);
}
