// coinbase_attestation v2 -- the Android FACTORY package.
//
// The same circuit id, public inputs, Coinbase revocation statement and nullifier as
// ../coinbase-attestation-v2-android (and its iPhone/server package); only who signed the
// statement differs: an Android phone whose attestation key was provisioned
// at the factory (devices launched with Android 12 or earlier), proven by its
// key attestation chain under Google's RSA root AND a Google Play Integrity
// verdict bound to the statement (../statement-signer
// verify_statement_android_factory), as zkPassport's Android FaceMatch
// circuit pairs them (decided 2026-10-28, user: Android 12 and earlier must
// be supported). Phones with Remote Key Provisioning use ../coinbase-attestation-v2-android,
// which needs no verdict and no server.

use coinbase_libs::nullifier::verify_wallet_nullifier;
use coinbase_v2_libs::{check_request_and_tx, CIRCUIT_TAG};
use coinbase_v2_libs::client_data::{check_client_data, CLIENT_DATA_LEN};
use statement_signer::{
    BATCH_TBS_MAX_LEN, FactoryChain, IK_TBS_MAX_LEN, IntegrityToken, LEAF_TBS_MAX_LEN,
    PAYLOAD_B64_MAX_LEN, RSA4096_LIMBS, verify_statement_android_factory,
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
    ik_tbs: [u8; IK_TBS_MAX_LEN],
    ik_tbs_len: u32,
    ik_sig: [u128; RSA4096_LIMBS],
    batch_tbs: [u8; BATCH_TBS_MAX_LEN],
    batch_tbs_len: u32,
    batch_sig: [u8; 96],
    leaf_tbs: [u8; LEAF_TBS_MAX_LEN],
    leaf_tbs_len: u32,
    leaf_sig: [u8; 64],
    // Google Play's integrity verdict for this statement: the JWS payload as
    // signed (base64url, zero-padded) and Google's ES256 signature, r || s.
    integrity_payload_b64: [u8; PAYLOAD_B64_MAX_LEN],
    integrity_payload_b64_len: u32,
    integrity_signature: [u8; 64],
    rsa_root_modulus: [u128; RSA4096_LIMBS],
    rsa_root_redc: [u128; RSA4096_LIMBS],
    // Google's RSA root and our app's Play Integrity verification key, as
    // prover inputs pinned by hash in ../statement-signer (Barretenberg cannot
    // build them as constants; see verify_statement_android_factory).
    play_integrity_key: [u8; 64],
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
    verify_statement_android_factory(
        client_data,
        statement_sig,
        FactoryChain {
            ik_tbs,
            ik_tbs_len,
            ik_sig,
            batch_tbs,
            batch_tbs_len,
            batch_sig,
            leaf_tbs,
            leaf_tbs_len,
            leaf_sig,
        },
        IntegrityToken {
            payload_b64: integrity_payload_b64,
            payload_b64_len: integrity_payload_b64_len,
            signature: integrity_signature,
        },
        rsa_root_modulus,
        rsa_root_redc,
        play_integrity_key,
    );

    // PART 4: one nullifier per wallet per scope
    verify_wallet_nullifier(user_address, CIRCUIT_TAG, scope, nullifier);
}
