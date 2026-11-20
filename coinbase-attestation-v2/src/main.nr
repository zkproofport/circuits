// coinbase_attestation v2 -- Coinbase KYC whose revocation is bound by a
// signed statement, from Apple App Attest or from the AI server.
//
// Built from the coinbase_app_attest_poc prototype (circuits commit
// b281485 / 33344e2). This package is named coinbase_attestation_v2 while v1
// still lives in ../coinbase-attestation; the circuit ID it serves is the
// canonical `coinbase_attestation`, and that is what its clientData's
// statement kind carries. README.md has the clientData spec, what the server signs,
// the public inputs and the measurements.
//
// WHY A SIGNED STATEMENT
//
// coinbase_attestation v1 proves Coinbase once sent attestAccount(wallet).
// That stays true after Coinbase revokes the attestation. So whoever builds
// the proof looks the EAS attestation up right before proving and, only if it
// is unrevoked, has a key the circuit trusts sign a statement saying so,
// bound to this wallet, this time and this request (decided 2026-10-23,
// .claude/agents/circuits-dev.md "Decisions").
//
// WHO SIGNS THE STATEMENT
//
// The phone (Apple App Attest) or the AI server (Cloud KMS), behind a private
// signer-kind byte, through ../statement-signer: the library that pins both
// keys and holds the one signature check. oidc_domain_attestation uses the
// same library, so the two circuits trust exactly the same signers. A
// statement here starts with "ZKProofport/AA/1" and keccak256
// ("coinbase_attestation") and is 225 bytes (client_data.nr); that is what
// keeps a signature over another circuit's statement from passing here.
//
// WHAT THIS PROVES
//
//   1. The wallet signed the request: personal_sign over signal_hash, or an
//      EIP-712 action -- coinbase_libs::signed_message::signed_digest, the
//      same rule as giwa_attestation, with the same public-input order.
//   2. coinbase_attestation v1's checks, unchanged: an attestAccount(wallet)
//      transaction to Coinbase's attester, signed by a key whose address is
//      in the public signer Merkle root.
//   3. A statement (client_data.nr) naming this wallet, the public
//      attested_at, Coinbase's KYC schema and attester, revoked = 0, this
//      request's digest and this scope, signed by the app (production App
//      Attest environment only) or by the server.
//   4. Nullifier: the OPRF nullifier for this wallet in (domain, scope)
//      (../oprf-nullifier-libs), under the OPRF key whose hash is public.
//
// THE STATEMENT KIND IS keccak256("coinbase_attestation"), the canonical id,
// not this package's name (CIRCUIT_TAG in ../coinbase-v2-libs).

use oprf_nullifier_libs::{OprfAnswer, verify_oprf_nullifier};
use coinbase_v2_libs::{check_request_and_tx, CIRCUIT_TAG};
use coinbase_v2_libs::client_data::{CLIENT_DATA_LEN, check_client_data};
use statement_signer::{
    ASSERT_AUTH_DATA_MAX_LEN, ATT_AUTH_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN, SignerChain,
    verify_statement,
};

fn main(
    // ============ Public Inputs (giwa_attestation's six, in its order) ============
    signal_hash: pub [u8; 32],
    domain_separator: pub [u8; 32],
    action_hash: pub [u8; 32],
    signer_list_merkle_root: pub [u8; 32],
    // The OPRF nullifier (../oprf-nullifier-libs): the hash of the OPRF key the
    // verifier pins for this proof type, the nullifier's domain and scope
    // (keccak256(string) mod p each), and the nullifier -- one per wallet per
    // (domain, scope) under that key, which nobody without the key can compute
    // from an address.
    oprf_key_hash: pub Field,
    domain: pub Field,
    scope: pub Field,
    nullifier: pub Field,

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
    signer_kind: u8,
    // P-256 r || s, s in low form: the App Attest assertion signature (app)
    // or the server's signature (server).
    statement_sig: [u8; 64],

    // App Attest chain below the pinned intermediate. The server kind passes
    // zeros for all of these.
    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    credential_tbs_len: u32,
    credential_sig: [u8; 96],
    att_auth_data: [u8; ATT_AUTH_DATA_MAX_LEN],
    att_auth_data_len: u32,
    att_client_data_hash: [u8; 32],
    assertion_auth_data: [u8; ASSERT_AUTH_DATA_MAX_LEN],
    assertion_auth_data_len: u32,
    // The OPRF nodes' answer for this wallet's query, and the blinding factor
    // (private; ../oprf-nullifier-libs checks them).
    oprf_public_key_x: Field,
    oprf_public_key_y: Field,
    oprf_beta: Field,
    oprf_dlog_e: Field,
    oprf_dlog_s: Field,
    oprf_response_x: Field,
    oprf_response_y: Field,
) {
    // ===================================================================
    // PARTS 1-2: this wallet signed THIS request; coinbase_attestation's
    //            transaction checks, unchanged (../coinbase-v2-libs)
    // ===================================================================
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

    // ===================================================================
    // PART 3: a trusted signer said, at attested_at, that this wallet's
    //         Coinbase attestation was unrevoked -- for this request
    // ===================================================================
    check_client_data(
        client_data,
        CIRCUIT_TAG,
        user_address,
        attested_at,
        message_hash,
        scope.to_be_bytes::<32>(),
    );
    verify_statement(
        client_data,
        signer_kind,
        statement_sig,
        SignerChain {
            credential_tbs,
            credential_tbs_len,
            credential_sig,
            att_auth_data,
            att_auth_data_len,
            att_client_data_hash,
            assertion_auth_data,
            assertion_auth_data_len,
        },
    );

    // ===================================================================
    // PART 4: one nullifier per wallet per (domain, scope), from the OPRF
    // ===================================================================
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
