// What can be refused without anyone's private key. The accepting cases need
// a signature by a pinned key, so they run in each circuit's acceptance run
// against a synthetic-anchors copy (scripts/statement-signer/).

use crate::{KIND_APP, KIND_SERVER, SignerChain, verify_statement};

fn empty_chain() -> SignerChain {
    SignerChain {
        credential_tbs: [0; crate::CREDENTIAL_TBS_MAX_LEN],
        credential_tbs_len: 0,
        credential_sig: [0; 96],
        att_auth_data: [0; crate::ATT_AUTH_DATA_MAX_LEN],
        att_auth_data_len: 0,
        att_client_data_hash: [0; 32],
        assertion_auth_data: [0; crate::ASSERT_AUTH_DATA_MAX_LEN],
        assertion_auth_data_len: 0,
    }
}

// r = 1, s = 1: a well-formed low-s signature no key made over this digest.
fn garbage_sig() -> [u8; 64] {
    let mut sig = [0; 64];
    sig[31] = 1;
    sig[63] = 1;
    sig
}

#[test(should_fail_with = "Unknown statement signer kind")]
fn kind_zero_is_refused() {
    verify_statement([1, 2, 3], 0, garbage_sig(), empty_chain());
}

#[test(should_fail_with = "Unknown statement signer kind")]
fn kind_three_is_refused() {
    verify_statement([1, 2, 3], 3, garbage_sig(), empty_chain());
}

#[test(should_fail_with = "Unknown statement signer kind")]
fn kind_255_is_refused() {
    verify_statement([1, 2, 3], 255, garbage_sig(), empty_chain());
}

#[test(should_fail_with = "Statement signature is invalid")]
fn server_kind_garbage_signature_is_refused() {
    verify_statement([1, 2, 3], KIND_SERVER, garbage_sig(), empty_chain());
}

// The all-zero signature: r = 0 is never a valid ECDSA signature. The
// solver refuses it before the assert (ACVM's P-256 black box).
#[test(should_fail_with = "Signature provided for ECDSA verification is zero")]
fn server_kind_zero_signature_is_refused() {
    verify_statement([1, 2, 3], KIND_SERVER, [0; 64], empty_chain());
}

// The app kind needs a certificate chain; zeros are refused by name.
#[test(should_fail_with = "No App Attest certificate chain")]
fn app_kind_without_a_chain_is_refused() {
    verify_statement([1, 2, 3], KIND_APP, garbage_sig(), empty_chain());
}

// ---- the Android signer ----------------------------------------------------
// Accepting needs a Google-signed chain with its leaf's private key, so the
// accepted cases run in the -android packages' acceptance runs (synthetic
// root); android-key-attestation's tests run real Google chains.

fn empty_android_chain() -> crate::AndroidChain {
    crate::AndroidChain {
        ca2_tbs: [0; crate::CA2_TBS_MAX_LEN],
        ca2_tbs_len: 0,
        ca2_sig: [0; 96],
        ca3_tbs: [0; crate::CA3_TBS_MAX_LEN],
        ca3_tbs_len: 0,
        ca3_sig: [0; 96],
        att_tbs: [0; crate::ATT_TBS_MAX_LEN],
        att_tbs_len: 0,
        att_sig: [0; 64],
        leaf_tbs: [0; crate::LEAF_TBS_MAX_LEN],
        leaf_tbs_len: 0,
        leaf_sig: [0; 64],
    }
}

// The server's zeros are not an Android chain.
#[test(should_fail_with = "No Android key attestation chain")]
fn android_with_no_chain_is_refused() {
    crate::verify_statement_android([1, 2, 3], garbage_sig(), empty_android_chain(), 1772323200);
}
