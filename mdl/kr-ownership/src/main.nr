// ZKProofport: Korea Mobile ID - Ownership predicate (expected-value matching)
//
// The prover holds a valid OmniOne CX response AND supplies a separate
// "expected" tuple (name / birth_date / sex / telno) - either the user
// typed it in or the dApp pre-committed to it. For every disclose_flags
// bit that is set the corresponding mDL value MUST equal the expected
// value, and owner_commit is derived from the expected values masked
// by the same flags. This lets a dApp pre-compute owner_commit and
// challenge the prover with it, instead of just accepting whatever the
// prover decides to disclose.
//
// Anonymous mode (disclose_flags == 0) skips all equality checks and
// forces owner_commit to the 32-byte zero hash.
//
// Same canonical (ci || jti || pri || birth || address) commitment as
// the age and region circuits, so a single user produces the same
// nullifier across all three circuits for a given scope/signal_hash.

use dep::coinbase_libs::nullifier;
use dep::mdl_kr_common::{
    verify_cx_integrity,
    derive_self_id_20,
    assert_owner_commit,
};

fn main(
    // ============ Public Inputs ============
    signal_hash:       pub [u8; 32],
    scope:             pub [u8; 32],
    nullifier_value:   pub [u8; 32],
    cx_integrity_root: pub [u8; 32],
    disclose_flags:    pub u8,
    owner_commit:      pub [u8; 32],
    // ============ Private Inputs ============
    // mDL values from the OmniOne CX response.
    ci:                [u8; 88],
    cx_jti:            [u8; 40],
    cx_pri:            [u8; 44],
    name:              [u8; 64],
    birth_date:        [u8; 8],
    telno:             [u8; 16],
    sex:               u8,
    address:           [u8; 256],
    // Expected values supplied by user or dApp.
    expected_name:     [u8; 64],
    expected_birth:    [u8; 8],
    expected_telno:    [u8; 16],
    expected_sex:      u8,
) {
    verify_cx_integrity(cx_jti, cx_pri, cx_integrity_root);
    let self_id_20 = derive_self_id_20(ci, cx_jti, cx_pri, birth_date, address);
    nullifier::verify_nullifier(self_id_20, signal_hash, scope, nullifier_value);
    assert_owner_commit(
        disclose_flags,
        name,
        birth_date,
        sex,
        telno,
        expected_name,
        expected_birth,
        expected_sex,
        expected_telno,
        owner_commit,
    );
}
