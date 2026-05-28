// ZKProofport: Korea Mobile ID - Ownership predicate
//
// Predicate: the prover holds a valid OmniOne CX response and discloses
// the selected subset of attributes (name / birth / sex / telno) under
// the disclose_flags mask. No age or region check. Anonymous mode
// (disclose_flags == 0) is allowed and forces owner_commit to zero.
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
    ci:                [u8; 88],
    cx_jti:            [u8; 40],
    cx_pri:            [u8; 44],
    name:              [u8; 64],
    birth_date:        [u8; 8],
    telno:             [u8; 16],
    sex:               u8,
    address:           [u8; 256],
) {
    verify_cx_integrity(cx_jti, cx_pri, cx_integrity_root);
    let self_id_20 = derive_self_id_20(ci, cx_jti, cx_pri, birth_date, address);
    nullifier::verify_nullifier(self_id_20, signal_hash, scope, nullifier_value);
    assert_owner_commit(disclose_flags, name, birth_date, sex, telno, owner_commit);
}
