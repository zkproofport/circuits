// ZKProofport: Korea Mobile ID - Age predicate
//
// Predicate: current_year - birth_year >= age_threshold.
//
// No selective disclosure, no region check. Always anonymous; the proof
// reveals only that the holder is at least `age_threshold` years old in
// `current_year` (and that they pass CX integrity + nullifier checks).
//
// Same canonical (ci || jti || pri || birth || address) commitment as
// the ownership and region circuits, so the same user yields the same
// nullifier across all three for a given scope/signal_hash.

use dep::coinbase_libs::nullifier;
use dep::mdl_kr_common::{
    verify_cx_integrity,
    derive_self_id_20,
    assert_age,
};

fn main(
    // ============ Public Inputs ============
    signal_hash:       pub [u8; 32],
    scope:             pub [u8; 32],
    nullifier_value:   pub [u8; 32],
    cx_integrity_root: pub [u8; 32],
    age_threshold:     pub u32,
    current_year:      pub u32,
    // ============ Private Inputs ============
    ci:                [u8; 88],
    cx_jti:            [u8; 40],
    cx_pri:            [u8; 44],
    birth_date:        [u8; 8],
    address:           [u8; 256],
) {
    verify_cx_integrity(cx_jti, cx_pri, cx_integrity_root);
    let self_id_20 = derive_self_id_20(ci, cx_jti, cx_pri, birth_date, address);
    nullifier::verify_nullifier(self_id_20, signal_hash, scope, nullifier_value);
    assert_age(birth_date, current_year, age_threshold);
}
