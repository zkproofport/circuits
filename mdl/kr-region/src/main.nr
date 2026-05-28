// ZKProofport: Korea Mobile ID - Region predicate
//
// Predicate: the first whitespace-separated token of the prover's
// `address` hashes to the public `region_code`. The address bytes come
// straight from the OmniOne CX response and are bound into the natural-
// person commitment, so a prover cannot substitute a different region.
//
// No selective disclosure, no age check. Always anonymous; the proof
// reveals only that the holder resides in the requested si/do (and that
// they pass CX integrity + nullifier checks).
//
// Same canonical (ci || jti || pri || birth || address) commitment as
// the ownership and age circuits, so the same user yields the same
// nullifier across all three for a given scope/signal_hash.

use dep::keccak256::keccak256;
use dep::coinbase_libs::nullifier;
use dep::mdl_kr_common::{
    verify_cx_integrity,
    derive_self_id_20,
    extract_region_token,
};

fn main(
    // ============ Public Inputs ============
    signal_hash:       pub [u8; 32],
    scope:             pub [u8; 32],
    nullifier_value:   pub [u8; 32],
    cx_integrity_root: pub [u8; 32],
    region_code:       pub [u8; 32],
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

    let extracted = extract_region_token(address);
    let extracted_hash = keccak256(extracted, 64);
    assert(extracted_hash == region_code, "Region mismatch");
}
