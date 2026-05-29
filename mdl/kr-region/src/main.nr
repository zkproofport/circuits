// ZKProofport: Korea Mobile ID - Region predicate v4.
//
// v4 change: nullifier formula changed to keccak(keccak(ci) || scope),
// matching the OIDC-domain-attestation pattern. signal_hash removed.
// cx_integrity_root, cx_jti, cx_pri commented out pending HS256 registration.
//
// Predicate: the first whitespace-separated token of the prover's
// `address` hashes to the public `region_code`. The address bytes come
// straight from the OmniOne CX response.
//
// No selective disclosure, no age check. Always anonymous; the proof
// reveals only that the holder resides in the requested si/do (and that
// they pass the nullifier check).

use dep::keccak256::keccak256;
use dep::mdl_kr_common::{
    verify_nullifier,
    extract_region_token,
};

fn main(
    // ============ Public Inputs ============
    // TODO(HS256): Re-enable when RAON registration provides the RP shared
    // secret. Currently disabled because no off-chain HS256 verifier exists,
    // so cx_integrity_root cannot anchor anything meaningfully.
    // signal_hash:       pub [u8; 32],
    scope:             pub [u8; 32],
    nullifier_value:   pub [u8; 32],
    // TODO(HS256): Re-enable when RAON registration provides the RP shared
    // secret. Currently disabled because no off-chain HS256 verifier exists,
    // so cx_integrity_root cannot anchor anything meaningfully.
    // cx_integrity_root: pub [u8; 32],
    region_code:       pub [u8; 32],
    // ============ Private Inputs ============
    ci:                [u8; 88],
    // TODO(HS256): Re-enable when RAON registration provides the RP shared
    // secret. Currently disabled because no off-chain HS256 verifier exists,
    // so cx_integrity_root cannot anchor anything meaningfully.
    // cx_jti:            [u8; 40],
    // cx_pri:            [u8; 44],
    // birth_date:        [u8; 8],  // not needed for nullifier in v4
    address:           [u8; 256],
) {
    // TODO(HS256): Re-enable when RAON registration provides the RP shared
    // secret. Currently disabled because no off-chain HS256 verifier exists,
    // so cx_integrity_root cannot anchor anything meaningfully.
    // verify_cx_integrity(cx_jti, cx_pri, cx_integrity_root);
    // let self_id_20 = derive_self_id_20(ci, cx_jti, cx_pri, birth_date, address);
    // nullifier::verify_nullifier(self_id_20, signal_hash, scope, nullifier_value);

    verify_nullifier(ci, scope, nullifier_value);

    let extracted = extract_region_token(address);
    let extracted_hash = keccak256(extracted, 64);
    assert(extracted_hash == region_code, "Region mismatch");
}
