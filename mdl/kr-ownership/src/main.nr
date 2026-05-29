// ZKProofport: Korea Mobile ID - Ownership predicate (privacy-preserving) v4.
//
// v4 change: nullifier formula changed to keccak(keccak(ci) || scope),
// matching the OIDC-domain-attestation pattern. signal_hash removed.
// cx_integrity_root, cx_jti, cx_pri commented out pending HS256 registration.
//
// The prover holds a valid OmniOne CX response. The user (or dApp) decides
// which attributes to disclose via disclose_flags (NAME / BIRTH / SEX /
// TELNO bits) and PRE-COMPUTES owner_commit OFF-CIRCUIT as
//   keccak(flag || masked(name) || masked(telno) || masked(birth) || masked(sex))
// over the expected attribute values. owner_commit is the only public
// commitment that travels with the proof; the expected plaintext values
// are NEVER inputs to the circuit, so the proof and witness contain no
// user PII.
//
// The circuit reproduces the same hash from the mDL values it received
// (private) and asserts equality with the public owner_commit. A wrong
// expected tuple yields a wrong owner_commit and verification fails.
//
// Anonymous mode (disclose_flags == 0) forces owner_commit = zero.

use dep::mdl_kr_common::{
    verify_nullifier,
    assert_owner_commit,
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
    disclose_flags:    pub u8,
    owner_commit:      pub [u8; 32],
    // ============ Private Inputs ============
    ci:                [u8; 88],
    // TODO(HS256): Re-enable when RAON registration provides the RP shared
    // secret. Currently disabled because no off-chain HS256 verifier exists,
    // so cx_integrity_root cannot anchor anything meaningfully.
    // cx_jti:            [u8; 40],
    // cx_pri:            [u8; 44],
    // address:           [u8; 256],  // ownership doesn't need address for nullifier
    name:              [u8; 64],
    birth_date:        [u8; 8],
    telno:             [u8; 16],
    sex:               u8,
) {
    // TODO(HS256): Re-enable when RAON registration provides the RP shared
    // secret. Currently disabled because no off-chain HS256 verifier exists,
    // so cx_integrity_root cannot anchor anything meaningfully.
    // verify_cx_integrity(cx_jti, cx_pri, cx_integrity_root);
    // let self_id_20 = derive_self_id_20(ci, cx_jti, cx_pri, birth_date, address);
    // nullifier::verify_nullifier(self_id_20, signal_hash, scope, nullifier_value);

    verify_nullifier(ci, scope, nullifier_value);
    assert_owner_commit(disclose_flags, name, birth_date, sex, telno, owner_commit);
}
