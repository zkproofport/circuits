// PROTOTYPE -- the nullifier part of a KYC proof, with an OPRF secret.
//
// The wallet-derived nullifiers in this repository are hashes of the address
// and values the verifier already has, so a verifier recovers the wallet by
// trying every public KYC address (scratch probe, 2026-10-22: 313,955
// addresses, about 3.5 s). Here the secret is OPRF(k, address): the service's
// key k is needed to compute it, the service never sees the address, and the
// circuit checks the service's Chaum-Pedersen proof against its public key.
//
// A real circuit adds this to the wallet-signature and membership checks; this
// one exists to prove the Rust service (taceo-oprf-core) and the Noir gadgets
// (deps/oprf-nr) agree on every value.

use babyjubjub::BabyJubJubPoint;
use oprf::oprf_output::verified_oprf;
use dep::poseidon::poseidon::bn254::hash_2;

/// b"DLOG Equality Proof" -- taceo-oprf-core's DLOG_DS.
global DS_DLOG: Field = 1523098184080632582082867317389990410064981862;
/// b"ZKProofport OPRF" as a field: the finalization domain, ours to choose.
global DS_OUT: Field = 0x5a4b50726f6f66706f7274204f505246;

fn main(
    oprf_public_key: pub BabyJubJubPoint,
    scope: pub Field,
    nullifier: pub Field,
    address: Field,
    beta: Field,
    dlog_e: Field,
    dlog_s: Field,
    response_blinded: BabyJubJubPoint,
    response: BabyJubJubPoint,
) {
    let secret = verified_oprf(
        beta,
        oprf_public_key,
        dlog_e,
        dlog_s,
        response_blinded,
        response,
        address,
        DS_DLOG,
        DS_OUT,
    );
    assert(hash_2([secret, scope]) == nullifier, "Nullifier mismatch");
}
