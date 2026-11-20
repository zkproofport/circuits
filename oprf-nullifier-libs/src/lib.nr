// The OPRF nullifier every wallet credential circuit publishes.
//
// WHY. A nullifier derived from the wallet address and values the verifier
// already holds (the keccak schemes these circuits used before) gives the
// wallet away: the KYC'd addresses are public on EAS, so a verifier hashes each
// one until the nullifier matches (2026-10-22: 313,955 addresses, about
// 3.5 s). Here the nullifier needs an OPRF key k that only the OPRF nodes hold,
// the nodes see the query only multiplied by a random blinding factor, and the
// circuit checks their Chaum-Pedersen proof, so nobody -- neither the nodes nor
// the verifier -- can compute it from an address.
//
// THE CONSTRUCTION (TACEO, SoW and their answers, 2026-11-17):
//
//   query     = Poseidon2(DS_QUERY, address, domain, scope)
//   A         = beta * encode_to_curve(query)           (the blinded query)
//   B         = k * A                                     (the nodes' answer)
//   P         = B / beta                                  (unblinded by the client)
//   nullifier = Poseidon2(DS_OUT, query, P.x, P.y)
//   key hash  = Poseidon2(DS_KEY, D.x, D.y),  D = k * G  (the OPRF public key)
//
// `verify_oprf_nullifier` recomputes A from beta and the query, recomputes
// B = beta * P (so the client's unblinding is checked), verifies the
// Chaum-Pedersen proof that log_G(D) = log_A(B) (DS_DLOG), and derives the
// nullifier -- oprf-nr's `verified_oprf` (TaceoLabs/oprf-nr v2.0.0) -- then
// requires the published nullifier and key hash to be those values.
//
// Poseidon2(a, b, ...) is the BN254 Poseidon2 permutation of width = number of
// inputs, output state[1] -- oprf-nr's convention. Every DS is its ASCII
// string read as a big-endian integer (each is under 31 bytes, so below p).
// `address` is the wallet's 20 bytes read big-endian. `domain` and `scope` are
// field elements; a string maps to keccak256(string) mod p before it gets
// here (the circuit cannot see the string).
//
// WHAT A VERIFIER MUST DO. Pin `oprf_key_hash` to the key registered for the
// circuit it accepts (one key per proof type: the same wallet, domain and
// scope then give unrelated nullifiers in two circuits). A proof with any other
// key hash says nothing: whoever holds a key can compute every address's
// nullifier under it. Compare `domain` and `scope` with keccak256(string) mod p
// of the strings it asked for.
//
// Mirrored off-circuit by ../scripts/oprf-nullifier (fixtures, TACEO's
// crates) and ../../proofport-oprf (the service); the tests in tests.nr pin
// this file to values those crates computed.

use babyjubjub::{BabyJubJubPoint, BabyJubJubPointInSubgroup};
use oprf::oprf_output::verified_oprf;
use poseidon2::bn254::permutation;

mod test_vectors;
mod tests;

/// b"TACEO_OPRF_zkProofport_query"
pub global DS_QUERY: Field = 8873080049130461605566892302184544221631163997938119966801040601721;
/// b"TACEO_OPRF_zkProofport_out"
pub global DS_OUT: Field = 135392456804358850182600285372688968225573181120881957501105524;
/// b"TACEO_OPRF_bjj_key"
pub global DS_KEY: Field = 7339639790271784127253828559220533810128249;
/// b"DLOG Equality Proof" -- taceo-oprf-core's DLOG_DS.
pub global DS_DLOG: Field = 1523098184080632582082867317389990410064981862;

/// The private inputs a prover gets from the OPRF nodes' answer and its own
/// blinding. None of them is public.
pub struct OprfAnswer {
    /// The OPRF public key D = k * G. Bound by its hash, which is public.
    pub public_key_x: Field,
    pub public_key_y: Field,
    /// The client's blinding factor, a BabyJubJub scalar, not zero.
    pub beta: Field,
    /// The nodes' Chaum-Pedersen proof (e in the base field, s a scalar).
    pub dlog_e: Field,
    pub dlog_s: Field,
    /// The unblinded answer P = B / beta.
    pub response_x: Field,
    pub response_y: Field,
}

/// A wallet address as the query takes it: the 20 bytes big-endian.
pub fn address_field(address: [u8; 20]) -> Field {
    let mut acc: Field = 0;
    for i in 0..20 {
        acc = acc * 256 + address[i] as Field;
    }
    acc
}

pub fn oprf_query(address: Field, domain: Field, scope: Field) -> Field {
    permutation::t4([DS_QUERY, address, domain, scope])[1]
}

pub fn key_hash(public_key: BabyJubJubPointInSubgroup) -> Field {
    permutation::t3([DS_KEY, public_key.x(), public_key.y()])[1]
}

/// The nullifier for `address` (the wallet the credential checks proved) in
/// (`domain`, `scope`), under the key whose hash is `oprf_key_hash`.
pub fn verify_oprf_nullifier(
    address: [u8; 20],
    domain: Field,
    scope: Field,
    oprf_key_hash: Field,
    nullifier: Field,
    answer: OprfAnswer,
) {
    // On the curve and in the prime-order subgroup. A pinned key hash already
    // fixes the point, so this matters only to a verifier that pins nothing --
    // and then the proof means nothing anyway; it is here so the point the
    // Chaum-Pedersen check uses is never outside the group it reasons about.
    let public_key = BabyJubJubPointInSubgroup::new(answer.public_key_x, answer.public_key_y);
    assert(key_hash(public_key) == oprf_key_hash, "OPRF key hash mismatch");

    // On the curve here; verified_oprf adds the subgroup check.
    let response = BabyJubJubPoint::new(answer.response_x, answer.response_y);
    let derived = verified_oprf(
        answer.beta,
        public_key,
        answer.dlog_e,
        answer.dlog_s,
        response,
        oprf_query(address_field(address), domain, scope),
        DS_DLOG,
        DS_OUT,
    );
    assert(derived == nullifier, "Nullifier mismatch");
}
