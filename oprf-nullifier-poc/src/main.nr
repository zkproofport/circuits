// PROTOTYPE -- the nullifier part of a KYC proof, keyed by an OPRF.
//
// The wallet-derived nullifiers in this repository are hashes of the address
// and values the verifier already has, so a verifier recovers the wallet by
// trying every public KYC address (scratch probe, 2026-10-22: 313,955
// addresses, about 3.5 s). Here the nullifier needs the OPRF key: the nodes
// never see the address, and the circuit checks their Chaum-Pedersen proof.
//
// The construction is the one TACEO specified for this integration
// (oprf-nullifier-libs):
//   query     = Poseidon2(DS_QUERY, address, domain, scope)
//   nullifier = Poseidon2(DS_OUT, query, P.x, P.y),  P = k * encode(query)
//   key hash  = Poseidon2(DS_KEY, D.x, D.y)
// Public inputs, in order: oprf_key_hash, domain, scope, nullifier.
//
// The public key D is private and bound by its hash. A verifier pins the hash
// of the key the network registers (OprfKeyRegistry.getOprfPublicKey; TACEO
// never rotates a key, resharing changes only shares), which is in the
// prime-order subgroup, so the point is not re-checked here.
//
// A real circuit adds this to the wallet-signature and membership checks; this
// one exists to prove the Rust service (taceo-oprf-core), TACEO's network and
// the Noir gadgets (TaceoLabs/oprf-nr v2.0.0 in deps/oprf-nr) agree on every
// value. v2.0.0 recomputes the blinded answer as response * beta, so the
// nodes' blinded answer is not an input.

use babyjubjub::{BabyJubJubPoint, BabyJubJubPointInSubgroup};
use oprf::oprf_output::verified_oprf;
use oprf_nullifier_libs::{DS_DLOG, DS_OUT, key_hash, oprf_query};

fn main(
    oprf_key_hash: pub Field,
    domain: pub Field,
    scope: pub Field,
    nullifier: pub Field,
    oprf_public_key_x: Field,
    oprf_public_key_y: Field,
    address: Field,
    beta: Field,
    dlog_e: Field,
    dlog_s: Field,
    response_x: Field,
    response_y: Field,
) {
    let public_key = BabyJubJubPointInSubgroup::new_unchecked(oprf_public_key_x, oprf_public_key_y);
    assert(key_hash(public_key) == oprf_key_hash, "OPRF key hash mismatch");
    // An Ethereum address is 160 bits; the request circuit derives it from a key.
    address.assert_max_bit_size::<160>();
    // Checks the unblinded response is on the curve.
    let response = BabyJubJubPoint::new(response_x, response_y);
    let derived = verified_oprf(
        beta,
        public_key,
        dlog_e,
        dlog_s,
        response,
        oprf_query(address, domain, scope),
        DS_DLOG,
        DS_OUT,
    );
    assert(derived == nullifier, "Nullifier mismatch");
}

mod tests {
    use super::main;
    use babyjubjub::{BabyJubJubPoint, BabyJubJubPointInSubgroup};
    use oprf::oprf_output::verified_oprf;
    use oprf_nullifier_libs::{DS_DLOG, key_hash};

    // proofport-oprf/scripts/make-fixtures.sh: anvil account 0, TACEO's
    // oprf-testnet test key 0x1234...abcd and beta, domain =
    // keccak256("zkproofport.app") mod p, scope = keccak256("oprf-fixture") mod p.
    // Every value below came out of the Rust side (taceo-oprf-core service and
    // finalize, taceo-poseidon2 for the query and key hash), not this circuit.
    global ADDRESS: Field = 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266;
    global DOMAIN: Field = 0x18710bf90bfc93f0c5e493223ae90dd38acb94ecce696da5005658255fed19cc;
    global SCOPE: Field = 0x0db311189e81402907f17f48d1fac1f27ec7bc88df607c71d9ad1611b842ead2;
    global BETA: Field = 0x035044ac4038fff4d560471e5cd5049343d293faa73d618140bb8630f2e37d23;
    global PK_X: Field = 0x0f4583e516f077314fb7c7b8a87fae07166068e3dddb4200fff32bf399b2349d;
    global PK_Y: Field = 0x1a289edfe55dabcc66eb07a2e53d7683afe0d6dcb27ac72dfbdd76bba9b949a8;
    global KEY_HASH: Field = 0x013f6250e42223259e528bc5a1bafb66543e5606ad1edefa3596327238427def;
    global DLOG_E: Field = 0x09d011de875a86eeb2bb4b0513abaa2ad7e642d3e6d5695c015d23f818d17609;
    global DLOG_S: Field = 0x00bfd968ecb7f70f8e4b0fb92004ba12030f2f22f56ddf2a5b71ced2bbe41425;
    global RESP_X: Field = 0x088c2bba15d183691bdb30934e72fb137d2dd2cbbb15efa63c2ceee1efe61049;
    global RESP_Y: Field = 0x00f6f0f58fc3120ed7042853c997c7238c3c6b881854c4951ecb5c50320cd04d;
    global NULLIFIER: Field = 0x15badbab3c5cf2c114f5801e253d7a9c18c3d3eac3bfb12eab6bb1d00cd63655;

    fn run(key: Field, domain: Field, scope: Field, nullifier: Field, address: Field, beta: Field, s: Field, rx: Field, ry: Field) {
        main(key, domain, scope, nullifier, PK_X, PK_Y, address, beta, DLOG_E, s, rx, ry);
    }

    #[test]
    fn accepts_the_nullifier_rust_computed() {
        run(KEY_HASH, DOMAIN, SCOPE, NULLIFIER, ADDRESS, BETA, DLOG_S, RESP_X, RESP_Y);
    }

    #[test]
    fn key_hash_equals_rust() {
        assert(key_hash(BabyJubJubPointInSubgroup::new(PK_X, PK_Y)) == KEY_HASH);
    }

    #[test]
    fn taceo_test_vector_gives_taceos_output_under_their_domain() {
        // TACEO oprf-testnet verified_oprf_proof's vector (query = bare address,
        // DS b"OPRF TestNet"): the vendored gadget reproduces their output.
        let out = verified_oprf(
            1498760273557913456370459222027449040163634869948415528344868600761947487523,
            BabyJubJubPointInSubgroup::new(PK_X, PK_Y),
            0x040e6bf380b2cf23744c604ecea4ce8b060bdcfac33e4aabfe67cfcb53066f82,
            0xb89a7e66ea91835b3d6841734ee7a766cac8606c5dce26006a68f2629b761a,
            BabyJubJubPoint::new(
                0x19e48cf0f614b50f0656d25f9b742fb8660a8e56fef9ecf64f3a625b69374670,
                0x1211ac4fca68ebc215dfdb62f679637e0c4bb46b07555702d27ed0f446b5d766,
            ),
            ADDRESS,
            DS_DLOG,
            24546418369108709687614662004,
        );
        assert(out == 0x3026ff285fe4388e1b9c62361f23ef502c4fb6e411356cbe753bb7a9d672c572);
    }

    #[test(should_fail_with = "OPRF key hash mismatch")]
    fn refuses_another_key_hash() {
        run(KEY_HASH + 1, DOMAIN, SCOPE, NULLIFIER, ADDRESS, BETA, DLOG_S, RESP_X, RESP_Y);
    }

    #[test(should_fail_with = "Nullifier mismatch")]
    fn refuses_a_wrong_nullifier() {
        run(KEY_HASH, DOMAIN, SCOPE, NULLIFIER + 1, ADDRESS, BETA, DLOG_S, RESP_X, RESP_Y);
    }

    #[test(should_fail_with = "Challenge verification failed")]
    fn refuses_another_scope() {
        // The nodes evaluated encode(query(address, domain, SCOPE)) * beta.
        run(KEY_HASH, DOMAIN, SCOPE + 1, NULLIFIER, ADDRESS, BETA, DLOG_S, RESP_X, RESP_Y);
    }

    #[test(should_fail_with = "Challenge verification failed")]
    fn refuses_another_domain() {
        run(KEY_HASH, DOMAIN + 1, SCOPE, NULLIFIER, ADDRESS, BETA, DLOG_S, RESP_X, RESP_Y);
    }

    #[test(should_fail_with = "Challenge verification failed")]
    fn refuses_another_address() {
        run(KEY_HASH, DOMAIN, SCOPE, NULLIFIER, ADDRESS + 1, BETA, DLOG_S, RESP_X, RESP_Y);
    }

    #[test(should_fail_with = "Challenge verification failed")]
    fn refuses_a_tampered_dlog_proof() {
        run(KEY_HASH, DOMAIN, SCOPE, NULLIFIER, ADDRESS, BETA, DLOG_S + 1, RESP_X, RESP_Y);
    }

    #[test(should_fail_with = "Point is not on the BabyJubJub curve")]
    fn refuses_a_response_off_the_curve() {
        run(KEY_HASH, DOMAIN, SCOPE, NULLIFIER, ADDRESS, BETA, DLOG_S, RESP_X + 1, RESP_Y);
    }

    #[test(should_fail_with = "OPRF response must be in prime order subgroup")]
    fn refuses_a_response_outside_the_subgroup() {
        // (-x, -y) is P plus a 2-torsion point: on the curve, not in the subgroup.
        run(KEY_HASH, DOMAIN, SCOPE, NULLIFIER, ADDRESS, BETA, DLOG_S, -RESP_X, -RESP_Y);
    }

    #[test(should_fail_with = "Beta cannot be zero")]
    fn refuses_zero_beta() {
        run(KEY_HASH, DOMAIN, SCOPE, NULLIFIER, ADDRESS, 0, DLOG_S, RESP_X, RESP_Y);
    }

    #[test(should_fail)]
    fn refuses_an_address_over_160_bits() {
        run(KEY_HASH, DOMAIN, SCOPE, NULLIFIER, ADDRESS + 0x10000000000000000000000000000000000000000, BETA, DLOG_S, RESP_X, RESP_Y);
    }
}
