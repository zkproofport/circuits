// The edge-case matrix for the OPRF nullifier (.claude/agents/circuits-dev.md,
// "OPRF nullifier in every wallet credential circuit"). Every expected value
// comes from TACEO's crates (test_vectors.nr, scripts/oprf-nullifier), never
// from this circuit. A refusal names the assert it must hit, so a refusal for
// another reason fails the test.

use crate::{
    address_field, DS_KEY, DS_OUT, DS_QUERY, key_hash, oprf_query, OprfAnswer,
    verify_oprf_nullifier,
};
use crate::test_vectors::{
    ADDRESS, BETA, BJJ_SCALAR_ORDER, BLINDED_X, BLINDED_Y, DLOG_E, DLOG_S, DOMAIN, KEY_HASH,
    NULLIFIER, OTHER_DLOG_E, OTHER_DLOG_S, OTHER_KEY_HASH, OTHER_NULLIFIER, OTHER_PK_X, OTHER_PK_Y,
    OTHER_RESP_X, OTHER_RESP_Y, OTHER_WALLET_ADDRESS, OTHER_WALLET_DLOG_E, OTHER_WALLET_DLOG_S,
    OTHER_WALLET_NULLIFIER, OTHER_WALLET_RESP_X, OTHER_WALLET_RESP_Y, PK_X, PK_Y, QUERY, RESP_X,
    RESP_Y, SCOPE, SWAPPED_DLOG_E, SWAPPED_DLOG_S, SWAPPED_NULLIFIER, SWAPPED_RESP_X,
    SWAPPED_RESP_Y,
};
use babyjubjub::{BabyJubJubPointInSubgroup, hash_to_curve::encode};

fn bytes20(a: Field) -> [u8; 20] {
    a.to_be_bytes::<20>()
}

struct Case {
    address: Field,
    domain: Field,
    scope: Field,
    key_hash: Field,
    nullifier: Field,
    pk_x: Field,
    pk_y: Field,
    beta: Field,
    e: Field,
    s: Field,
    rx: Field,
    ry: Field,
}

fn honest() -> Case {
    Case {
        address: ADDRESS,
        domain: DOMAIN,
        scope: SCOPE,
        key_hash: KEY_HASH,
        nullifier: NULLIFIER,
        pk_x: PK_X,
        pk_y: PK_Y,
        beta: BETA,
        e: DLOG_E,
        s: DLOG_S,
        rx: RESP_X,
        ry: RESP_Y,
    }
}

fn run(c: Case) {
    verify_oprf_nullifier(
        bytes20(c.address),
        c.domain,
        c.scope,
        c.key_hash,
        c.nullifier,
        OprfAnswer {
            public_key_x: c.pk_x,
            public_key_y: c.pk_y,
            beta: c.beta,
            dlog_e: c.e,
            dlog_s: c.s,
            response_x: c.rx,
            response_y: c.ry,
        },
    );
}

// ---------------------------------------------------------------------------
// The construction itself, against TACEO's crates
// ---------------------------------------------------------------------------

#[test]
fn accepts_the_honest_evaluation() {
    run(honest());
}

#[test]
fn query_equals_taceo_crates() {
    assert(oprf_query(ADDRESS, DOMAIN, SCOPE) == QUERY);
}

#[test]
fn blinded_query_equals_taceo_crates() {
    // A = beta * encode_to_curve(query), what the client sends the nodes.
    let a = encode(QUERY).scalar_mul(babyjubjub::BabyJubJubScalarFieldElement::new(BETA));
    assert((a.x() == BLINDED_X) & (a.y() == BLINDED_Y));
}

#[test]
fn key_hash_equals_taceo_crates() {
    assert(key_hash(BabyJubJubPointInSubgroup::new(PK_X, PK_Y)) == KEY_HASH);
}

#[test]
fn domain_separators_are_their_ascii_strings() {
    let s = |b: [u8; 32], n: u32| -> Field {
        let mut acc: Field = 0;
        for i in 0..32 {
            if i < n {
                acc = acc * 256 + b[i] as Field;
            }
        }
        acc
    };
    let mut q = [0; 32];
    let qs = "TACEO_OPRF_zkProofport_query".as_bytes();
    for i in 0..28 {
        q[i] = qs[i];
    }
    assert(s(q, 28) == DS_QUERY);
    let mut o = [0; 32];
    let os = "TACEO_OPRF_zkProofport_out".as_bytes();
    for i in 0..26 {
        o[i] = os[i];
    }
    assert(s(o, 26) == DS_OUT);
    let mut k = [0; 32];
    let ks = "TACEO_OPRF_bjj_key".as_bytes();
    for i in 0..18 {
        k[i] = ks[i];
    }
    assert(s(k, 18) == DS_KEY);
}

#[test]
fn address_is_big_endian() {
    let mut a = [0; 20];
    a[19] = 1;
    assert(address_field(a) == 1);
    a[0] = 0xf3;
    assert(address_field(a) == 0xf300000000000000000000000000000000000001);
    // All 0xff: the largest address, 2^160 - 1, no reduction.
    assert(address_field([0xff; 20]) == 0xffffffffffffffffffffffffffffffffffffffff);
    assert(address_field(bytes20(ADDRESS)) == ADDRESS);
}

// ---------------------------------------------------------------------------
// Public outputs: nullifier and key hash
// ---------------------------------------------------------------------------

#[test(should_fail_with = "Nullifier mismatch")]
fn refuses_nullifier_plus_one() {
    let mut c = honest();
    c.nullifier = NULLIFIER + 1;
    run(c);
}

#[test(should_fail_with = "Nullifier mismatch")]
fn refuses_nullifier_minus_one() {
    let mut c = honest();
    c.nullifier = NULLIFIER - 1;
    run(c);
}

#[test(should_fail_with = "Nullifier mismatch")]
fn refuses_zero_nullifier() {
    let mut c = honest();
    c.nullifier = 0;
    run(c);
}

#[test(should_fail_with = "OPRF key hash mismatch")]
fn refuses_key_hash_plus_one() {
    let mut c = honest();
    c.key_hash = KEY_HASH + 1;
    run(c);
}

#[test(should_fail_with = "OPRF key hash mismatch")]
fn refuses_another_keys_hash_for_this_key() {
    let mut c = honest();
    c.key_hash = OTHER_KEY_HASH;
    run(c);
}

// ---------------------------------------------------------------------------
// Wrong OPRF public key D
// ---------------------------------------------------------------------------

#[test(should_fail_with = "OPRF key hash mismatch")]
fn refuses_another_key_under_this_keys_hash() {
    let mut c = honest();
    c.pk_x = OTHER_PK_X;
    c.pk_y = OTHER_PK_Y;
    run(c);
}

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_this_answer_claimed_under_another_key() {
    // Hash and point agree with each other; the proof is for the real key.
    let mut c = honest();
    c.pk_x = OTHER_PK_X;
    c.pk_y = OTHER_PK_Y;
    c.key_hash = OTHER_KEY_HASH;
    run(c);
}

#[test]
fn another_keys_honest_answer_gives_another_nullifier() {
    // Why a verifier pins the key hash: any key holder can produce a valid
    // proof, with a nullifier unrelated to the registered key's.
    let mut c = honest();
    c.key_hash = OTHER_KEY_HASH;
    c.nullifier = OTHER_NULLIFIER;
    c.pk_x = OTHER_PK_X;
    c.pk_y = OTHER_PK_Y;
    c.e = OTHER_DLOG_E;
    c.s = OTHER_DLOG_S;
    c.rx = OTHER_RESP_X;
    c.ry = OTHER_RESP_Y;
    run(c);
    assert(OTHER_NULLIFIER != NULLIFIER);
}

#[test(should_fail_with = "Nullifier mismatch")]
fn another_keys_answer_cannot_claim_this_keys_nullifier() {
    let mut c = honest();
    c.key_hash = OTHER_KEY_HASH;
    c.pk_x = OTHER_PK_X;
    c.pk_y = OTHER_PK_Y;
    c.e = OTHER_DLOG_E;
    c.s = OTHER_DLOG_S;
    c.rx = OTHER_RESP_X;
    c.ry = OTHER_RESP_Y;
    run(c);
}

#[test(should_fail_with = "Point is not on the BabyJubJub curve")]
fn refuses_a_public_key_off_the_curve() {
    // The hash is of the off-curve point, so only the curve check can refuse.
    let mut c = honest();
    c.pk_x = PK_X + 1;
    c.key_hash = key_hash(BabyJubJubPointInSubgroup::new_unchecked(PK_X + 1, PK_Y));
    run(c);
}

#[test(should_fail_with = "Point is not in the correct subgroup")]
fn refuses_a_public_key_outside_the_subgroup() {
    // (-x, -y) = D + the 2-torsion point (0, -1): on the curve, order 2r.
    let mut c = honest();
    c.pk_x = -PK_X;
    c.pk_y = -PK_Y;
    c.key_hash = key_hash(BabyJubJubPointInSubgroup::new_unchecked(-PK_X, -PK_Y));
    run(c);
}

#[test(should_fail_with = "Point a must not be identity")]
fn refuses_the_identity_as_public_key() {
    let mut c = honest();
    c.pk_x = 0;
    c.pk_y = 1;
    c.key_hash = key_hash(BabyJubJubPointInSubgroup::new_unchecked(0, 1));
    run(c);
}

#[test(should_fail_with = "Point is not on the BabyJubJub curve")]
fn refuses_zero_zero_as_public_key() {
    let mut c = honest();
    c.pk_x = 0;
    c.pk_y = 0;
    c.key_hash = key_hash(BabyJubJubPointInSubgroup::new_unchecked(0, 0));
    run(c);
}

// ---------------------------------------------------------------------------
// Wrong blinding factor beta
// ---------------------------------------------------------------------------

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_beta_plus_one() {
    let mut c = honest();
    c.beta = BETA + 1;
    run(c);
}

#[test(should_fail_with = "Beta cannot be zero")]
fn refuses_zero_beta() {
    let mut c = honest();
    c.beta = 0;
    run(c);
}

#[test(should_fail)]
fn refuses_beta_equal_to_the_group_order() {
    // r is 0 as a scalar; the scalar range check refuses it.
    let mut c = honest();
    c.beta = BJJ_SCALAR_ORDER;
    run(c);
}

#[test(should_fail)]
fn refuses_beta_plus_the_group_order() {
    // The same scalar as BETA, encoded differently: refused, not reduced.
    let mut c = honest();
    c.beta = BETA + BJJ_SCALAR_ORDER;
    run(c);
}

// ---------------------------------------------------------------------------
// The nodes' answer: B != k * A, tampered Chaum-Pedersen proof
// ---------------------------------------------------------------------------

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_another_keys_answer_with_this_keys_proof() {
    // B = k' * A with the proof made for k: log_A(B) != log_G(D).
    let mut c = honest();
    c.rx = OTHER_RESP_X;
    c.ry = OTHER_RESP_Y;
    run(c);
}

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_e_plus_one() {
    let mut c = honest();
    c.e = DLOG_E + 1;
    run(c);
}

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_s_plus_one() {
    let mut c = honest();
    c.s = DLOG_S + 1;
    run(c);
}

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_e_and_s_swapped() {
    let mut c = honest();
    c.e = DLOG_S;
    c.s = DLOG_E;
    run(c);
}

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_another_requests_proof() {
    // A valid proof, for another wallet's query under the same key.
    let mut c = honest();
    c.e = OTHER_WALLET_DLOG_E;
    c.s = OTHER_WALLET_DLOG_S;
    run(c);
}

#[test(should_fail)]
fn refuses_s_plus_the_group_order() {
    // s + r is the same scalar as s; accepting it would make proofs malleable.
    let mut c = honest();
    c.s = DLOG_S + BJJ_SCALAR_ORDER;
    run(c);
}

#[test(should_fail_with = "Computed points cannot be identity")]
fn refuses_zero_proof() {
    // e = s = 0 makes r1 = 0*G - 0*D the identity, refused before the hash.
    let mut c = honest();
    c.e = 0;
    c.s = 0;
    run(c);
}

// ---------------------------------------------------------------------------
// The unblinded answer P
// ---------------------------------------------------------------------------

#[test(should_fail_with = "Point is not on the BabyJubJub curve")]
fn refuses_a_response_off_the_curve() {
    let mut c = honest();
    c.rx = RESP_X + 1;
    run(c);
}

#[test(should_fail_with = "OPRF response must be in prime order subgroup")]
fn refuses_a_response_outside_the_subgroup() {
    // (-x, -y) = P + the 2-torsion point: beta * it differs from B by a
    // torsion component unless the subgroup check refuses it.
    let mut c = honest();
    c.rx = -RESP_X;
    c.ry = -RESP_Y;
    run(c);
}

#[test(should_fail_with = "Point c must not be identity")]
fn refuses_the_identity_as_response() {
    let mut c = honest();
    c.rx = 0;
    c.ry = 1;
    run(c);
}

#[test(should_fail_with = "Point is not on the BabyJubJub curve")]
fn refuses_zero_zero_as_response() {
    let mut c = honest();
    c.rx = 0;
    c.ry = 0;
    run(c);
}

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_the_negated_response() {
    // -P = (-x, y) is in the subgroup and on the curve, but beta * -P = -B.
    let mut c = honest();
    c.rx = -RESP_X;
    run(c);
}

// ---------------------------------------------------------------------------
// The query inputs: address, domain, scope
// ---------------------------------------------------------------------------

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_another_address() {
    // The credential proved another wallet than the one the nodes answered for.
    let mut c = honest();
    c.address = ADDRESS + 1;
    run(c);
}

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_another_wallets_answer_for_this_wallet() {
    let mut c = honest();
    c.e = OTHER_WALLET_DLOG_E;
    c.s = OTHER_WALLET_DLOG_S;
    c.rx = OTHER_WALLET_RESP_X;
    c.ry = OTHER_WALLET_RESP_Y;
    c.nullifier = OTHER_WALLET_NULLIFIER;
    run(c);
}

#[test]
fn another_wallet_gets_another_nullifier() {
    let mut c = honest();
    c.address = OTHER_WALLET_ADDRESS;
    c.nullifier = OTHER_WALLET_NULLIFIER;
    c.e = OTHER_WALLET_DLOG_E;
    c.s = OTHER_WALLET_DLOG_S;
    c.rx = OTHER_WALLET_RESP_X;
    c.ry = OTHER_WALLET_RESP_Y;
    run(c);
    assert(OTHER_WALLET_NULLIFIER != NULLIFIER);
}

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_domain_and_scope_swapped() {
    let mut c = honest();
    c.domain = SCOPE;
    c.scope = DOMAIN;
    run(c);
}

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_the_swapped_querys_answer_under_the_right_order() {
    let mut c = honest();
    c.nullifier = SWAPPED_NULLIFIER;
    c.e = SWAPPED_DLOG_E;
    c.s = SWAPPED_DLOG_S;
    c.rx = SWAPPED_RESP_X;
    c.ry = SWAPPED_RESP_Y;
    run(c);
}

#[test]
fn swapping_domain_and_scope_is_another_nullifier() {
    // Honest under the swapped order -- and a different value, so a verifier
    // that compared domain and scope as a set would be fooled.
    let mut c = honest();
    c.domain = SCOPE;
    c.scope = DOMAIN;
    c.nullifier = SWAPPED_NULLIFIER;
    c.e = SWAPPED_DLOG_E;
    c.s = SWAPPED_DLOG_S;
    c.rx = SWAPPED_RESP_X;
    c.ry = SWAPPED_RESP_Y;
    run(c);
    assert(SWAPPED_NULLIFIER != NULLIFIER);
}

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_another_scope() {
    let mut c = honest();
    c.scope = SCOPE + 1;
    run(c);
}

#[test(should_fail_with = "Challenge verification failed")]
fn refuses_another_domain() {
    let mut c = honest();
    c.domain = DOMAIN + 1;
    run(c);
}
