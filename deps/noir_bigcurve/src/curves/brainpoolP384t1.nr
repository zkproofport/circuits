use bignum::BigNum;
pub use bignum::{BrainpoolP384t1_Fq, BrainpoolP384t1_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global BRAINPOOLP384t1_PARAM: BigCurveParams<BrainpoolP384t1_Fq> = BigCurveParams {
    a: BrainpoolP384t1_Fq::from_limbs([
        0xd3a729901d1a71874700133107ec50,
        0x7109ed5456b412b1da197fb71123ac,
        0x82a3386d280f5d6f7e50e641df152f,
        0x8cb91e,
    ]),
    b: BrainpoolP384t1_Fq::from_limbs([
        0x74aa263b88805ced70355a33b471ee,
        0x46ed8ccdc64e4b1abd11756dce1d20,
        0xada7bda81bd826dba647910f8c4b93,
        0x7f519e,
    ]),
    one: [
        BrainpoolP384t1_Fq::from_limbs([
            0xff191b946a5f54d8d0aa2f418808cc,
            0xab12ebd653172476fecd462aabffc4,
            0xb02db9a306f2afcd7235f72a819b80,
            0x18de98,
        ]),
        BrainpoolP384t1_Fq::from_limbs([
            0x9408584dc2b2912675bf5b9e582928,
            0x93475b7a1fca3b88f2b6a208ccfe46,
            0x6962d30651a114afd2755ad336747f,
            0x25ab05,
        ]),
    ],
    offset_generator: [
        BrainpoolP384t1_Fq::from_limbs([
            0x5c2d5939d5c1a1734cf2b30ea612f4,
            0x8147cdbb075b2ff11562030e71b529,
            0x783ed34c1d8318308adefcd5f6dbee,
            0x02ca60,
        ]),
        BrainpoolP384t1_Fq::from_limbs([
            0x3df30f0ef5b2de4fcbc19309c0443c,
            0x4ebc7b3384ad290184fedc32cfb312,
            0xe831cf7f90f2c96274a037b19c9652,
            0x2677ac,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP384t1_Fq::from_limbs([
            0x3608e970d693ffa85c48ff5533a14b,
            0x551947e529bb2aca6e3d352a8217e2,
            0xfdbc5ad073724091679b964dde3acb,
            0x6ac102,
        ]),
        BrainpoolP384t1_Fq::from_limbs([
            0xcc87d8d1a8ad98b0e57ad18b965cb3,
            0x75c025307ebaa5b2b8e627e7415973,
            0x9219c739ad2f62d9a83df60ae49735,
            0x879c97,
        ]),
    ],
};

pub global BRAINPOOLP384t1_SCALAR_SLICES: u32 = 97;
pub type BrainpoolP384t1Scalar = ScalarField<BRAINPOOLP384t1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::BrainpoolP384t1_Fq }, quote { BRAINPOOLP384t1_PARAM })]
pub struct BrainpoolP384t1 {
    pub x: BrainpoolP384t1_Fq,
    pub y: BrainpoolP384t1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, BrainpoolP384t1_Fq, BrainpoolP384t1_Fr};
    use std::ops::Neg;

    use crate::bigcurve::BigCurve;

    use super::{BrainpoolP384t1, BRAINPOOLP384t1_SCALAR_SLICES, BrainpoolP384t1Scalar};

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BrainpoolP384t1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == BRAINPOOLP384t1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BrainpoolP384t1::one();
        let negone = BrainpoolP384t1_Fr::one().neg();
        let scalar = BrainpoolP384t1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = BrainpoolP384t1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = BrainpoolP384t1_Fr::from(4);
        let p_minus_4_fr = BrainpoolP384t1_Fr::modulus() - four;
        let p_minus_4 = BrainpoolP384t1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BrainpoolP384t1_Fr::one();
        let p_minus_5 = BrainpoolP384t1Scalar::from_bignum(p_minus_5_fr);
        let scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP384t1::one();
        let b = a.neg();
        let points = [a, b];

        let result = BrainpoolP384t1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP384t1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // BrainpoolP384t1 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<BrainpoolP384t1_Fq, BRAINPOOLP384t1_SCALAR_SLICES, BrainpoolP384t1>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP384t1_Fr = BrainpoolP384t1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP384t1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
