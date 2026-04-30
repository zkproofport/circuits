use crate::BigCurve;
use crate::BigCurveParams;
use crate::derive_curve_impl;
use crate::scalar_field::ScalarField;
use bignum::BigNum;
pub use bignum::{BrainpoolP384t1_Fq, BrainpoolP384t1_Fr};

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
    offset_generator: [
        BrainpoolP384t1_Fq::from_limbs([
            0xab2a95595a8cf5c742744146db4423,
            0xcafbcff834543d7813419ddbc47dc9,
            0x5d28d6a981a53726bf047776d08a7e,
            0x168260,
        ]),
        BrainpoolP384t1_Fq::from_limbs([
            0x3a87f2e823514ed685a7dd25cfcdbe,
            0xd7dd6f25cb3c5766b7a36e055c5523,
            0xd29b58363212f0d12f1f8869a093fb,
            0x6e1883,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP384t1_Fq::from_limbs([
            0x1e940dd0d5fd274ecda25613aea130,
            0x6c088dcfccc1a92ada8b7195c33b31,
            0x2fc84411ddaf2f68a06db9fcc77a59,
            0x195942,
        ]),
        BrainpoolP384t1_Fq::from_limbs([
            0xf3c0a8d407798b901c3cd905ac157d,
            0xfaa93dfeae5e0759fe001cf3f52f1d,
            0x2fbc2d9f2c4f18a417c7b40823d678,
            0x781ef2,
        ]),
    ],
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

    use crate::BigCurve;
    use super::BrainpoolP384t1;
    use super::BRAINPOOLP384t1_SCALAR_SLICES;
    use super::BrainpoolP384t1Scalar;

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
        let mut scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP384t1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = BrainpoolP384t1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP384t1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP384t1_Fr = BrainpoolP384t1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP384t1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
