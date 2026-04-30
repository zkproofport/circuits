use crate::BigCurve;
use crate::BigCurveParams;
use crate::derive_curve_impl;
use crate::scalar_field::ScalarField;
use bignum::BigNum;
pub use bignum::{BrainpoolP256t1_Fq, BrainpoolP256t1_Fr};

pub global BRAINPOOLP256t1_PARAM: BigCurveParams<BrainpoolP256t1_Fq> = BigCurveParams {
    a: BrainpoolP256t1_Fq::from_limbs([
        0x3bf623d52620282013481d1f6e5374,
        0x57dba1eea9bc3e660a909d838d726e,
        0xa9fb,
    ]),
    b: BrainpoolP256t1_Fq::from_limbs([
        0x93ebc4af2f49256ae58101fee92b04,
        0x61c430d84ea4fe66a7733d0b76b7bf,
        0x662c,
    ]),
    offset_generator: [
        BrainpoolP256t1_Fq::from_limbs([
            0xdf7b7690a146dc4daa3e512094cd28,
            0x0293f430def68c091076b5e85608a3,
            0x256a,
        ]),
        BrainpoolP256t1_Fq::from_limbs([
            0x3cd2eb3fdb4d801d7d357371eeb0f7,
            0xaa3d8b3084d3a11df020a3fe22a258,
            0x4ecd,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP256t1_Fq::from_limbs([
            0x982c0658a8aa105afe1c74b5f403b5,
            0x7b8ade1081f0492e3fab6d9a99d0c2,
            0x7dcf,
        ]),
        BrainpoolP256t1_Fq::from_limbs([
            0x442f5f8f9bdef5a5366dc979b93d2a,
            0xd1c8259ef3e220a6792624929c0520,
            0x4862,
        ]),
    ],
    one: [
        BrainpoolP256t1_Fq::from_limbs([
            0xa142c47aafbc2b79a191562e1305f4,
            0xeb3cc1cfe7b7732213b23a656149af,
            0xa3e8,
        ]),
        BrainpoolP256t1_Fq::from_limbs([
            0xbcb6de39d027001dabe8f35b25c9be,
            0x6c823439c56d7f7b22e14644417e69,
            0x2d99,
        ]),
    ],
};

pub global BRAINPOOLP256t1_SCALAR_SLICES: u32 = 65;
pub type BrainpoolP256t1Scalar = ScalarField<BRAINPOOLP256t1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::BrainpoolP256t1_Fq }, quote { BRAINPOOLP256t1_PARAM })]
pub struct BrainpoolP256t1 {
    pub x: BrainpoolP256t1_Fq,
    pub y: BrainpoolP256t1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, BrainpoolP256t1_Fq, BrainpoolP256t1_Fr};
    use std::ops::Neg;

    use crate::BigCurve;
    use super::BrainpoolP256t1;
    use super::BRAINPOOLP256t1_SCALAR_SLICES;
    use super::BrainpoolP256t1Scalar;

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BrainpoolP256t1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == BRAINPOOLP256t1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BrainpoolP256t1::one();
        let negone = BrainpoolP256t1_Fr::one().neg();
        let scalar = BrainpoolP256t1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = BrainpoolP256t1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = BrainpoolP256t1_Fr::from(4);
        let p_minus_4_fr = BrainpoolP256t1_Fr::modulus() - four;
        let p_minus_4 = BrainpoolP256t1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BrainpoolP256t1_Fr::one();
        let p_minus_5 = BrainpoolP256t1Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP256t1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = BrainpoolP256t1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP256t1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP256t1_Fr = BrainpoolP256t1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP256t1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
