use crate::BigCurve;
use crate::BigCurveParams;
use crate::derive_curve_impl;
use crate::scalar_field::ScalarField;
use bignum::BigNum;
pub use bignum::{BrainpoolP224r1_Fq, BrainpoolP224r1_Fr};

pub global BRAINPOOLP224r1_PARAM: BigCurveParams<BrainpoolP224r1_Fq> = BigCurveParams {
    a: BrainpoolP224r1_Fq::from(0x68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43),
    b: BrainpoolP224r1_Fq::from(0x2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b),
    offset_generator: [
        BrainpoolP224r1_Fq::from_limbs([
            1075323320920990120713067180320075673,
            6568313905546376908115172528949,
        ]),
        BrainpoolP224r1_Fq::from_limbs([
            1192846486069290426873476727072532297,
            588125046588385822265914270979,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP224r1_Fq::from_limbs([
            1114440702009118313651831794369170326,
            2044932198558320143185824551663,
        ]),
        BrainpoolP224r1_Fq::from_limbs([
            1152749763947463143444993900943280499,
            6355650461538811215480836636148,
        ]),
    ],
    one: [
        BrainpoolP224r1_Fq::from(0xd9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d),
        BrainpoolP224r1_Fq::from(0x58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd),
    ],
};
pub global BRAINPOOLP224r1_SCALAR_SLICES: u32 = 57;
pub type BrainpoolP224r1Scalar = ScalarField<BRAINPOOLP224r1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::BrainpoolP224r1_Fq }, quote { BRAINPOOLP224r1_PARAM })]
pub struct BrainpoolP224r1 {
    pub x: BrainpoolP224r1_Fq,
    pub y: BrainpoolP224r1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, BrainpoolP224r1_Fq, BrainpoolP224r1_Fr};
    use std::ops::Neg;

    use crate::BigCurve;
    use super::BrainpoolP224r1;
    use super::BRAINPOOLP224r1_SCALAR_SLICES;
    use super::BrainpoolP224r1Scalar;

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BrainpoolP224r1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == BRAINPOOLP224r1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BrainpoolP224r1::one();
        let negone = BrainpoolP224r1_Fr::one().neg();
        let scalar = BrainpoolP224r1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = BrainpoolP224r1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = BrainpoolP224r1_Fr::from(4);
        let p_minus_4_fr = BrainpoolP224r1_Fr::modulus() - four;
        let p_minus_4 = BrainpoolP224r1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BrainpoolP224r1_Fr::one();
        let p_minus_5 = BrainpoolP224r1Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP224r1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = BrainpoolP224r1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP224r1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP224r1_Fr = BrainpoolP224r1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP224r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
