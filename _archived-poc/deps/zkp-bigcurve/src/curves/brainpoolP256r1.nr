use crate::BigCurve;
use crate::BigCurveParams;
use crate::derive_curve_impl;
use crate::scalar_field::ScalarField;
use bignum::BigNum;
pub use bignum::{BrainpoolP256r1_Fq, BrainpoolP256r1_Fr};

pub global BRAINPOOLP256r1_PARAM: BigCurveParams<BrainpoolP256r1_Fq> = BigCurveParams {
    a: BrainpoolP256r1_Fq::from_limbs([
        0x8055c126dc5c6ce94a4b44f330b5d9,
        0x975fc2c3057eef67530417affe7fb,
        0x7d5a,
    ]),
    b: BrainpoolP256r1_Fq::from_limbs([
        0x8416295cf7e1ce6bccdc18ff8c07b6,
        0x5c6ce94a4b44f330b5d9bbd77cbf95,
        0x26dc,
    ]),
    offset_generator: [
        BrainpoolP256r1_Fq::from_limbs([
            0xdf7b7690a146dc4daa3e512094cd28,
            0x0293f430def68c091076b5e85608a3,
            0x256a,
        ]),
        BrainpoolP256r1_Fq::from_limbs([
            0xe90d38a99e804a5d800451dcb0103e,
            0x398ffd08546ea665948bc7f6fb6ca7,
            0x0b5e,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP256r1_Fq::from_limbs([
            0xa92997c4eee759bbff34df47c83551,
            0x49c4a27c8f3a09dce7819cd9e8903d,
            0x8bd1,
        ]),
        BrainpoolP256r1_Fq::from_limbs([
            0x7c95e35a05c9ad107623858de9a569,
            0x9fd7b0ea3a97ed1cd0b8820e3aec6d,
            0x26e5,
        ]),
    ],
    one: [
        BrainpoolP256r1_Fq::from_limbs([
            0xde27e1e3bd23c23a4453bd9ace3262,
            0xaeb9cb7e57cb2c4b482ffc81b7afb9,
            0x8bd2,
        ]),
        BrainpoolP256r1_Fq::from_limbs([
            0x7745132ded8e545c1d54c72f046997,
            0xf835c3dac4fd97f8461a14611dc9c2,
            0x547e,
        ]),
    ],
};

pub global BRAINPOOLP256r1_SCALAR_SLICES: u32 = 65;
pub type BrainpoolP256r1Scalar = ScalarField<BRAINPOOLP256r1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::BrainpoolP256r1_Fq }, quote { BRAINPOOLP256r1_PARAM })]
pub struct BrainpoolP256r1 {
    pub x: BrainpoolP256r1_Fq,
    pub y: BrainpoolP256r1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, BrainpoolP256r1_Fq, BrainpoolP256r1_Fr};
    use std::ops::Neg;

    use crate::BigCurve;
    use super::BrainpoolP256r1;
    use super::BRAINPOOLP256r1_SCALAR_SLICES;
    use super::BrainpoolP256r1Scalar;

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BrainpoolP256r1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == BRAINPOOLP256r1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BrainpoolP256r1::one();
        let negone = BrainpoolP256r1_Fr::one().neg();
        let scalar = BrainpoolP256r1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = BrainpoolP256r1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = BrainpoolP256r1_Fr::from(4);
        let p_minus_4_fr = BrainpoolP256r1_Fr::modulus() - four;
        let p_minus_4 = BrainpoolP256r1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BrainpoolP256r1_Fr::one();
        let p_minus_5 = BrainpoolP256r1Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP256r1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = BrainpoolP256r1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP256r1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP256r1_Fr = BrainpoolP256r1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP256r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
