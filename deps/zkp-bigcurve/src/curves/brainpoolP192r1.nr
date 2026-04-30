use crate::BigCurve;
use crate::BigCurveParams;
use crate::derive_curve_impl;
use crate::scalar_field::ScalarField;
use bignum::BigNum;
pub use bignum::{BrainpoolP192r1_Fq, BrainpoolP192r1_Fr};

pub global BRAINPOOLP192r1_PARAM: BigCurveParams<BrainpoolP192r1_Fq> = BigCurveParams {
    a: BrainpoolP192r1_Fq::from(0x6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef),
    b: BrainpoolP192r1_Fq::from(0x469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9),
    offset_generator: [
        BrainpoolP192r1_Fq::from_limbs([
            341737422451312232813322064752395693,
            2591393770624295342613,
        ]),
        BrainpoolP192r1_Fq::from_limbs([
            998235051954736967020072969000649982,
            2426767175810624694119,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP192r1_Fq::from_limbs([
            983407475235826105811997472305228754,
            3281197066244531590496,
        ]),
        BrainpoolP192r1_Fq::from_limbs([
            817955550732409348615512766579207649,
            3022595801548064898877,
        ]),
    ],
    one: [
        BrainpoolP192r1_Fq::from(0xc0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6),
        BrainpoolP192r1_Fq::from(0x14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f),
    ],
};
pub global BRAINPOOLP192r1_SCALAR_SLICES: u32 = 49;
pub type BrainpoolP192r1Scalar = ScalarField<BRAINPOOLP192r1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::BrainpoolP192r1_Fq }, quote { BRAINPOOLP192r1_PARAM })]
pub struct BrainpoolP192r1 {
    pub x: BrainpoolP192r1_Fq,
    pub y: BrainpoolP192r1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, BrainpoolP192r1_Fq, BrainpoolP192r1_Fr};
    use std::ops::Neg;

    use crate::BigCurve;
    use super::BrainpoolP192r1;
    use super::BRAINPOOLP192r1_SCALAR_SLICES;
    use super::BrainpoolP192r1Scalar;

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BrainpoolP192r1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == BRAINPOOLP192r1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BrainpoolP192r1::one();
        let negone = BrainpoolP192r1_Fr::one().neg();
        let scalar = BrainpoolP192r1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = BrainpoolP192r1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = BrainpoolP192r1_Fr::from(4);
        let p_minus_4_fr = BrainpoolP192r1_Fr::modulus() - four;
        let p_minus_4 = BrainpoolP192r1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BrainpoolP192r1_Fr::one();
        let p_minus_5 = BrainpoolP192r1Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP192r1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = BrainpoolP192r1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP192r1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP192r1_Fr = BrainpoolP192r1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP192r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
