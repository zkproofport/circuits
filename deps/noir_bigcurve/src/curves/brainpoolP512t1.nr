use bignum::BigNum;
pub use bignum::{BrainpoolP512t1_Fq, BrainpoolP512t1_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global BRAINPOOLP512t1_PARAM: BigCurveParams<BrainpoolP512t1_Fq> = BigCurveParams {
    a: BrainpoolP512t1_Fq::from_limbs([
        0x81ff2f2d82c68528aa6056583a48f0,
        0x9b009bc66842aecda12ae6a380e628,
        0xb3b3c9d20ed6639cca703308717d4d,
        0xdbe9c48b3fd4e6ae33c9fc07cb308d,
        0xaadd9db8,
    ]),
    b: BrainpoolP512t1_Fq::from_limbs([
        0x2553b465763689180ea2571867423e,
        0xfa2304976540f6450085f2dae145c2,
        0x0bcb4981527897504bec3e36a62bcd,
        0x441cfab76e1890e46884eae321f70c,
        0x7cbbbcf9,
    ]),
    one: [
        BrainpoolP512t1_Fq::from_limbs([
            0xa3f25fe26f06b51baa2696fa9035da,
            0x51735cdb3ea499aa77a7d6943a64f7,
            0x2458c56dde9db1758d39c0313d82ba,
            0x12788717b9c1ba06cbc2a6feba8584,
            0x640ece5c,
        ]),
        BrainpoolP512t1_Fq::from_limbs([
            0x6ecff96dbb8bace198b61e00f8b332,
            0x2184beef216bd71df2dadf86a62730,
            0x19b71634c01131159cae03cee9d993,
            0x95f5af0fa2c892376c84ace1bb4e30,
            0x5b534bd5,
        ]),
    ],
    offset_generator: [
        BrainpoolP512t1_Fq::from_limbs([
            0xa2dc14fbfe624cb98c63479d510d26,
            0xac0865d0b5dd014ec828234b1eecba,
            0x81c7bc44b98ac12c0f1d20dea0e8d3,
            0x46c5a7074418de49d735fab083451f,
            0x0afb6d50,
        ]),
        BrainpoolP512t1_Fq::from_limbs([
            0xce05a54e52677d8ba4e5f5ee32f28c,
            0x797f2041792870594ff800bbea8703,
            0x0b36284f87716d5de3eee159979a3c,
            0x78d5cc8b13b4686ac670e12a00f4d2,
            0x6c267cea,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP512t1_Fq::from_limbs([
            0x5fa9e662ce8323ec52a7a365aff707,
            0x373a623e92772d316215860d8633f0,
            0x95a9c9f4d3245b9e915a0e8aeaa705,
            0xaea4ebd26fb2742e8d234ff78cba95,
            0x79ad367d,
        ]),
        BrainpoolP512t1_Fq::from_limbs([
            0x2631ca3828b1e59114bcb8e00927b9,
            0x2b3250289b486d5dec861cf2b2e7bf,
            0x689d1ff3cb9a97befb34474be0214a,
            0x67605b5796dfffe237570d0b3c680c,
            0x6526dd3f,
        ]),
    ],
};

pub global BRAINPOOLP512t1_SCALAR_SLICES: u32 = 129;
pub type BrainpoolP512t1Scalar = ScalarField<BRAINPOOLP512t1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::BrainpoolP512t1_Fq }, quote { BRAINPOOLP512t1_PARAM })]
pub struct BrainpoolP512t1 {
    pub x: BrainpoolP512t1_Fq,
    pub y: BrainpoolP512t1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, BrainpoolP512t1_Fq, BrainpoolP512t1_Fr};
    use std::ops::Neg;

    use crate::bigcurve::BigCurve;

    use super::{BrainpoolP512t1, BRAINPOOLP512t1_SCALAR_SLICES, BrainpoolP512t1Scalar};

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BrainpoolP512t1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == BRAINPOOLP512t1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BrainpoolP512t1::one();
        let negone = BrainpoolP512t1_Fr::one().neg();
        let scalar = BrainpoolP512t1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = BrainpoolP512t1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = BrainpoolP512t1_Fr::from(4);
        let p_minus_4_fr = BrainpoolP512t1_Fr::modulus() - four;
        let p_minus_4 = BrainpoolP512t1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BrainpoolP512t1_Fr::one();
        let p_minus_5 = BrainpoolP512t1Scalar::from_bignum(p_minus_5_fr);
        let scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP512t1::one();
        let b = a.neg();
        let points = [a, b];

        let result = BrainpoolP512t1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP512t1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // BrainpoolP512t1 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<BrainpoolP512t1_Fq, BRAINPOOLP512t1_SCALAR_SLICES, BrainpoolP512t1>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP512t1_Fr = BrainpoolP512t1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP512t1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
