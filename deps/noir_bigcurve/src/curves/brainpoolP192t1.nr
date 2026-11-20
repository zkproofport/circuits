use bignum::BigNum;
pub use bignum::{BrainpoolP192t1_Fq, BrainpoolP192t1_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global BRAINPOOLP192t1_PARAM: BigCurveParams<BrainpoolP192t1_Fq> = BigCurveParams {
    a: BrainpoolP192t1_Fq::from_limbs([0xa3463093d18db78fce476de1a86294, 0xc302f41d932a36cda7]),
    b: BrainpoolP192t1_Fq::from_limbs([0xf9deb43b35bec2fb68542e27897b79, 0x13d56ffaec78681e68]),
    one: [
        BrainpoolP192t1_Fq::from_limbs([0x2e1fe7bbf43fa72c446af6f4618129, 0x3ae9e58c82f63c3028]),
        BrainpoolP192t1_Fq::from_limbs([0x2ab5ca449d0084b7e5b3de7ccc01c9, 0x097e2c5667c2223a90]),
    ],
    offset_generator: [
        BrainpoolP192t1_Fq::from_limbs([0x7210f42fbede9c5985dc3ee4c9e721, 0x05134449dcd7b0384f]),
        BrainpoolP192t1_Fq::from_limbs([0x3f624b0afa2af98b5a994c97cb914a, 0x57f9a8880093600278]),
    ],
    offset_generator_final: [
        BrainpoolP192t1_Fq::from_limbs([0xeffb0b3c2c47d0f3f7ce70830c82e8, 0x22d7f1508778a9a944]),
        BrainpoolP192t1_Fq::from_limbs([0x9f29d0f7cda0fb363a2a7ec6caed27, 0x10c25751a5ccaf84cb]),
    ],
};

pub global BRAINPOOLP192t1_SCALAR_SLICES: u32 = 49;
pub type BrainpoolP192t1Scalar = ScalarField<BRAINPOOLP192t1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::BrainpoolP192t1_Fq }, quote { BRAINPOOLP192t1_PARAM })]
pub struct BrainpoolP192t1 {
    pub x: BrainpoolP192t1_Fq,
    pub y: BrainpoolP192t1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, BrainpoolP192t1_Fq, BrainpoolP192t1_Fr};
    use std::ops::Neg;

    use crate::bigcurve::BigCurve;

    use super::{BrainpoolP192t1, BRAINPOOLP192t1_SCALAR_SLICES, BrainpoolP192t1Scalar};

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BrainpoolP192t1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == BRAINPOOLP192t1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BrainpoolP192t1::one();
        let negone = BrainpoolP192t1_Fr::one().neg();
        let scalar = BrainpoolP192t1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = BrainpoolP192t1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = BrainpoolP192t1_Fr::from(4);
        let p_minus_4_fr = BrainpoolP192t1_Fr::modulus() - four;
        let p_minus_4 = BrainpoolP192t1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BrainpoolP192t1_Fr::one();
        let p_minus_5 = BrainpoolP192t1Scalar::from_bignum(p_minus_5_fr);
        let scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP192t1::one();
        let b = a.neg();
        let points = [a, b];

        let result = BrainpoolP192t1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP192t1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // BrainpoolP192t1 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<BrainpoolP192t1_Fq, BRAINPOOLP192t1_SCALAR_SLICES, BrainpoolP192t1>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP192t1_Fr = BrainpoolP192t1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP192t1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
