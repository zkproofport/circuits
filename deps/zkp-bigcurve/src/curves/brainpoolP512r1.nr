use crate::BigCurve;
use crate::BigCurveParams;
use crate::derive_curve_impl;
use crate::scalar_field::ScalarField;
use bignum::BigNum;
pub use bignum::{BrainpoolP512r1_Fq, BrainpoolP512r1_Fr};

pub global BRAINPOOLP512r1_PARAM: BigCurveParams<BrainpoolP512r1_Fq> = BigCurveParams {
    a: BrainpoolP512r1_Fq::from_limbs([
        0x1117a72bf2c7b9e7c1ac4d77fc94ca,
        0x5d5aa8253aa10a2ef1c98b9ac8b57f,
        0x8d3df91610a83441caea9863bc2ded,
        0x8b603b89e2327145ac234cc594cbdd,
        0x7830a331,
    ]),
    b: BrainpoolP512r1_Fq::from_limbs([
        0x4050b75ebae5dd2809bd638016f723,
        0xc7b9e7c1ac4d77fc94cadc083e6798,
        0xa10a2ef1c98b9ac8b57f1117a72bf2,
        0xa83441caea9863bc2ded5d5aa8253a,
        0x3df91610,
    ]),
    offset_generator: [
        BrainpoolP512r1_Fq::from_limbs([
            0xdcf10230b2c0660f79fc7397a8c6e5,
            0x0556564b4b7901a0beaed7a0891da5,
            0xc135b5fb1581ddaa80896e30daee11,
            0x1a481ad9252517735bfe56e66da9f7,
            0x66cbe79a,
        ]),
        BrainpoolP512r1_Fq::from_limbs([
            0x64b036951242a31fcf7066d07abcc0,
            0x618024a6d4ac557eb0358161f6660c,
            0xf305c87ef13f65c0ecc3047a5022e2,
            0x64c180f28bbc7c222eae073ac2520a,
            0x1f9575b6,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP512r1_Fq::from_limbs([
            0x53e17fbc1d577357b617d757c63cb4,
            0x9e7ba2c6e516bf440a84b2d3402f7c,
            0x55d09ab142686a6995c977ed1e8d10,
            0xaaa3ef0f00c4dc86f1ec828bcc8f7d,
            0x3ff3122d,
        ]),
        BrainpoolP512r1_Fq::from_limbs([
            0xa18e1f24911d50ccf3e9ed1249f5eb,
            0x880f5343bc7ef5841cd3307d99eadc,
            0xb6aad18c4eec580e48862d3190d3c0,
            0x89fbf0c52b76b888fd185e468b1c99,
            0x9338fe,
        ]),
    ],
    one: [
        BrainpoolP512r1_Fq::from_limbs([
            0x6d5047406a5e688b352209bcb9f822,
            0x1f78e2d0d48d50d1687b93b97d5f7c,
            0x70b5d916c1b43b62eef4d0098eff3b,
            0xd82ed9645a21322e9c4c6a9385ed9f,
            0x81aee4bd,
        ]),
        BrainpoolP512r1_Fq::from_limbs([
            0xca2b2fa8f0540678cd1e0f3ad80892,
            0xde494a5f485e5bca4bd88a2763aed1,
            0x24a57b1aa000c55b881f8111b2dc,
            0x566332ecc0eabfa9cf7822fdf209f7,
            0x7dde385d,
        ]),
    ],
};

pub global BRAINPOOLP512r1_SCALAR_SLICES: u32 = 129;
pub type BrainpoolP512r1Scalar = ScalarField<BRAINPOOLP512r1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::BrainpoolP512r1_Fq }, quote { BRAINPOOLP512r1_PARAM })]
pub struct BrainpoolP512r1 {
    pub x: BrainpoolP512r1_Fq,
    pub y: BrainpoolP512r1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, BrainpoolP512r1_Fq, BrainpoolP512r1_Fr};
    use std::ops::Neg;

    use crate::BigCurve;
    use super::BrainpoolP512r1;
    use super::BRAINPOOLP512r1_SCALAR_SLICES;
    use super::BrainpoolP512r1Scalar;

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BrainpoolP512r1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == BRAINPOOLP512r1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BrainpoolP512r1::one();
        let negone = BrainpoolP512r1_Fr::one().neg();
        let scalar = BrainpoolP512r1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = BrainpoolP512r1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = BrainpoolP512r1_Fr::from(4);
        let p_minus_4_fr = BrainpoolP512r1_Fr::modulus() - four;
        let p_minus_4 = BrainpoolP512r1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BrainpoolP512r1_Fr::one();
        let p_minus_5 = BrainpoolP512r1Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP512r1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = BrainpoolP512r1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP512r1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP512r1_Fr = BrainpoolP512r1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP512r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
