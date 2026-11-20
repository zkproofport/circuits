use crate::BigCurve;
use crate::BigCurveParams;
use crate::derive_curve_impl;
use crate::scalar_field::ScalarField;
use bignum::BigNum;
pub use bignum::{BrainpoolP512t1_Fq, BrainpoolP512t1_Fr};

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
        0xbcb4981527897504bec3e36a62bcd,
        0x441cfab76e1890e46884eae321f70c,
        0x7cbbbcf9,
    ]),
    offset_generator: [
        BrainpoolP512t1_Fq::from_limbs([
            0xdcf10230b2c0660f79fc7397a8c6e5,
            0x0556564b4b7901a0beaed7a0891da5,
            0xc135b5fb1581ddaa80896e30daee11,
            0x1a481ad9252517735bfe56e66da9f7,
            0x66cbe79a,
        ]),
        BrainpoolP512t1_Fq::from_limbs([
            0x1c6aa6c8709a7ece25d8f1f6edc899,
            0x195ca5bccc18999c80123574962c7c,
            0xa99e8057af3c1120b2f2201a1d92cc,
            0x349185683024e53e809dd1ce4bc8b2,
            0x44963c33,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP512t1_Fq::from_limbs([
            0x813b049374f7c0bb40fb2811111662,
            0x8684539a69e1d3fe9bbf911e3ea04b,
            0x9be7dc88b90072819806e09897121a,
            0x9b130e4cc41066313fbe901f8761b0,
            0x5f25a490,
        ]),
        BrainpoolP512t1_Fq::from_limbs([
            0x245156a742893d5e4b73e73dc82668,
            0xc90ed6121108b6c30519ba1e3c9578,
            0x59c6a6adcef48852e56ddbbf6a9f8a,
            0x38e1d6da6bfd998f4fafd4344fb177,
            0x1045e964,
        ]),
    ],
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

    use crate::BigCurve;
    use super::BrainpoolP512t1;
    use super::BRAINPOOLP512t1_SCALAR_SLICES;
    use super::BrainpoolP512t1Scalar;

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
        let mut scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP512t1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = BrainpoolP512t1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP512t1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP512t1_Fr = BrainpoolP512t1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP512t1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
