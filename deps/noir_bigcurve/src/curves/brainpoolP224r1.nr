use bignum::BigNum;
pub use bignum::{BrainpoolP224r1_Fq, BrainpoolP224r1_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global BRAINPOOLP224r1_PARAM: BigCurveParams<BrainpoolP224r1_Fq> = BigCurveParams {
    a: BrainpoolP224r1_Fq::from_limbs([
        0x530b514e182ad8b0042a59cad29f43,
        0x68a5e62ca9ce6c1c299803a6c1,
    ]),
    b: BrainpoolP224r1_Fq::from_limbs([
        0x2369e33e2135d266dbb372386c400b,
        0x2580f63ccfe44138870713b1a9,
    ]),
    one: [
        BrainpoolP224r1_Fq::from_limbs([
            0x7dc68c9e4ce3174c1e6efdee12c07d,
            0x0d9029ad2c7e5cf4340823b2a8,
        ]),
        BrainpoolP224r1_Fq::from_limbs([
            0xcdac24354b9e99caa3f6d3761402cd,
            0x58aa56f772c0726f24c6b89e4e,
        ]),
    ],
    offset_generator: [
        BrainpoolP224r1_Fq::from_limbs([
            0x2ac97021a80a8156c585cf92933ef8,
            0x95ae8f4efb7a3ae99eb0b586e5,
        ]),
        BrainpoolP224r1_Fq::from_limbs([
            0x692bb26fc3b64b6dec2ba62fc11710,
            0x69d967e78a4dc06038d4bb1d3f,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP224r1_Fq::from_limbs([
            0x0312f3eb3f899974b0e6e20da9355a,
            0x53c9f4cdbb3decbab32d546a92,
        ]),
        BrainpoolP224r1_Fq::from_limbs([
            0xc8e3be1d563dacfc7154b066c5f150,
            0x4f8dafb15140e09db144cec356,
        ]),
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

    use crate::bigcurve::BigCurve;

    use super::{BrainpoolP224r1, BRAINPOOLP224r1_SCALAR_SLICES, BrainpoolP224r1Scalar};

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
        let scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP224r1::one();
        let b = a.neg();
        let points = [a, b];

        let result = BrainpoolP224r1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP224r1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // BrainpoolP224r1 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<BrainpoolP224r1_Fq, BRAINPOOLP224r1_SCALAR_SLICES, BrainpoolP224r1>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP224r1_Fr = BrainpoolP224r1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP224r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
