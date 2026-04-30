use crate::BigCurve;
use crate::BigCurveParams;
use crate::derive_curve_impl;
use crate::scalar_field::ScalarField;
use bignum::BigNum;
pub use bignum::{BrainpoolP384r1_Fq, BrainpoolP384r1_Fr};

pub global BRAINPOOLP384r1_PARAM: BigCurveParams<BrainpoolP384r1_Fq> = BigCurveParams {
    a: BrainpoolP384r1_Fq::from_limbs([
        0xa5814a503ad4eb04a8c7dd22ce2826,
        0xa28e4fb22787139165efba91f90f8a,
        0xc63d8c150c3c72080ace05afa0c2be,
        0x7bc382,
    ]),
    b: BrainpoolP384r1_Fq::from_limbs([
        0xb4390295dbc9943ab78696fa504c11,
        0x7de107dcd2a62e880ea53eeb62d57c,
        0xdd22ce28268b39b55416f0447c2fb7,
        0x4a8c7,
    ]),
    offset_generator: [
        BrainpoolP384r1_Fq::from_limbs([
            0xbbbaabfc4cac1a405d106d80d5c4d3,
            0x43fd3007a1f13a542923edd0092e31,
            0x56f1e610db6c0448cd751930f2aec1,
            0x6bfeb1,
        ]),
        BrainpoolP384r1_Fq::from_limbs([
            0xc9c86458b6cea4b5b0de7915d7bbae,
            0xac24a6ee83c6a3f28782753877c208,
            0xeaa52b8f5dd6e1e0f1d1f7bebdcbb2,
            0x3837d0,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP384r1_Fq::from_limbs([
            0x2e9f7227713bea6f733c401324b4e0,
            0x785e76d88efb112077932d55a977da,
            0xa0a30affcd27bceca918db80e34dd6,
            0x1bce71,
        ]),
        BrainpoolP384r1_Fq::from_limbs([
            0x5be84d2eeb67a7c229a9fa69e4b8fe,
            0xbfe86c50b839a1fd240ccd06d5c2e6,
            0xc93d3f8b990b154369ebf7c3621a8d,
            0x60cef5,
        ]),
    ],
    one: [
        BrainpoolP384r1_Fq::from_limbs([
            0x26e03436d646aaef87b2e247d4af1e,
            0xa3e77ef14fe3db7fcafe0cbd10e8e8,
            0xf068cf45ffa2a63a81b7c13f6b8847,
            0x1d1c64,
        ]),
        BrainpoolP384r1_Fq::from_limbs([
            0x4646217791811142820341263c5315,
            0xb29feec5864e19c054ff99129280e,
            0x7520f9c2a45cb1eb8e95cfd55262b7,
            0x8abe1d,
        ]),
    ],
};

pub global BRAINPOOLP384r1_SCALAR_SLICES: u32 = 97;
pub type BrainpoolP384r1Scalar = ScalarField<BRAINPOOLP384r1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::BrainpoolP384r1_Fq }, quote { BRAINPOOLP384r1_PARAM })]
pub struct BrainpoolP384r1 {
    pub x: BrainpoolP384r1_Fq,
    pub y: BrainpoolP384r1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, BrainpoolP384r1_Fq, BrainpoolP384r1_Fr};
    use std::ops::Neg;

    use crate::BigCurve;
    use super::BrainpoolP384r1;
    use super::BRAINPOOLP384r1_SCALAR_SLICES;
    use super::BrainpoolP384r1Scalar;

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = BrainpoolP384r1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == BRAINPOOLP384r1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = BrainpoolP384r1::one();
        let negone = BrainpoolP384r1_Fr::one().neg();
        let scalar = BrainpoolP384r1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = BrainpoolP384r1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = BrainpoolP384r1_Fr::from(4);
        let p_minus_4_fr = BrainpoolP384r1_Fr::modulus() - four;
        let p_minus_4 = BrainpoolP384r1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - BrainpoolP384r1_Fr::one();
        let p_minus_5 = BrainpoolP384r1Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP384r1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result = BrainpoolP384r1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP384r1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP384r1_Fr = BrainpoolP384r1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP384r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
