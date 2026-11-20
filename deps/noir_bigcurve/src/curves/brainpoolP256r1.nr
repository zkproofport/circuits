use bignum::BigNum;
pub use bignum::{BrainpoolP256r1_Fq, BrainpoolP256r1_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global BRAINPOOLP256r1_PARAM: BigCurveParams<BrainpoolP256r1_Fq> = BigCurveParams {
    a: BrainpoolP256r1_Fq::from_limbs([
        0x8055c126dc5c6ce94a4b44f330b5d9,
        0x0975fc2c3057eef67530417affe7fb,
        0x7d5a,
    ]),
    b: BrainpoolP256r1_Fq::from_limbs([
        0x8416295cf7e1ce6bccdc18ff8c07b6,
        0x5c6ce94a4b44f330b5d9bbd77cbf95,
        0x26dc,
    ]),
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
    offset_generator: [
        BrainpoolP256r1_Fq::from_limbs([
            0xe347fe3396a058bfb1d48f091d44ef,
            0xf8176ac05fb4161c3552c2c91a1d7e,
            0x9b80,
        ]),
        BrainpoolP256r1_Fq::from_limbs([
            0x4574d21f398662bcbe132cd81f1a34,
            0x6b481da3b998f5150ac28437d4993e,
            0x20c1,
        ]),
    ],
    offset_generator_final: [
        BrainpoolP256r1_Fq::from_limbs([
            0x10c3ef21e37f9c0658d197dc7c7b60,
            0x0c51a73f4d6cf64e9b7be93e9ad4ea,
            0x2651,
        ]),
        BrainpoolP256r1_Fq::from_limbs([
            0x011cfdcb0483ad02b428eba883e264,
            0x5221562935997482578985c96380b3,
            0x1883,
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

    use crate::bigcurve::BigCurve;

    use super::{BrainpoolP256r1, BRAINPOOLP256r1_SCALAR_SLICES, BrainpoolP256r1Scalar};

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
        let scalars = [p_minus_4, p_minus_5];
        let a = BrainpoolP256r1::one();
        let b = a.neg();
        let points = [a, b];

        let result = BrainpoolP256r1::evaluate_linear_expression(
            points,
            scalars,
            [BrainpoolP256r1::one().neg()],
        );

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // BrainpoolP256r1 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<BrainpoolP256r1_Fq, BRAINPOOLP256r1_SCALAR_SLICES, BrainpoolP256r1>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: BrainpoolP256r1_Fr = BrainpoolP256r1_Fr::derive_from_seed(seed);
        let scalar_field = BrainpoolP256r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
