use bignum::BigNum;
pub use bignum::{Secp224r1_Fq, Secp224r1_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global SECP224r1_PARAM: BigCurveParams<Secp224r1_Fq> = BigCurveParams {
    a: Secp224r1_Fq::from_limbs(
        [0xfffffefffffffffffffffffffffffe, 0xffffffffffffffffffffffffff],
    ),
    b: Secp224r1_Fq::from_limbs(
        [0x44b0b7d7bfd8ba270b39432355ffb4, 0xb4050a850c04b3abf541325650],
    ),
    one: [
        Secp224r1_Fq::from_limbs(
            [0x03c1d356c21122343280d6115c1d21, 0xb70e0cbd6bb4bf7f321390b94a],
        ),
        Secp224r1_Fq::from_limbs(
            [0x4375a05a07476444d5819985007e34, 0xbd376388b5f723fb4c22dfe6cd],
        ),
    ],
    offset_generator: [
        Secp224r1_Fq::from_limbs(
            [0x8c9f733f1a33d59745d94300eb8f84, 0x7cc7c3a7601ad6d2a112027009],
        ),
        Secp224r1_Fq::from_limbs(
            [0xbd0d523de3eb4368cc71162a4adb74, 0x01f78f37c545e0a7f82cdf458c],
        ),
    ],
    offset_generator_final: [
        Secp224r1_Fq::from_limbs(
            [0x4e1f4c2297068f1415d886d7618560, 0x458e7e5480670115bf0ba3ac],
        ),
        Secp224r1_Fq::from_limbs(
            [0xc76f2003e5037b98fb6222aaf943a1, 0x60beb691bd00ddb8d7283b7147],
        ),
    ],
};

pub global SECP224r1_SCALAR_SLICES: u32 = 57;
pub type Secp224r1Scalar = ScalarField<SECP224r1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::Secp224r1_Fq }, quote { SECP224r1_PARAM })]
pub struct Secp224r1 {
    pub x: Secp224r1_Fq,
    pub y: Secp224r1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, Secp224r1_Fq, Secp224r1_Fr};
    use std::ops::Neg;

    use crate::bigcurve::BigCurve;

    use super::{Secp224r1, SECP224r1_SCALAR_SLICES, Secp224r1Scalar};

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = Secp224r1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == SECP224r1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = Secp224r1::one();
        let negone = Secp224r1_Fr::one().neg();
        let scalar = Secp224r1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = Secp224r1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = Secp224r1_Fr::from(4);
        let p_minus_4_fr = Secp224r1_Fr::modulus() - four;
        let p_minus_4 = Secp224r1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - Secp224r1_Fr::one();
        let p_minus_5 = Secp224r1Scalar::from_bignum(p_minus_5_fr);
        let scalars = [p_minus_4, p_minus_5];
        let a = Secp224r1::one();
        let b = a.neg();
        let points = [a, b];

        let result =
            Secp224r1::evaluate_linear_expression(points, scalars, [Secp224r1::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // Secp224r1 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<Secp224r1_Fq, SECP224r1_SCALAR_SLICES, Secp224r1>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: Secp224r1_Fr = Secp224r1_Fr::derive_from_seed(seed);
        let scalar_field = Secp224r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
