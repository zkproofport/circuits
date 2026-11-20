use crate::BigCurve;
use crate::BigCurveParams;
use crate::derive_curve_impl;
use crate::scalar_field::ScalarField;
use bignum::BigNum;
pub use bignum::{Secp224r1_Fq, Secp224r1_Fr};

pub global SECP224r1_PARAM: BigCurveParams<Secp224r1_Fq> = BigCurveParams {
    a: Secp224r1_Fq::from(0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe),
    b: Secp224r1_Fq::from(0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4),
    offset_generator: [
        Secp224r1_Fq::from_limbs([
            256580546934709026519577652212863357,
            11339088992457647144137718767961,
        ]),
        Secp224r1_Fq::from_limbs([
            353594544583432096372112790460281511,
            2171878428325809151599171173861,
        ]),
    ],
    offset_generator_final: [
        Secp224r1_Fq::from_limbs([
            1054362967121624051910781646571944004,
            13920482839761186129698370926212,
        ]),
        Secp224r1_Fq::from_limbs([
            1271693749289344300113760553252857630,
            17890356279514120347325778718798,
        ]),
    ],
    one: [
        Secp224r1_Fq::from(0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21),
        Secp224r1_Fq::from(0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34),
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

    use crate::BigCurve;
    use super::Secp224r1;
    use super::SECP224r1_SCALAR_SLICES;
    use super::Secp224r1Scalar;

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
        let mut scalars = [p_minus_4, p_minus_5];
        let a = Secp224r1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result =
            Secp224r1::evaluate_linear_expression(points, scalars, [Secp224r1::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: Secp224r1_Fr = Secp224r1_Fr::derive_from_seed(seed);
        let scalar_field = Secp224r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
