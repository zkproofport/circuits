use crate::BigCurve;
use crate::BigCurveParams;
use crate::derive_curve_impl;
use crate::scalar_field::ScalarField;
use bignum::BigNum;
pub use bignum::{Secp192r1_Fq, Secp192r1_Fr};

pub global SECP192r1_PARAM: BigCurveParams<Secp192r1_Fq> = BigCurveParams {
    a: Secp192r1_Fq::from(0xfffffffffffffffffffffffffffffffefffffffffffffffc),
    b: Secp192r1_Fq::from(0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1),
    offset_generator: [
        Secp192r1_Fq::from_limbs([232713807617434633364479786242241517, 90646127116863941060]),
        Secp192r1_Fq::from_limbs(
            [851326007238532123554569531696614955, 206678998028752795097],
        ),
    ],
    offset_generator_final: [
        Secp192r1_Fq::from_limbs(
            [354972031435724352040004843069284759, 2389854163324638626497],
        ),
        Secp192r1_Fq::from_limbs(
            [634712850436303468863967363097653750, 2581934864307078617660],
        ),
    ],
    one: [
        Secp192r1_Fq::from(0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012),
        Secp192r1_Fq::from(0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811),
    ],
};
pub global SECP192r1_SCALAR_SLICES: u32 = 49;
pub type Secp192r1Scalar = ScalarField<SECP192r1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::Secp192r1_Fq }, quote { SECP192r1_PARAM })]
pub struct Secp192r1 {
    pub x: Secp192r1_Fq,
    pub y: Secp192r1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, Secp192r1_Fq, Secp192r1_Fr};
    use std::ops::Neg;

    use crate::BigCurve;
    use super::Secp192r1;
    use super::SECP192r1_SCALAR_SLICES;
    use super::Secp192r1Scalar;

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = Secp192r1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == SECP192r1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = Secp192r1::one();
        let negone = Secp192r1_Fr::one().neg();
        let scalar = Secp192r1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = Secp192r1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = Secp192r1_Fr::from(4);
        let p_minus_4_fr = Secp192r1_Fr::modulus() - four;
        let p_minus_4 = Secp192r1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - Secp192r1_Fr::one();
        let p_minus_5 = Secp192r1Scalar::from_bignum(p_minus_5_fr);
        let mut scalars = [p_minus_4, p_minus_5];
        let a = Secp192r1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result =
            Secp192r1::evaluate_linear_expression(points, scalars, [Secp192r1::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: Secp192r1_Fr = Secp192r1_Fr::derive_from_seed(seed);
        let scalar_field = Secp192r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
