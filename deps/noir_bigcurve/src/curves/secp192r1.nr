use bignum::BigNum;
pub use bignum::{Secp192r1_Fq, Secp192r1_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global SECP192r1_PARAM: BigCurveParams<Secp192r1_Fq> = BigCurveParams {
    a: Secp192r1_Fq::from_limbs([0xfffffffffffffefffffffffffffffc, 0xffffffffffffffffff]),
    b: Secp192r1_Fq::from_limbs([0xa7e9ab72243049feb8deecc146b9b1, 0x64210519e59c80e70f]),
    one: [
        Secp192r1_Fq::from_limbs([0xbf20eb43a18800f4ff0afd82ff1012, 0x188da80eb03090f67c]),
        Secp192r1_Fq::from_limbs([0x1011ed6b24cdd573f977a11e794811, 0x07192b95ffc8da7863]),
    ],
    offset_generator: [
        Secp192r1_Fq::from_limbs([0x9010ce281b9e7de9162b42f5711419, 0xc70a23d934deb64f17]),
        Secp192r1_Fq::from_limbs([0x3f54578627772e36199bea8593ba86, 0x3d43bcb3cd65705315]),
    ],
    offset_generator_final: [
        Secp192r1_Fq::from_limbs([0x9f53415b9d7594201dd0313ac6d415, 0xdd2e6f287484a55f58]),
        Secp192r1_Fq::from_limbs([0x37eda2bf0ee9bc54691a928895096a, 0x8d6937b7d49454f2a0]),
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

    use crate::bigcurve::BigCurve;

    use super::{Secp192r1, SECP192r1_SCALAR_SLICES, Secp192r1Scalar};

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
        let scalars = [p_minus_4, p_minus_5];
        let a = Secp192r1::one();
        let b = a.neg();
        let points = [a, b];

        let result =
            Secp192r1::evaluate_linear_expression(points, scalars, [Secp192r1::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // Secp192r1 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<Secp192r1_Fq, SECP192r1_SCALAR_SLICES, Secp192r1>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: Secp192r1_Fr = Secp192r1_Fr::derive_from_seed(seed);
        let scalar_field = Secp192r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
