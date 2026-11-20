use bignum::BigNum;
pub use bignum::{Secp521r1_Fq, Secp521r1_Fr};

use crate::bigcurve::BigCurve;
use crate::bigcurve::BigCurveParams;
use crate::bigcurve::derive_curve_impl;
use crate::scalar_field::ScalarField;

pub global SECP521r1_PARAM: BigCurveParams<Secp521r1_Fq> = BigCurveParams {
    a: Secp521r1_Fq::from_limbs([
        0xfffffffffffffffffffffffffffffc,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0xffffffffffffffffffffffffffffff,
        0x01ffffffffff,
    ]),
    b: Secp521r1_Fq::from_limbs([
        0x73df883d2c34f1ef451fd46b503f00,
        0x3951ec7e937b1652c0bd3bb1bf0735,
        0x5b99b315f3b8b489918ef109e15619,
        0x8e1c9a1f929a21a0b68540eea2da72,
        0x51953eb961,
    ]),
    one: [
        Secp521r1_Fq::from_limbs([
            0x48b3c1856a429bf97e7e31c2e5bd66,
            0x5e77efe75928fe1dc127a2ffa8de33,
            0x39053fb521f828af606b4d3dbaa14b,
            0x0404e9cd9e3ecb662395b4429c6481,
            0xc6858e06b7,
        ]),
        Secp521r1_Fq::from_limbs([
            0x3c7086a272c24088be94769fd16650,
            0x72995ef42640c550b9013fad076135,
            0x49579b446817afbd17273e662c97ee,
            0x9a3bc0045c8a5fb42c7d1bd998f544,
            0x011839296a78,
        ]),
    ],
    offset_generator: [
        Secp521r1_Fq::from_limbs([
            0x705db0a356a31751c08c9ad9239888,
            0xa6bd34be73dbcb9e5629721cbc8258,
            0xa8ee34e3dd9e2016d6826f192906c0,
            0x44e8d871ffa940799bb4863be9f94a,
            0x01b28faa22e6,
        ]),
        Secp521r1_Fq::from_limbs([
            0xcbbe2fcf69240150dec0714e01f62a,
            0x9a0dd6d808835a1c304e42308095ba,
            0x9c72ecfc7f5a8a0c4ea1b0f1d0c384,
            0x2cdfef65874ff5e72ee300d484f522,
            0xe6a8e44e68,
        ]),
    ],
    offset_generator_final: [
        Secp521r1_Fq::from_limbs([
            0xf2d67a119f1c1e7d9a820df897b869,
            0xc65ca29d23e3a2342f1faae7839342,
            0x8192077f6c30fa407c23d4f08c3ddc,
            0xab12bc6dc79aa4efe6fd1a1f72e02f,
            0x010a533ab82c,
        ]),
        Secp521r1_Fq::from_limbs([
            0xc3f6751abb32fa5179da76f2030266,
            0x01a0df142459e4740244c791830174,
            0x35c85a543fabaf81667c37d2392799,
            0x5191a7a8c9d46a5aa7e6952faee952,
            0x014914e8acad,
        ]),
    ],
};

pub global SECP521r1_SCALAR_SLICES: u32 = 131;
pub type Secp521r1Scalar = ScalarField<SECP521r1_SCALAR_SLICES>;

#[derive_curve_impl(quote { bignum::Secp521r1_Fq }, quote { SECP521r1_PARAM })]
pub struct Secp521r1 {
    pub x: Secp521r1_Fq,
    pub y: Secp521r1_Fq,
    pub is_infinity: bool,
}

mod test {
    use bignum::{BigNum, Secp521r1_Fq, Secp521r1_Fr};
    use std::ops::Neg;

    use crate::bigcurve::BigCurve;

    use super::{Secp521r1, SECP521r1_SCALAR_SLICES, Secp521r1Scalar};

    #[test]
    fn check_num_scalar_slices_in_scalar_field() {
        let x = Secp521r1_Fq::zero();
        let max_wnaf_bits: u32 = x.modulus_bits() + 1;

        let scalar_slices = (max_wnaf_bits / 4) + (max_wnaf_bits % 4 != 0) as u32;
        assert(scalar_slices == SECP521r1_SCALAR_SLICES);
    }

    #[test]
    fn test_offset_generators() {
        let one = Secp521r1::one();
        let negone = Secp521r1_Fr::one().neg();
        let scalar = Secp521r1Scalar::from_bignum(negone);
        let final = one.mul(scalar);

        assert(final.eq(one.neg()));
    }

    #[test]
    fn test_hash_to_curve() {
        let r = Secp521r1::hash_to_curve("hello world".as_bytes());

        r.validate_on_curve();
    }

    #[test]
    fn test_msm() {
        let four = Secp521r1_Fr::from(4);
        let p_minus_4_fr = Secp521r1_Fr::modulus() - four;
        let p_minus_4 = Secp521r1Scalar::from_bignum(p_minus_4_fr);
        let p_minus_5_fr = p_minus_4_fr - Secp521r1_Fr::one();
        let p_minus_5 = Secp521r1Scalar::from_bignum(p_minus_5_fr);
        let scalars = [p_minus_4, p_minus_5];
        let a = Secp521r1::one();
        let b = a.neg();
        let points = [a, b];

        let result =
            Secp521r1::evaluate_linear_expression(points, scalars, [Secp521r1::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn verify_offset_generators() {
        // Secp521r1 cofactor is 1
        crate::utils::derive_offset_generators::verify_offset_generators::<Secp521r1_Fq, SECP521r1_SCALAR_SLICES, Secp521r1>(
            1,
        );
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: Secp521r1_Fr = Secp521r1_Fr::derive_from_seed(seed);
        let scalar_field = Secp521r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
