use crate::BigCurve;
use crate::BigCurveParams;
use crate::derive_curve_impl;
use crate::scalar_field::ScalarField;
use bignum::BigNum;
pub use bignum::{Secp521r1_Fq, Secp521r1_Fr};

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
            0x404e9cd9e3ecb662395b4429c6481,
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
            0x556e6521a2e048b585bd4221787414,
            0xd054f5d5317edea39eac7c0cdc4338,
            0x1317c4d27d768ef84cbe5b656be8c7,
            0x1f171c2c85cf6432bc4cc735794aff,
            0x019239eeece5,
        ]),
        Secp521r1_Fq::from_limbs([
            0x7a162ee85cbddff40688824e850caa,
            0xcf8f5428560f64e195da7cdcceb42a,
            0x36d91a939cab0b7cb093f4f586ff4a,
            0xc05642261499a58d74752ac95a0058,
            0x0145ca767742,
        ]),
    ],
    offset_generator_final: [
        Secp521r1_Fq::from_limbs([
            0xb483f5efbac1cf69bca8bddc4dc26e,
            0x02ad53022131b99528a619ead7e675,
            0xd1889b76dfdd29015488507df6ad3b,
            0x2f876099900e5e458a3c978bef39be,
            0x01260121e9f4,
        ]),
        Secp521r1_Fq::from_limbs([
            0xedccb160310b14dae3a8faf4550e8a,
            0x106d88c2d6a0a6f50d6609bc7e1a80,
            0x053a8d8f0a56d8b08ae5482fdf2206,
            0x84659f411d8392905aa718aa9b36c0,
            0xb281ae4c0d,
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

    use crate::BigCurve;
    use super::Secp521r1;
    use super::SECP521r1_SCALAR_SLICES;
    use super::Secp521r1Scalar;

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
        let mut scalars = [p_minus_4, p_minus_5];
        let a = Secp521r1::one();
        let b = a.neg();
        let mut points = [a, b];

        let result =
            Secp521r1::evaluate_linear_expression(points, scalars, [Secp521r1::one().neg()]);

        assert(result.is_infinity);
    }

    #[test]
    unconstrained fn test_scalar_field_conversion(seed: [u8; 10]) {
        let num: Secp521r1_Fr = Secp521r1_Fr::derive_from_seed(seed);
        let scalar_field = Secp521r1Scalar::from_bignum(num);
        let bignum = scalar_field.into_bignum();
        assert(bignum == num);
    }
}
