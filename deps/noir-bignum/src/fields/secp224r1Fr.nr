use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global Secp224r1_Fr_PARAMS: BigNumParams<2, 224> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0xff16a2e0b8f03e13dd29455c5c2a3d, 0xffffffffffffffffffffffffff],
    double_modulus: [0x01fe2d45c171e07c27ba528ab8b8547a, 0x01fffffffffffffffffffffffffe],
    redc_param: [0x3a5747d1c3f07b08b5aea8e8f570f5, 0x4000000000000000000000000000],
};

#[derive_bignum(2, 224, quote { Secp224r1_Fr_PARAMS })]
pub struct Secp224r1_Fr {
    limbs: [u128; 2],
}
