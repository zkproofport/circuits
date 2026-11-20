use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global Secp192r1_Fq_PARAMS: BigNumParams<2, 192> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0xfffffffffffffeffffffffffffffff, 0xffffffffffffffffff],
    double_modulus: [0x01fffffffffffffdfffffffffffffffe, 0x01fffffffffffffffffe],
    redc_param: [0x400000000000000040, 0x40000000000000000000],
};

#[derive_bignum(2, 192, quote { Secp192r1_Fq_PARAMS })]
pub struct Secp192r1_Fq {
    limbs: [u128; 2],
}
