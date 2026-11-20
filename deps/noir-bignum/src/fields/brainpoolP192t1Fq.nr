use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global BrainpoolP192t1_Fq_PARAMS: BigNumParams<2, 192> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0xa3463093d18db78fce476de1a86297, 0xc302f41d932a36cda7],
    double_modulus: [0x01468c6127a31b6f1f9c8edbc350c52e, 0x018605e83b26546d9b4e],
    redc_param: [0xf0bf7091881dd98e7fb3c42c6b02bb, 0x5403fa8e7fc5ca3219d6],
};

#[derive_bignum(2, 192, quote { BrainpoolP192t1_Fq_PARAMS })]
pub struct BrainpoolP192t1_Fq {
    limbs: [u128; 2],
}
