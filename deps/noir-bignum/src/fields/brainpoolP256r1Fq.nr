use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global BrainpoolP256r1_Fq_PARAMS: BigNumParams<3, 256> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0x3bf623d52620282013481d1f6e5377, 0x57dba1eea9bc3e660a909d838d726e, 0xa9fb],
    double_modulus: [
        0x0177ec47aa4c40504026903a3edca6ee,
        0x01afb743dd53787ccc15213b071ae4db,
        0x0153f5,
    ],
    redc_param: [0xd5283fda8bea6d8ab98c046037431a, 0x4c687156dfaedceaea0c8a9efca6d3, 0x606304],
};

#[derive_bignum(3, 256, quote { BrainpoolP256r1_Fq_PARAMS })]
pub struct BrainpoolP256r1_Fq {
    limbs: [u128; 3],
}
