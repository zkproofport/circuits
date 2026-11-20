use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global BrainpoolP256t1_Fr_PARAMS: BigNumParams<3, 256> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0x397aa3b561a6f7901e0e82974856a7, 0x57dba1eea9bc3e660a909d838d718c, 0xa9fb],
    double_modulus: [
        0x0172f5476ac34def203c1d052e90ad4e,
        0x01afb743dd53787ccc15213b071ae317,
        0x0153f5,
    ],
    redc_param: [0x22317f7d57a9435ced1b33441c584, 0x4c687156dfaedceaea0c8a9efd26fc, 0x606304],
};

#[derive_bignum(3, 256, quote { BrainpoolP256t1_Fr_PARAMS })]
pub struct BrainpoolP256t1_Fr {
    limbs: [u128; 3],
}
