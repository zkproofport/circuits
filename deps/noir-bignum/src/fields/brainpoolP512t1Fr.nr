use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global BrainpoolP512t1_Fr_PARAMS: BigNumParams<5, 512> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [
        0xb1d381085ddaddb58796829ca90069,
        0x5c414ca92619418661197fac10471d,
        0xb3b3c9d20ed6639cca70330870553e,
        0xdbe9c48b3fd4e6ae33c9fc07cb308d,
        0xaadd9db8,
    ],
    double_modulus: [
        0x0163a70210bbb5bb6b0f2d05395200d2,
        0x01b88299524c32830cc232ff58208e3a,
        0x01676793a41dacc73994e06610e0aa7b,
        0x01b7d389167fa9cd5c6793f80f96611a,
        0x0155bb3b70,
    ],
    redc_param: [
        0xc364057571338bebeb1936d5f6cdfe,
        0x318688d75127fce3d7d67b91c403ab,
        0x33113bc2599ab63cbd6fe4bdf6e51c,
        0xb6bae285757a8bc0d18787a0dcebd8,
        0x5fe35fd3b5,
    ],
};

#[derive_bignum(5, 512, quote { BrainpoolP512t1_Fr_PARAMS })]
pub struct BrainpoolP512t1_Fr {
    limbs: [u128; 5],
}
