use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global BrainpoolP224t1_Fr_PARAMS: BigNumParams<2, 224> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0xd0fb98d116bc4b6ddebca3a5a7939f, 0xd7c134aa264366862a18302575],
    double_modulus: [0x01a1f731a22d7896dbbd79474b4f273e, 0x01af8269544c86cd0c5430604aea],
    redc_param: [0xc7a7efb856f0d642a534c72296e856, 0x4bf0267de3f488a65387550fd80f],
};

#[derive_bignum(2, 224, quote { BrainpoolP224t1_Fr_PARAMS })]
pub struct BrainpoolP224t1_Fr {
    limbs: [u128; 2],
}
