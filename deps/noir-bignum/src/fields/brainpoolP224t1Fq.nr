use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global BrainpoolP224t1_Fq_PARAMS: BigNumParams<2, 224> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [0xd1d787b09f075797da89f57ec8c0ff, 0xd7c134aa264366862a18302575],
    double_modulus: [0x01a3af0f613e0eaf2fb513eafd9181fe, 0x01af8269544c86cd0c5430604aea],
    redc_param: [0x7a3f4cf69e13fbd837136cdbd7d3c1, 0x4bf0267de3f488a65387550fd80f],
};

#[derive_bignum(2, 224, quote { BrainpoolP224t1_Fq_PARAMS })]
pub struct BrainpoolP224t1_Fq {
    limbs: [u128; 2],
}
