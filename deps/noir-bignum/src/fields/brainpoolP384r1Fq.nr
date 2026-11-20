use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global BrainpoolP384r1_Fq_PARAMS: BigNumParams<4, 384> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [
        0xd3a729901d1a71874700133107ec53,
        0x7109ed5456b412b1da197fb71123ac,
        0x82a3386d280f5d6f7e50e641df152f,
        0x8cb91e,
    ],
    double_modulus: [
        0x01a74e53203a34e30e8e0026620fd8a6,
        0x01e213daa8ad682563b432ff6e224758,
        0x01054670da501ebadefca1cc83be2a5d,
        0x0119723c,
    ],
    redc_param: [
        0xef381e9c559bc4280efda12899c598,
        0x1272b95bb7a7b56433bc7135c86411,
        0x5b63b1ae3fc96b7f4f31be997768b1,
        0x746d5d6c,
    ],
};

#[derive_bignum(4, 384, quote { BrainpoolP384r1_Fq_PARAMS })]
pub struct BrainpoolP384r1_Fq {
    limbs: [u128; 4],
}
