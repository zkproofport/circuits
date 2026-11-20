use crate::bignum::BigNum;
use crate::bignum::derive_bignum;
use crate::params::BigNumParams;

pub global BrainpoolP384r1_Fr_PARAMS: BigNumParams<4, 384> = BigNumParams {
    has_multiplicative_inverse: true,
    modulus: [
        0x3ab6af6b7fc3103b883202e9046565,
        0x7109ed5456b31f166e6cac0425a7cf,
        0x82a3386d280f5d6f7e50e641df152f,
        0x8cb91e,
    ],
    double_modulus: [
        0x01756d5ed6ff862077106405d208caca,
        0x01e213daa8ad663e2cdcd958084b4f9d,
        0x01054670da501ebadefca1cc83be2a5d,
        0x0119723c,
    ],
    redc_param: [
        0xf6d19e9948425802b7333e29c7e285,
        0x1272b95bb87141bcbf85940c79c627,
        0x5b63b1ae3fc96b7f4f31be997768b1,
        0x746d5d6c,
    ],
};

#[derive_bignum(4, 384, quote { BrainpoolP384r1_Fr_PARAMS })]
pub struct BrainpoolP384r1_Fr {
    limbs: [u128; 4],
}
