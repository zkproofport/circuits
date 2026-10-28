// Probe: one RSA-4096 PKCS#1 v1.5 SHA-256 verification with the modulus a witness.
use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::rsa::verify_sha256_pkcs1v15;
fn main(h: [u8; 32], m: [u128; 35], r: [u128; 35], s: [u128; 35]) {
    let params: BigNumParams<35, 4096> = BigNumParams::new(false, m, r);
    let sig: RuntimeBigNum<35, 4096> = RuntimeBigNum { params, limbs: s };
    assert(verify_sha256_pkcs1v15(h, sig, 65537));
}
