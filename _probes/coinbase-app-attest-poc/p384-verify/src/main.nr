use bignum::bignum::BigNum;
use bignum::fields::secp384r1Fq::Secp384r1_Fq;
use bignum::fields::secp384r1Fr::Secp384r1_Fr;
use ecdsa::ecdsa::verify_secp384r1_ecdsa;

fn main(x: [u8; 48], y: [u8; 48], r: [u8; 48], s: [u8; 48], digest: [u8; 32]) {
    let px: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(x);
    let py: Secp384r1_Fq = Secp384r1_Fq::from_be_bytes(y);
    let rr: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(r);
    let ss: Secp384r1_Fr = Secp384r1_Fr::from_be_bytes(s);
    assert(verify_secp384r1_ecdsa(px, py, digest, (rr, ss)));
}
