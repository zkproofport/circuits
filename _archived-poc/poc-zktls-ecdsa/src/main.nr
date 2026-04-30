// PoC: smallest possible ECDSA P-384 verify circuit
// Goal: measure gate count for a single P-384 signature verification
// Reference: ZKPassport noir-ecdsa test_secp384r1_signature_verification
// Why: AWS Nitro attestation cert chain is 4-deep ECDSA P-384 + SHA-384.
// single verify gates x 4 + SHA = realistic estimate for Module 2.

use bigcurve::curves::secp384r1::{Secp384r1_Fq, Secp384r1_Fr};
use bignum::BigNum;
use noir_ecdsa::ecdsa::verify_secp384r1_ecdsa;
use sha256::sha256_var;

fn main(
    public_key_x_limbs: pub [u128; 4],
    public_key_y_limbs: pub [u128; 4],
    sig_r_limbs: pub [u128; 4],
    sig_s_limbs: pub [u128; 4],
    message_hash: pub [u8; 32],
) {
    let public_key_x: Secp384r1_Fq = BigNum::from_limbs(public_key_x_limbs);
    let public_key_y: Secp384r1_Fq = BigNum::from_limbs(public_key_y_limbs);
    let r: Secp384r1_Fr = BigNum::from_limbs(sig_r_limbs);
    let s: Secp384r1_Fr = BigNum::from_limbs(sig_s_limbs);

    assert(verify_secp384r1_ecdsa(public_key_x, public_key_y, message_hash, (r, s)));
}

#[test]
fn test_p384_verify_known_vector() {
    let msg: [u8; 31] = [
        72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33, 32, 84, 104, 105, 115, 32, 105,
        115, 32, 78, 111, 105, 114, 45, 69, 67, 68, 83, 65,
    ];
    let sha256_hash: [u8; 32] = sha256_var(msg, 31);

    let r: Secp384r1_Fr = BigNum::from_limbs([
        0xeb06adc631cd09d17ed3268f65e288,
        0x4102680df5a59b6fc9f8f38cd01016,
        0x272042bb400a185ba04fefaa7c05ce,
        0x680dc4,
    ]);
    let s: Secp384r1_Fr = BigNum::from_limbs([
        0x711084a23ae842fc0e6702c3009784,
        0xe17e64a3c451466091c4c1aae7550f,
        0x017a18c55fc11347e0f27fa8fdb958,
        0x32ec1b,
    ]);
    let pk_x: Secp384r1_Fq = BigNum::from_limbs([
        0x4bb414953ec1391fdbc6ea75e0d61a,
        0xfed1f2c9f9ac404d4bf5c0b267cddb,
        0xd1031dd17188527bc28ade5c97d23c,
        0x41b3d3,
    ]);
    let pk_y: Secp384r1_Fq = BigNum::from_limbs([
        0x23db4726c61ec970c07ff770a2b380,
        0x3270662d9105998b8e26e9575147da,
        0x33e912de6612af790c627629f33de0,
        0x4b834d,
    ]);
    assert(verify_secp384r1_ecdsa(pk_x, pk_y, sha256_hash, (r, s)));
}
