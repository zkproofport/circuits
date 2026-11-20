use bigcurve::BigCurve;
use bigcurve::curves::secp384r1::{Secp384r1, Secp384r1_Fq, Secp384r1_Fr};
use bigcurve::ScalarField;
use bignum::BigNum;

pub fn verify_ecdsa<let HASH_BYTE_SIZE: u32, let SCALAR_SLICES: u32, Fq, Fr, Curve>(
    public_key_x: Fq,
    public_key_y: Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Fr, Fr),
) -> bool
where
    Fr: BigNum,
    Fr: std::convert::From<Field>,
    Fr: std::cmp::Ord,
    Fq: BigNum,
    Curve: BigCurve<Fq>,
{
    let (r, s) = signature;
    let n = Fr::modulus();
    let n_half = n.udiv(Fr::from(2));
    assert(s <= n_half, "Signature s value is not in canonical form");

    let mut formatted_message_digest = Fr::zero().to_le_bytes();
    let mut startIndex = 0;
    if HASH_BYTE_SIZE < formatted_message_digest.len() {
        startIndex = formatted_message_digest.len() - HASH_BYTE_SIZE;
    }
    for i in startIndex..formatted_message_digest.len() {
        formatted_message_digest[i] = message_digest[i - startIndex];
    }
    let e: Fr = Fr::from_be_bytes(formatted_message_digest);

    let w = unsafe { s.__invmod() };
    assert(s * w == Fr::one());

    let u_1: ScalarField<SCALAR_SLICES> = ScalarField::from_bignum(e * w);
    let u_2: ScalarField<SCALAR_SLICES> = ScalarField::from_bignum(r * w);

    let public_key = Curve::from_coordinates(public_key_x, public_key_y, false);
    public_key.validate_on_curve();

    let gen = Curve::one();
    let r_point = Curve::evaluate_linear_expression([gen, public_key], [u_1, u_2], []);
    let r_point_x = r_point.x();
    let r_point_x_as_fr: Fr = Fr::from_limbs(r_point_x.get_limbs());
    r_point_x_as_fr == r
}

pub fn verify_secp384r1_ecdsa<let HASH_BYTE_SIZE: u32>(
    public_key_x: Secp384r1_Fq,
    public_key_y: Secp384r1_Fq,
    message_digest: [u8; HASH_BYTE_SIZE],
    signature: (Secp384r1_Fr, Secp384r1_Fr),
) -> bool {
    verify_ecdsa::<HASH_BYTE_SIZE, 97, Secp384r1_Fq, Secp384r1_Fr, Secp384r1>(
        public_key_x,
        public_key_y,
        message_digest,
        signature,
    )
}
