use dep::jwt::JWT;
use dep::keccak256::keccak256;

global MAX_PARTIAL_DATA_LENGTH: u32 = 640;
global MAX_DOMAIN_LENGTH: u32 = 64;
global MAX_EMAIL_LENGTH: u32 = 128;

fn main(
    // ============ Public Inputs ============

    // RSA public key (identifies OIDC provider)
    pubkey_modulus_limbs: pub [u128; 18],

    // Domain to prove (e.g., "google.com")
    domain: pub BoundedVec<u8, MAX_DOMAIN_LENGTH>,

    // Sybil resistance
    scope: pub [u8; 32],
    nullifier: pub [u8; 32],

    // ============ Private Inputs ============

    // JWT data (Partial SHA)
    partial_data: BoundedVec<u8, MAX_PARTIAL_DATA_LENGTH>,
    partial_hash: [u32; 8],
    full_data_length: u32,
    base64_decode_offset: u32,

    // RSA signature
    redc_params_limbs: [u128; 18],
    signature_limbs: [u128; 18],
) {
    // ========================================
    // PART 1: JWT RSA Signature Verification
    // ========================================
    let jwt: JWT<MAX_PARTIAL_DATA_LENGTH> = JWT::init_with_partial_hash(
        partial_data,
        partial_hash,
        full_data_length,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );
    jwt.verify();

    // ========================================
    // PART 2: Email Verification + Domain Extraction
    // ========================================
    jwt.assert_claim_bool("email_verified".as_bytes(), true);

    let email: BoundedVec<u8, MAX_EMAIL_LENGTH> =
        jwt.get_claim_string("email".as_bytes());

    let domain_start = unsafe { get_domain_start_index(email) };
    assert(email.storage()[domain_start - 1] == 64, "char before domain is not @");
    for i in 0..MAX_DOMAIN_LENGTH {
        if i < domain.len() {
            assert(
                email.storage()[domain_start + i] == domain.storage()[i],
                "domain mismatch",
            );
        }
    }
    // Assert remaining email chars after domain are zero (email ends at domain end)
    let email_len = email.len();
    assert(domain_start + domain.len() == email_len, "email has chars after domain");

    // ========================================
    // PART 3: Nullifier Verification
    // ========================================
    verify_nullifier(email, scope, nullifier);
}

fn verify_nullifier(
    email: BoundedVec<u8, MAX_EMAIL_LENGTH>,
    scope: [u8; 32],
    nullifier: [u8; 32],
) {
    let email_hash: [u8; 32] = keccak256(email.storage(), email.len() as u32);

    let mut preimage: [u8; 64] = [0; 64];
    for i in 0..32 {
        preimage[i] = email_hash[i];
    }
    for i in 0..32 {
        preimage[32 + i] = scope[i];
    }
    let expected: [u8; 32] = keccak256(preimage, 64);
    assert(nullifier == expected, "nullifier mismatch");
}

unconstrained fn get_domain_start_index(
    email: BoundedVec<u8, MAX_EMAIL_LENGTH>,
) -> u32 {
    let mut idx = 0;
    for i in 0..MAX_EMAIL_LENGTH {
        if email.storage()[i] == 64 {
            idx = i + 1;
        }
    }
    idx
}
