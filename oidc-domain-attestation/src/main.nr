mod claims;

use jwt::JWT;
use keccak256::keccak256;

// header tail (< 64 bytes, so the `.` stays in) + the whole base64url payload.
// Sized in README.md "Token layout".
global MAX_PARTIAL_DATA_LENGTH: u32 = 2048;
global MAX_DOMAIN_LENGTH: u32 = 64;
global MAX_EMAIL_LENGTH: u32 = 128;
global MAX_AUD_LENGTH: u32 = 128;
global MAX_ISS_LENGTH: u32 = 128;
// 64 hex characters; one more so a longer nonce is read and refused by length
// instead of failing as an unterminated value.
global NONCE_HEX_LENGTH: u32 = 64;
global MAX_NONCE_LENGTH: u32 = 65;

// Provider constants
global PROVIDER_GOOGLE: u8 = 0;
global PROVIDER_MICROSOFT: u8 = 1;

global NONCE_MODE_NONE: u8 = 0;
global NONCE_MODE_BOUND: u8 = 1;

global MS_ISS_PREFIX_LENGTH: u32 = 34; // "https://login.microsoftonline.com/"
global MS_ISS_LENGTH: u32 = 75; // prefix + 36-character tenant GUID + "/v2.0"

fn main(
    // ============ Public Inputs ============
    // Offsets 0-147 are unchanged from v1; v2 appends after `provider`.

    // RSA public key (identifies OIDC provider)
    pubkey_modulus_limbs: pub [u128; 18],

    // Domain to prove (e.g., "google.com")
    domain: pub BoundedVec<u8, MAX_DOMAIN_LENGTH>,

    // Sybil resistance
    scope: pub [u8; 32],
    nullifier: pub [u8; 32],

    // OIDC provider (0 = Google, 1 = Microsoft)
    provider: pub u8,

    // keccak256 of the token's `aud` string. The verifier checks it against
    // the client ids it accepts.
    aud_hash: pub [u8; 32],

    // 1 = the token's `nonce` claim is the lowercase hex of nonce_binding;
    // 0 = no nonce is bound (device flow) and nonce_binding is all zero.
    nonce_mode: pub u8,
    nonce_binding: pub [u8; 32],

    // Unix seconds the proof claims to be made at: iat <= now < exp. The
    // verifier decides how far `now` may be from its own clock.
    now: pub u64,

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
    // Validate provider
    assert(
        (provider == PROVIDER_GOOGLE) | (provider == PROVIDER_MICROSOFT),
        "unsupported provider: must be 0 (Google) or 1 (Microsoft)",
    );
    assert(
        (nonce_mode == NONCE_MODE_NONE) | (nonce_mode == NONCE_MODE_BOUND),
        "unsupported nonce_mode: must be 0 (none) or 1 (bound)",
    );

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

    let payload = claims::decode_payload(partial_data, base64_decode_offset);

    // ========================================
    // PART 2: Issuer, audience, freshness, nonce
    // ========================================
    let iss: BoundedVec<u8, MAX_ISS_LENGTH> = claims::string_claim(payload, "iss".as_bytes());
    if provider == PROVIDER_MICROSOFT {
        assert(is_microsoft_v2_issuer(iss), "iss is not a Microsoft v2.0 tenant issuer");
    } else {
        assert(is_google_issuer(iss), "iss is not Google");
    }

    let aud: BoundedVec<u8, MAX_AUD_LENGTH> = claims::string_claim(payload, "aud".as_bytes());
    assert(aud.len() > 0, "aud is empty");
    assert(keccak256(aud.storage(), aud.len()) == aud_hash, "aud does not match aud_hash");

    let iat = claims::number_claim(payload, "iat".as_bytes());
    let exp = claims::number_claim(payload, "exp".as_bytes());
    assert(iat <= now, "token issued after now");
    assert(now < exp, "token expired at now");

    if nonce_mode == NONCE_MODE_BOUND {
        let nonce: BoundedVec<u8, MAX_NONCE_LENGTH> =
            claims::string_claim(payload, "nonce".as_bytes());
        assert(nonce.len() == NONCE_HEX_LENGTH, "nonce claim is not 64 characters");
        for i in 0..32 {
            let b = nonce_binding[i];
            assert(
                (nonce.storage()[2 * i] == hex_digit(b >> 4))
                    & (nonce.storage()[2 * i + 1] == hex_digit(b & 15)),
                "nonce claim does not match nonce_binding",
            );
        }
    } else {
        assert(nonce_binding == [0; 32], "nonce_binding must be zero when nonce_mode is 0");
    }

    // ========================================
    // PART 3: Email Verification + Domain Extraction
    // ========================================
    // Google: email_verified claim, Microsoft: xms_edov claim
    if provider == PROVIDER_MICROSOFT {
        assert(claims::bool_claim(payload, "xms_edov".as_bytes()), "xms_edov is not true");
    } else {
        assert(
            claims::bool_claim(payload, "email_verified".as_bytes()),
            "email_verified is not true",
        );
    }

    let email: BoundedVec<u8, MAX_EMAIL_LENGTH> =
        claims::string_claim(payload, "email".as_bytes());

    // Safety: the byte before the returned index is asserted to be '@' and the
    // rest of the email is asserted to equal the public domain.
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
    // PART 4: Nullifier Verification
    // ========================================
    verify_nullifier(email, scope, nullifier);
}

// Google documents both spellings: https://developers.google.com/identity/openid-connect/openid-connect
fn is_google_issuer(iss: BoundedVec<u8, MAX_ISS_LENGTH>) -> bool {
    claims::equals(iss, "https://accounts.google.com".as_bytes())
        | claims::equals(iss, "accounts.google.com".as_bytes())
}

// https://login.microsoftonline.com/{tenant GUID}/v2.0, the GUID lowercase
// 8-4-4-4-12 hex. v1.0 issuers (sts.windows.net) are not accepted.
fn is_microsoft_v2_issuer(iss: BoundedVec<u8, MAX_ISS_LENGTH>) -> bool {
    let prefix = "https://login.microsoftonline.com/".as_bytes();
    let suffix = "/v2.0".as_bytes();
    let s = iss.storage();
    let mut ok = iss.len() == MS_ISS_LENGTH;
    for i in 0..MS_ISS_PREFIX_LENGTH {
        ok = ok & (s[i] == prefix[i]);
    }
    for i in 0..36 {
        let c = s[MS_ISS_PREFIX_LENGTH + i];
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) {
            ok = ok & (c == 45); // -
        } else {
            ok = ok & (((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)));
        }
    }
    for i in 0..5 {
        ok = ok & (s[MS_ISS_PREFIX_LENGTH + 36 + i] == suffix[i]);
    }
    ok
}

fn hex_digit(nibble: u8) -> u8 {
    if nibble < 10 {
        nibble + 48
    } else {
        nibble + 87
    }
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
