// oidc_domain_attestation -- the iPhone (App Attest) and AI-server (Cloud
// KMS) package. Everything about the token is ../oidc-libs; this package adds
// who vouched for the provider key (../statement-signer). The Android package,
// ../oidc-domain-attestation-android, is the same circuit id with an Android
// key attestation signer instead.

use oidc_libs::{
    check_claims, check_modes, MAX_DOMAIN_LENGTH, MAX_PARTIAL_DATA_LENGTH, provider_key,
    verify_jwt,
};
use statement_signer::{
    ASSERT_AUTH_DATA_MAX_LEN, ATT_AUTH_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN, SignerChain,
    verify_statement,
};

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

    // Who vouched that pubkey_modulus_limbs is the provider's published key
    // (provider_key.nr): 1 = the phone (App Attest), 2 = the AI server (Cloud
    // KMS). Private; the proof does not say which.
    signer_kind: u8,
    // P-256 r || s, s in low form: the App Attest assertion signature (app)
    // or the server's signature (server), over the provider-key statement.
    statement_sig: [u8; 64],
    // App Attest chain below the pinned intermediate, exactly as in
    // coinbase_attestation v2. The server kind passes zeros for all of these.
    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    credential_tbs_len: u32,
    credential_sig: [u8; 96],
    att_auth_data: [u8; ATT_AUTH_DATA_MAX_LEN],
    att_auth_data_len: u32,
    att_client_data_hash: [u8; 32],
    assertion_auth_data: [u8; ASSERT_AUTH_DATA_MAX_LEN],
    assertion_auth_data_len: u32,
) {
    check_modes(provider, nonce_mode);

    // ========================================
    // PART 1: JWT RSA Signature Verification
    // ========================================
    verify_jwt(
        partial_data,
        partial_hash,
        full_data_length,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    // ========================================
    // PART 1b: the key is the provider's published key
    // ========================================
    // A signer we trust (app or server, ../statement-signer) compared this
    // modulus with the provider's live key list at `now` and signed the
    // provider-key statement; the statement is built here from public inputs.
    verify_statement(
        provider_key::statement(provider, now, pubkey_modulus_limbs),
        signer_kind,
        statement_sig,
        SignerChain {
            credential_tbs,
            credential_tbs_len,
            credential_sig,
            att_auth_data,
            att_auth_data_len,
            att_client_data_hash,
            assertion_auth_data,
            assertion_auth_data_len,
        },
    );

    // ========================================
    // PARTS 2-4: claims, domain, nullifier
    // ========================================
    check_claims(
        partial_data,
        base64_decode_offset,
        domain,
        scope,
        nullifier,
        provider,
        aud_hash,
        nonce_mode,
        nonce_binding,
        now,
    );
}
