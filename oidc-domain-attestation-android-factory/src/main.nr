// oidc_domain_attestation -- the Android FACTORY package.
//
// The same circuit id, public inputs, OIDC provider-key statement and nullifier as
// ../oidc-domain-attestation-android (and its iPhone/server package); only who signed the
// statement differs: an Android phone whose attestation key was provisioned
// at the factory (devices launched with Android 12 or earlier), proven by its
// key attestation chain under Google's RSA root AND a Google Play Integrity
// verdict bound to the statement (../statement-signer
// verify_statement_android_factory), as zkPassport's Android FaceMatch
// circuit pairs them (decided 2026-10-28, user: Android 12 and earlier must
// be supported). Phones with Remote Key Provisioning use ../oidc-domain-attestation-android,
// which needs no verdict and no server.

use oidc_libs::{
    check_claims, check_modes, MAX_DOMAIN_LENGTH, MAX_PARTIAL_DATA_LENGTH, provider_key, verify_jwt,
};
use statement_signer::{
    BATCH_TBS_MAX_LEN, FactoryChain, IK_TBS_MAX_LEN, IntegrityToken, LEAF_TBS_MAX_LEN,
    PAYLOAD_B64_MAX_LEN, RSA4096_LIMBS, verify_statement_android_factory,
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
    // The provider-key statement's signature by an Android key (P-256 r || s,
    // s in low form, SHA256withECDSA over the 313-byte statement), and the
    // Android key attestation chain below Google's pinned root that vouches
    // for that key (../statement-signer verify_statement_android).
    statement_sig: [u8; 64],
    ik_tbs: [u8; IK_TBS_MAX_LEN],
    ik_tbs_len: u32,
    ik_sig: [u128; RSA4096_LIMBS],
    batch_tbs: [u8; BATCH_TBS_MAX_LEN],
    batch_tbs_len: u32,
    batch_sig: [u8; 96],
    leaf_tbs: [u8; LEAF_TBS_MAX_LEN],
    leaf_tbs_len: u32,
    leaf_sig: [u8; 64],
    // Google Play's integrity verdict for this statement: the JWS payload as
    // signed (base64url, zero-padded) and Google's ES256 signature, r || s.
    integrity_payload_b64: [u8; PAYLOAD_B64_MAX_LEN],
    integrity_payload_b64_len: u32,
    integrity_signature: [u8; 64],
    rsa_root_modulus: [u128; RSA4096_LIMBS],
    rsa_root_redc: [u128; RSA4096_LIMBS],
    // Google's RSA root and our app's Play Integrity verification key, as
    // prover inputs pinned by hash in ../statement-signer (Barretenberg cannot
    // build them as constants; see verify_statement_android_factory).
    play_integrity_key: [u8; 64],
) {
    check_modes(provider, nonce_mode);

    // PART 1: JWT RSA signature
    verify_jwt(
        partial_data,
        partial_hash,
        full_data_length,
        base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
    );

    // PART 1b: an Android phone running our app vouched for the provider key
    verify_statement_android_factory(
        provider_key::statement(provider, now, pubkey_modulus_limbs),
        statement_sig,
        FactoryChain {
            ik_tbs,
            ik_tbs_len,
            ik_sig,
            batch_tbs,
            batch_tbs_len,
            batch_sig,
            leaf_tbs,
            leaf_tbs_len,
            leaf_sig,
        },
        IntegrityToken {
            payload_b64: integrity_payload_b64,
            payload_b64_len: integrity_payload_b64_len,
            signature: integrity_signature,
        },
        rsa_root_modulus,
        rsa_root_redc,
        play_integrity_key,
    );

    // PARTS 2-4: claims, domain, nullifier
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
