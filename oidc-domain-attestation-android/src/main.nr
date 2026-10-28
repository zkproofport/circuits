// oidc_domain_attestation -- the Android package.
//
// The same circuit id, public inputs, provider-key statement and nullifier as
// ../oidc-domain-attestation (everything about the token is ../oidc-libs);
// only who vouched for the provider key differs: an Android phone's
// hardware-backed key, proven by Android key attestation
// (../statement-signer verify_statement_android, ../android-key-attestation).
// A separate package because that chain is 1,167,923 gates and would make
// every iPhone and server proof 2^21 as a third signer kind (decided
// 2026-10-28, .claude/agents/circuits-dev.md "Android signer").
//
// `now` is also the time the chain's certificates must be valid at: the
// verifier bounds `now` against its own clock, as it already does for the
// token's iat/exp.

use oidc_libs::{
    check_claims, check_modes, MAX_DOMAIN_LENGTH, MAX_PARTIAL_DATA_LENGTH, provider_key, verify_jwt,
};
use statement_signer::{
    AndroidChain, ATT_TBS_MAX_LEN, CA2_TBS_MAX_LEN, CA3_TBS_MAX_LEN, LEAF_TBS_MAX_LEN,
    verify_statement_android,
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
    ca2_tbs: [u8; CA2_TBS_MAX_LEN],
    ca2_tbs_len: u32,
    ca2_sig: [u8; 96],
    ca3_tbs: [u8; CA3_TBS_MAX_LEN],
    ca3_tbs_len: u32,
    ca3_sig: [u8; 96],
    att_tbs: [u8; ATT_TBS_MAX_LEN],
    att_tbs_len: u32,
    att_sig: [u8; 64],
    leaf_tbs: [u8; LEAF_TBS_MAX_LEN],
    leaf_tbs_len: u32,
    leaf_sig: [u8; 64],
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
    verify_statement_android(
        provider_key::statement(provider, now, pubkey_modulus_limbs),
        statement_sig,
        AndroidChain {
            ca2_tbs,
            ca2_tbs_len,
            ca2_sig,
            ca3_tbs,
            ca3_tbs_len,
            ca3_sig,
            att_tbs,
            att_tbs_len,
            att_sig,
            leaf_tbs,
            leaf_tbs_len,
            leaf_sig,
        },
        now,
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
