// Apple App Attest, verified in a circuit: "a genuine instance of this app,
// on a genuine Apple device, signed this clientData".
//
// The chain is Apple root -> App Attest intermediate CA -> credential
// certificate (one per app key) -> assertion (one per request). The first
// link is the same for every user, so it is verified OUTSIDE the circuit and
// enters only as `ca_key_hash` = SHA256(intermediate X || Y), a public input
// the verifier compares with the key it has checked against Apple's root.
// Everything below that link is per device and stays private.

pub mod der;
pub mod credential;
pub mod assertion;
mod tests;

use credential::{parse_credential_tbs, verify_credential_signature};
use assertion::{check_attestation_auth_data, verify_assertion};

pub use credential::CREDENTIAL_TBS_MAX_LEN;
pub use assertion::{ASSERT_AUTH_DATA_MAX_LEN, ATT_AUTH_DATA_MAX_LEN};

pub struct AppAttestInputs<let TBS: u32, let ATT: u32, let ASSERT: u32> {
    /// The intermediate CA's public key, X || Y (P-384). Private; only its
    /// hash is public.
    pub ca_key: [u8; 96],
    pub credential_tbs: [u8; TBS],
    pub credential_tbs_len: u32,
    /// The certificate's signature, r || s, s in low form.
    pub credential_sig: [u8; 96],
    /// The attestation object's authData and the clientDataHash it was made
    /// with (SHA256 of the attestation challenge). Kept by the app.
    pub att_auth_data: [u8; ATT],
    pub att_auth_data_len: u32,
    pub att_client_data_hash: [u8; 32],
    /// The assertion: authenticatorData and the P-256 signature (r || s,
    /// s in low form), from the DER signature in the assertion object.
    pub assertion_auth_data: [u8; ASSERT],
    pub assertion_auth_data_len: u32,
    pub assertion_sig: [u8; 64],
}

/// Verify the whole per-device chain and return the assertion counter.
/// `client_data` is whatever the caller's format is; it is bound only
/// through the assertion signature, so the caller checks its contents.
pub fn verify_app_attest<let TBS: u32, let ATT: u32, let ASSERT: u32, let A: u32, let C: u32>(
    inputs: AppAttestInputs<TBS, ATT, ASSERT>,
    ca_key_hash: [u8; 32],
    app_id: [u8; A],
    app_id_hash: [u8; 32],
    production: bool,
    client_data: [u8; C],
) -> u32 {
    assert(sha256::digest(inputs.ca_key) == ca_key_hash, "App Attest CA key does not match the public key hash");

    let mut ca_x: [u8; 48] = [0; 48];
    let mut ca_y: [u8; 48] = [0; 48];
    let mut r: [u8; 48] = [0; 48];
    let mut s: [u8; 48] = [0; 48];
    for i in 0..48 {
        ca_x[i] = inputs.ca_key[i];
        ca_y[i] = inputs.ca_key[48 + i];
        r[i] = inputs.credential_sig[i];
        s[i] = inputs.credential_sig[48 + i];
    }
    assert(
        verify_credential_signature(
            ca_x,
            ca_y,
            inputs.credential_tbs,
            inputs.credential_tbs_len,
            r,
            s,
        ),
        "Credential certificate is not signed by the App Attest CA key",
    );

    let key = parse_credential_tbs(inputs.credential_tbs, inputs.credential_tbs_len, app_id);

    check_attestation_auth_data(
        inputs.att_auth_data,
        inputs.att_auth_data_len,
        inputs.att_client_data_hash,
        key.nonce,
        app_id_hash,
        production,
    );

    verify_assertion(
        key.x,
        key.y,
        inputs.assertion_auth_data,
        inputs.assertion_auth_data_len,
        client_data,
        inputs.assertion_sig,
        app_id_hash,
    )
}
