// Apple App Attest, verified in a circuit: "a genuine instance of this app,
// on a genuine Apple device, signed this clientData".
//
// The chain is Apple root -> App Attest intermediate CA -> credential
// certificate (one per app key) -> assertion (one per request). The caller
// pins ONLY the root key (a circuit constant); every link below it is
// verified here from private inputs, the way zkPassport verifies FaceMatch.
// So Apple replacing the intermediate changes nothing in the circuit.

pub mod der;
pub mod intermediate;
pub mod credential;
pub mod assertion;
mod tests;

use intermediate::{parse_intermediate_tbs, verify_intermediate_signature};
use credential::{parse_credential_tbs, verify_credential_signature};
use assertion::{assertion_digest, check_attestation_auth_data};

pub use intermediate::INTERMEDIATE_TBS_MAX_LEN;
pub use credential::CREDENTIAL_TBS_MAX_LEN;
pub use assertion::{ASSERT_AUTH_DATA_MAX_LEN, ATT_AUTH_DATA_MAX_LEN};

/// Everything a device contributes to one App Attest statement, except the
/// assertion signature itself (the caller verifies that, so one P-256 check
/// can serve more than one kind of signer).
pub struct AppAttestChain<let ITBS: u32, let TBS: u32, let ATT: u32, let ASSERT: u32> {
    /// The intermediate CA certificate's TBS (zero-padded) and the root's
    /// signature over it, r || s, s in low form.
    pub intermediate_tbs: [u8; ITBS],
    pub intermediate_tbs_len: u32,
    pub intermediate_sig: [u8; 96],
    /// The credential certificate's TBS (zero-padded) and the intermediate's
    /// signature over it, r || s, s in low form.
    pub credential_tbs: [u8; TBS],
    pub credential_tbs_len: u32,
    pub credential_sig: [u8; 96],
    /// The attestation object's authData and the clientDataHash it was made
    /// with (SHA256 of the attestation challenge). Kept by the app.
    pub att_auth_data: [u8; ATT],
    pub att_auth_data_len: u32,
    pub att_client_data_hash: [u8; 32],
    /// The assertion's authenticatorData (zero-padded).
    pub assertion_auth_data: [u8; ASSERT],
    pub assertion_auth_data_len: u32,
}

/// The credential key, the digest it must have signed for `client_data_hash`,
/// and the assertion counter. Asserts every link from `root` down:
///   root --SHA-384/P-384--> intermediate (a CA, P-384 key)
///        --SHA-256/P-384--> credential certificate (our App ID, P-256 key,
///                           Apple's nonce)
///   attestation authData hashes to that nonce, is for our app, counter 0,
///   AAGUID of the requested environment
///   assertion authData is for our app, counter > 0
pub fn app_attest_signing_key<let ITBS: u32, let TBS: u32, let ATT: u32, let ASSERT: u32, let A: u32>(
    chain: AppAttestChain<ITBS, TBS, ATT, ASSERT>,
    root_x: [u8; 48],
    root_y: [u8; 48],
    app_id: [u8; A],
    app_id_hash: [u8; 32],
    production: bool,
    client_data_hash: [u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32], u32) {
    // A caller that branches (coinbase-attestation-v2's server kind passes
    // zeros here) gets a named refusal instead of the first library assert
    // the zeros happen to trip.
    assert(chain.intermediate_tbs_len != 0, "No App Attest certificate chain");
    let mut r: [u8; 48] = [0; 48];
    let mut s: [u8; 48] = [0; 48];
    for i in 0..48 {
        r[i] = chain.intermediate_sig[i];
        s[i] = chain.intermediate_sig[48 + i];
    }
    assert(
        verify_intermediate_signature(
            root_x,
            root_y,
            chain.intermediate_tbs,
            chain.intermediate_tbs_len,
            r,
            s,
        ),
        "Intermediate is not signed by Apple's App Attestation root",
    );
    let ca = parse_intermediate_tbs(chain.intermediate_tbs, chain.intermediate_tbs_len);

    for i in 0..48 {
        r[i] = chain.credential_sig[i];
        s[i] = chain.credential_sig[48 + i];
    }
    assert(
        verify_credential_signature(
            ca.x,
            ca.y,
            chain.credential_tbs,
            chain.credential_tbs_len,
            r,
            s,
        ),
        "Credential certificate is not signed by the App Attest intermediate",
    );

    let key = parse_credential_tbs(chain.credential_tbs, chain.credential_tbs_len, app_id);

    check_attestation_auth_data(
        chain.att_auth_data,
        chain.att_auth_data_len,
        chain.att_client_data_hash,
        key.nonce,
        app_id_hash,
        production,
    );

    let (digest, counter) = assertion_digest(
        chain.assertion_auth_data,
        chain.assertion_auth_data_len,
        client_data_hash,
        app_id_hash,
    );
    (key.x, key.y, digest, counter)
}
