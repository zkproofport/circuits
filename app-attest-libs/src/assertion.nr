// The two authenticator-data checks: the attestation's (once per key, bound
// into the certificate by Apple's nonce) and the assertion's (once per proof,
// signed by the credential key).
//
// Apple's steps, from "Validating apps that connect to your server"
// (developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server):
//
//   attestation  nonce = SHA256(authData || clientDataHash) equals the 8.2
//                extension; RP ID hash = SHA256(App ID); counter = 0; aaguid
//                is "appattestdevelop" or "appattest" + seven zero bytes.
//   assertion    nonce = SHA256(authenticatorData || SHA256(clientData));
//                the signature is valid for nonce; RP ID hash = SHA256(App ID);
//                counter > previous (> 0 on the first).
//
// "Valid for nonce" means ECDSA-SHA256 over the 32-byte nonce, so the digest
// the curve sees is SHA256(nonce): the Secure Enclave hashes the message it is
// given. takimoto3/app-attest (assertion.go) verifies it that way.
//
// Both authenticator-data blobs are variable length: Apple's page now lists
// CBOR extensions (apple_validation_category_01, apple_bundle_version_01) in
// them. The circuit hashes whatever length is supplied and reads only the
// fixed WebAuthn prefix (rpIdHash 32, flags 1, signCount 4, then for the
// attestation aaguid 16). The extensions are NOT parsed here.

use crate::der::{bytes_at, slice_at};

pub global ATT_AUTH_DATA_MAX_LEN: u32 = 256;
pub global ASSERT_AUTH_DATA_MAX_LEN: u32 = 128;

/// "appattest" followed by seven zero bytes.
global AAGUID_PRODUCTION: [u8; 16] =
    [0x61, 0x70, 0x70, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0, 0, 0, 0, 0, 0, 0];
/// "appattestdevelop".
global AAGUID_DEVELOPMENT: [u8; 16] =
    [0x61, 0x70, 0x70, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70];

fn be32<let N: u32>(buf: [u8; N], pos: u32) -> u32 {
    ((buf[pos] as u32) << 24)
        | ((buf[pos + 1] as u32) << 16)
        | ((buf[pos + 2] as u32) << 8)
        | (buf[pos + 3] as u32)
}

/// buf[0..len] ++ tail, zero-padded, so a variable-length prefix can be hashed.
fn append_32<let N: u32>(buf: [u8; N], len: u32, tail: [u8; 32]) -> [u8; N + 32] {
    let mut out: [u8; N + 32] = [0; N + 32];
    for i in 0..N {
        if i < len {
            out[i] = buf[i];
        }
    }
    for i in 0..32 {
        out[len + i] = tail[i];
    }
    out
}

fn zero_past<let N: u32>(buf: [u8; N], len: u32) {
    for i in 0..N {
        if i >= len {
            assert(buf[i] == 0, "Authenticator data padding is not zero");
        }
    }
}

/// The attestation's authenticator data is the one Apple certified for this
/// key, is for this app, and comes from the environment the verifier asked for.
pub fn check_attestation_auth_data<let N: u32>(
    auth_data: [u8; N],
    auth_len: u32,
    client_data_hash: [u8; 32],
    cert_nonce: [u8; 32],
    app_id_hash: [u8; 32],
    production: bool,
) {
    // rpIdHash 32 + flags 1 + counter 4 + aaguid 16 + credIdLen 2 + credId 32
    // + COSE key 77 = 164, the shape of the real one.
    assert((auth_len >= 164) & (auth_len <= N), "Attestation authenticator data length out of range");
    zero_past(auth_data, auth_len);
    let nonce = sha256::sha256_var(append_32(auth_data, auth_len, client_data_hash), auth_len + 32);
    assert(nonce == cert_nonce, "Attestation authenticator data is not the one Apple certified");
    assert(bytes_at(auth_data, 0, app_id_hash), "Attestation is not for this app");
    assert(be32(auth_data, 33) == 0, "Attestation counter is not zero");
    let aaguid: [u8; 16] = slice_at(auth_data, 37);
    let want = if production { AAGUID_PRODUCTION } else { AAGUID_DEVELOPMENT };
    assert(aaguid == want, "App Attest environment does not match");
}

/// The assertion is signed by the credential key over this clientData, for
/// this app. Returns the counter.
pub fn verify_assertion<let N: u32, let C: u32>(
    key_x: [u8; 32],
    key_y: [u8; 32],
    auth_data: [u8; N],
    auth_len: u32,
    client_data: [u8; C],
    signature: [u8; 64],
    app_id_hash: [u8; 32],
) -> u32 {
    assert((auth_len >= 37) & (auth_len <= N), "Assertion authenticator data length out of range");
    zero_past(auth_data, auth_len);
    let client_data_hash = sha256::digest(client_data);
    let nonce = sha256::sha256_var(append_32(auth_data, auth_len, client_data_hash), auth_len + 32);
    let digest = sha256::digest(nonce);
    // std's P-256 verification is a Barretenberg black box; it refuses a
    // high s, so the prover supplies the low form (n - s) when Apple's is high.
    assert(
        std::ecdsa_secp256r1::verify_signature(key_x, key_y, signature, digest),
        "Assertion signature is invalid",
    );
    assert(bytes_at(auth_data, 0, app_id_hash), "Assertion is not for this app");
    let counter = be32(auth_data, 33);
    assert(counter > 0, "Assertion counter is zero");
    counter
}
