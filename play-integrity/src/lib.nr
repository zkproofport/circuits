// A Google Play Integrity verdict (classic request), verified in a circuit.
//
// Mirrors zkPassport's Android FaceMatch circuit (zkpassport/circuits 818e7a7,
// src/noir/lib/facematch/src/android/token.nr). The app asks Play Integrity
// for a token with a nonce bound to the statement it is about to prove; Google
// answers with a JWE (A256KW / A256GCM) of a JWS (ES256)
// (developer.android.com/google/play/integrity/classic). Our relay only
// decrypts it with the app's response-decryption key and hands back the JWS
// parts; Google's signature over the JWS is checked HERE, against the app's
// pinned Play Integrity verification key, so the relay is trusted for
// confidentiality only.
//
// REQUIRED, as zkPassport requires for its production environment:
//   - the ES256 signature over BASE64URL(header) "." BASE64URL(payload) by the
//     pinned verification key; the header is Google's `{"alg":"ES256"}`
//     (zkPassport pins the same 20 characters);
//   - requestDetails.requestPackageName and appIntegrity.packageName both our
//     package;
//   - appIntegrity.appRecognitionVerdict PLAY_RECOGNIZED: this binary is the
//     one Play distributes for our package and signing certificate;
//   - deviceIntegrity.deviceRecognitionVerdict contains MEETS_DEVICE_INTEGRITY
//     or MEETS_STRONG_INTEGRITY (MEETS_BASIC_INTEGRITY alone is refused, as
//     zkPassport does): a genuine, certified device with a locked
//     bootloader; Google evaluates this server-side, including attestation
//     keys it has revoked;
//   - requestDetails.nonce is base64url(nonce) of the caller's 32-byte nonce,
//     with or without the one padding character Google may echo as `=`
//     (zkPassport strips the same escape).
// The caller builds the nonce from the statement and the key's signature over
// it, so the verdict cannot be reused for another statement.

mod tests;
mod test_vectors;

use base64::{BASE64_URL_DECODER, BASE64_URL_ENCODER};
use json_parser::JSON1kb;

/// base64url of a JSON payload of at most 1024 bytes (zkPassport's limit).
pub global PAYLOAD_MAX_LEN: u32 = 1024;
pub global PAYLOAD_B64_MAX_LEN: u32 = 1368;

/// base64url('{"alg":"ES256"}'), the protected header Google signs with.
global JWS_HEADER_B64: [u8; 20] =
    [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 85, 122, 73, 49, 78, 105, 74, 57];
global PERIOD: u8 = 46;
/// `=`: the JSON escape of '=' Google uses when it echoes a padded nonce.
global ESCAPED_PAD: [u8; 6] = [92, 117, 48, 48, 51, 100];

/// What the relay returns, as the circuit takes it: the JWS payload exactly
/// as signed (base64url, zero-padded) and Google's ES256 signature, r || s
/// with s in low form.
pub struct IntegrityToken {
    pub payload_b64: [u8; PAYLOAD_B64_MAX_LEN],
    pub payload_b64_len: u32,
    pub signature: [u8; 64],
}

fn same_string<let N: u32, let M: u32>(v: BoundedVec<u8, N>, s: [u8; M]) -> bool {
    let mut ok = v.len() == M;
    for i in 0..M {
        if i < v.len() {
            ok &= v.get_unchecked(i) == s[i];
        }
    }
    ok
}

/// Asserts the token is Google Play's signed verdict for `package` with
/// `nonce`, recognized app and device integrity, verified with the pinned
/// verification key (`key_x`, `key_y`, P-256).
pub fn verify_integrity_token<let P: u32>(
    token: IntegrityToken,
    key_x: [u8; 32],
    key_y: [u8; 32],
    package: [u8; P],
    nonce: [u8; 32],
) {
    let len = token.payload_b64_len;
    assert((len > 0) & (len <= PAYLOAD_B64_MAX_LEN), "Integrity token payload length out of range");
    for i in 0..PAYLOAD_B64_MAX_LEN {
        if i >= len {
            assert(token.payload_b64[i] == 0, "Integrity token padding is not zero");
        }
    }

    // ---- Google's signature over header "." payload ----
    let mut signed: [u8; 21 + PAYLOAD_B64_MAX_LEN] = [0; 21 + PAYLOAD_B64_MAX_LEN];
    for i in 0..20 {
        signed[i] = JWS_HEADER_B64[i];
    }
    signed[20] = PERIOD;
    for i in 0..PAYLOAD_B64_MAX_LEN {
        signed[21 + i] = token.payload_b64[i];
    }
    let digest = sha256::sha256_var(signed, 21 + len);
    assert(
        std::ecdsa_secp256r1::verify_signature(key_x, key_y, token.signature, digest),
        "Integrity verdict is not signed by Google Play",
    );

    // ---- the verdict ----
    let payload: BoundedVec<u8, 1026> =
        BASE64_URL_DECODER::decode_var(BoundedVec::from_parts(token.payload_b64, len));
    assert(payload.len() <= PAYLOAD_MAX_LEN, "Integrity verdict is longer than the circuit reads");
    // The parser reads a fixed 1 KB; bytes past the payload are spaces.
    let mut text: [u8; PAYLOAD_MAX_LEN] = [32; PAYLOAD_MAX_LEN];
    for i in 0..PAYLOAD_MAX_LEN {
        if i < payload.len() {
            text[i] = payload.get_unchecked(i);
        }
    }
    let json = JSON1kb::parse_json(text);

    let request = json.get_object("requestDetails").unwrap();
    let request_package: BoundedVec<u8, 128> = request.get_string("requestPackageName").unwrap();
    assert(same_string(request_package, package), "Integrity verdict was requested by another app");

    let app = json.get_object("appIntegrity").unwrap();
    let recognition: BoundedVec<u8, 32> = app.get_string("appRecognitionVerdict").unwrap();
    assert(
        same_string(recognition, "PLAY_RECOGNIZED".as_bytes()),
        "App is not recognized by Google Play",
    );
    let app_package: BoundedVec<u8, 128> = app.get_string("packageName").unwrap();
    assert(same_string(app_package, package), "Integrity verdict is for another app");

    let device = json.get_object("deviceIntegrity").unwrap();
    let verdicts = device.get_array("deviceRecognitionVerdict").unwrap();
    let count = verdicts.get_length();
    let mut meets = false;
    // At most four verdict strings exist (BASIC, DEVICE, STRONG, VIRTUAL).
    for i in 0..4 {
        if i < count {
            let v: BoundedVec<u8, 32> = verdicts.get_string_from_array(i as Field).unwrap();
            meets |= same_string(v, "MEETS_DEVICE_INTEGRITY".as_bytes())
                | same_string(v, "MEETS_STRONG_INTEGRITY".as_bytes());
        }
    }
    assert(meets, "Device does not meet Play device integrity");

    // ---- the nonce: base64url(nonce), unpadded, or padded as `=` ----
    let token_nonce: BoundedVec<u8, 64> = request.get_string("nonce").unwrap();
    let want: [u8; 43] = BASE64_URL_ENCODER::encode(nonce);
    let n = token_nonce.len();
    assert((n == 43) | (n == 49), "Integrity verdict nonce is not this statement's");
    let mut ok = true;
    for i in 0..43 {
        ok &= token_nonce.get_unchecked(i) == want[i];
    }
    if n == 49 {
        for i in 0..6 {
            ok &= token_nonce.get_unchecked(43 + i) == ESCAPED_PAD[i];
        }
    }
    assert(ok, "Integrity verdict nonce is not this statement's");
}
