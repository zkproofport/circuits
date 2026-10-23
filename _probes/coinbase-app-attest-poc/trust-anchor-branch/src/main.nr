// The merged branch: one circuit, two ways to vouch for a statement, and the
// proof does not say which was used.
//
//   app kind     Apple's CA key (P-384) signed a credential certificate; the
//                certificate's P-256 key signed the statement.
//   server kind  A server's P-256 key signed the statement directly.
//
// Either way the anchor key (CA key or server key) must be in the public
// trust-anchor set (depth-2 Poseidon2 tree, see ../trust-anchor-lib), and the
// kind byte is private.
//
// Both branches are always computed (a circuit cannot skip one), so the
// P-384 verification runs for the server kind too, as a bool that is then
// ignored. zkPassport noir-ecdsa v0.3.0's verify_ecdsa returns a bool for a
// wrong signature but ASSERTS on three things before getting there: s must be
// low (s <= n/2), s must be invertible (s * s^-1 == 1, so s != 0), and the
// public key must be on the curve. So the server kind feeds it the P-384
// generator as the key (always on the curve) and any low, non-zero s.
// The credential TBS is also parsed for both kinds and the parser asserts on
// shape, so the server kind must supply some well-formed TBS (any public
// one); its key is then not used.
//
// Simplification against coinbase_app_attest_poc: the statement is a 32-byte
// public digest signed directly, not Apple's assertion over
// authenticatorData || SHA256(clientData), and the attestation authData /
// nonce check is left out. Both kinds would sign the same statement shape.

use app_attest::CREDENTIAL_TBS_MAX_LEN;
use app_attest::credential::{parse_credential_tbs, verify_credential_signature};
use trust_anchor::{leaf_poseidon2, root_poseidon2};

global DEPTH: u32 = 2;

global KIND_APP: u8 = 1;
global KIND_SERVER: u8 = 2;

global APP_ID: [u8; 36] = [
    0x52, 0x34, 0x47, 0x33, 0x32, 0x43, 0x56, 0x59, 0x32, 0x39, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x6d,
    0x61, 0x73, 0x73, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x2e, 0x7a, 0x6b, 0x70, 0x72, 0x6f, 0x6f, 0x66,
    0x70, 0x6f, 0x72, 0x74,
]; // "R4G32CVY29.com.masselabs.zkproofport"

/// The P-384 generator, the key the server kind gives the ignored P-384 check.
global P384_GX: [u8; 48] = [
    0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74,
    0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38,
    0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
];
global P384_GY: [u8; 48] = [
    0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
    0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
    0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
];

fn main(
    trust_anchor_root: pub Field,
    statement_digest: pub [u8; 32],
    // KIND_APP or KIND_SERVER. Private: the proof does not say which.
    kind: u8,
    // App: the CA key X || Y (P-384, 96 bytes). Server: the P-256 key
    // X || Y followed by 32 zero bytes. key_hash = SHA256 of all 96 bytes.
    anchor_key: [u8; 96],
    anchor_index: u32,
    anchor_path: [Field; DEPTH],
    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    credential_tbs_len: u32,
    // r || s of the certificate signature, s low.
    credential_sig: [u8; 96],
    // r || s of the statement signature (P-256), s low.
    statement_sig: [u8; 64],
) {
    assert((kind == KIND_APP) | (kind == KIND_SERVER), "Unknown trust anchor kind");
    let is_server = kind == KIND_SERVER;

    // ---- the anchor is in the published set -----------------------------
    let key_hash = sha256::digest(anchor_key);
    let leaf = leaf_poseidon2(kind, key_hash);
    assert(
        root_poseidon2::<DEPTH>(leaf, anchor_index, anchor_path) == trust_anchor_root,
        "Trust anchor is not in the published set",
    );

    let mut server_x: [u8; 32] = [0; 32];
    let mut server_y: [u8; 32] = [0; 32];
    let mut ca_x: [u8; 48] = [0; 48];
    let mut ca_y: [u8; 48] = [0; 48];
    let mut r: [u8; 48] = [0; 48];
    let mut s: [u8; 48] = [0; 48];
    for i in 0..32 {
        server_x[i] = anchor_key[i];
        server_y[i] = anchor_key[32 + i];
        if is_server {
            assert(anchor_key[64 + i] == 0, "Server anchor key is not X || Y || 32 zero bytes");
        }
    }
    for i in 0..48 {
        ca_x[i] = if is_server { P384_GX[i] } else { anchor_key[i] };
        ca_y[i] = if is_server { P384_GY[i] } else { anchor_key[48 + i] };
        r[i] = credential_sig[i];
        s[i] = credential_sig[48 + i];
    }

    // ---- (a) the certificate signature, as a bool -----------------------
    let cert_ok = verify_credential_signature(ca_x, ca_y, credential_tbs, credential_tbs_len, r, s);

    // ---- (b) the signing key: from the certificate or the anchor --------
    let cred = parse_credential_tbs(credential_tbs, credential_tbs_len, APP_ID);
    let mut key_x: [u8; 32] = [0; 32];
    let mut key_y: [u8; 32] = [0; 32];
    for i in 0..32 {
        key_x[i] = if is_server { server_x[i] } else { cred.x[i] };
        key_y[i] = if is_server { server_y[i] } else { cred.y[i] };
    }

    // ---- (c) the statement signature ------------------------------------
    assert(
        std::ecdsa_secp256r1::verify_signature(key_x, key_y, statement_sig, statement_digest),
        "Statement signature is invalid",
    );

    // ---- (d) the app kind needs the certificate -------------------------
    assert(is_server | cert_ok, "Credential certificate is not signed by the trust anchor");
}
