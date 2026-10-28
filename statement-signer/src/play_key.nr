// The app's Play Integrity VERIFICATION key, X || Y (P-256): the public key
// Google Play signs our app's integrity verdicts with when the app manages its
// own response-encryption keys (Play Console > App integrity > Response
// encryption > self-managed; set up 2026-10-28, Cloud project
// masselabs-zkproofport). Play Console gives it as base64 DER
// SubjectPublicKeyInfo:
//   MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9mG5EsLPQCtC4JQDSgvE5WUjoXYnwmt1Xp1Y
//   fEOdQzsjwbDMVpN/QUbDB+vbGlUWMY/Z5Q3x6Z8sTFVQTwpnWw==
// (also in Secret Manager as play-integrity-verification-key). It is public;
// the DECRYPTION key is the relay's secret and never reaches a circuit.
//
// Used only by verify_statement_android_factory. If the key is rotated in
// Play Console, every circuit using this file needs a release.
// `node scripts/statement-signer/set-play-key.js --show` says which key the
// line below holds; the synthetic-anchors copy replaces it with the INSECURE
// test key of scripts/statement-signer/anchors.js.

pub global PLAY_INTEGRITY_KEY: [u8; 64] = [
    0xf6, 0x61, 0xb9, 0x12, 0xc2, 0xcf, 0x40, 0x2b, 0x42, 0xe0, 0x94, 0x03, 0x4a, 0x0b, 0xc4, 0xe5,
    0x65, 0x23, 0xa1, 0x76, 0x27, 0xc2, 0x6b, 0x75, 0x5e, 0x9d, 0x58, 0x7c, 0x43, 0x9d, 0x43, 0x3b,
    0x23, 0xc1, 0xb0, 0xcc, 0x56, 0x93, 0x7f, 0x41, 0x46, 0xc3, 0x07, 0xeb, 0xdb, 0x1a, 0x55, 0x16,
    0x31, 0x8f, 0xd9, 0xe5, 0x0d, 0xf1, 0xe9, 0x9f, 0x2c, 0x4c, 0x55, 0x50, 0x4f, 0x0a, 0x67, 0x5b,
];

/// play_key_hash(PLAY_INTEGRITY_KEY): what the circuits pin (the key itself is
/// a prover input; see verify_statement_android_factory).
pub global PLAY_INTEGRITY_KEY_HASH: Field = 0x11cee22bf659d69e4d0794f0469aa9b7ae59d88e37f6033fd75b3a8be8ab827b;
