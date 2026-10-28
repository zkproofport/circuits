// Apple's App Attest INTERMEDIATE CA public key, X || Y (P-384): the only
// Apple key the circuits using this library pin. Every credential certificate it accepts must
// be signed by this key (SHA-256 over the TBS, P-384).
//
//   subject   CN=Apple App Attestation CA 1, O=Apple Inc., ST=California
//   issuer    CN=Apple App Attestation Root CA (valid to 2045-03-15)
//   validity  2020-03-18 to 2030-03-13 00:00:00 UTC
//   SHA256(X || Y) = 0x8ef85f951d5958d17e728c881f11f059f370aff763503903a96417405b59747f
//
// WHY THE INTERMEDIATE AND NOT THE ROOT (decided 2026-10-27,
// .claude/agents/circuits-dev.md "DECIDED 2026-10-27"): verifying root ->
// intermediate in-circuit costs 669,935 gates and makes coinbase v2 a 2^21 circuit
// (.srs 134 MB, over GitHub's file limit, about twice the phone's proving
// cost). Pinned, it is 2^20.
//
// THE PRICE: when Apple issues a successor intermediate and attestations
// start chaining to it, every App Attest proof fails until new circuit
// releases pin the new key (new vk, verifier redeploy, app/SDK/AI release).
// Watch for it from 2029 at the latest.
//
// scripts/coinbase-attestation-v2/check-apple-vector.js downloads Apple's
// root from apple.com, checks the root signed the CA 1 certificate
// (apple-vector.json), and fails unless these bytes are that certificate's
// key. app-attest-libs tests verify the same root -> CA 1 link in-circuit.
//
// Each acceptance run's synthetic-anchors copy of this library
// (scripts/statement-signer/make-synthetic-anchors.sh) replaces this file and
// server_key.nr with keys whose private halves the fixture generators hold;
// nothing else in the copy differs.

pub global APPLE_APP_ATTESTATION_CA_KEY: [u8; 96] = [
    0xae, 0x5b, 0x37, 0xa0, 0x77, 0x4d, 0x79, 0xb2, 0x35, 0x8f, 0x40, 0xe7, 0xd1, 0xf2, 0x26, 0x26,
    0xf1, 0xc2, 0x5f, 0xef, 0x17, 0x80, 0x2d, 0xea, 0xb3, 0x82, 0x6a, 0x59, 0x87, 0x4f, 0xf8, 0xd2,
    0xad, 0x15, 0x25, 0x78, 0x9a, 0xa2, 0x66, 0x04, 0x19, 0x12, 0x48, 0xb6, 0x3c, 0xb9, 0x67, 0x06,
    0x9e, 0x98, 0xd3, 0x63, 0xbd, 0x5e, 0x37, 0x0f, 0xbf, 0xa0, 0x8e, 0x32, 0x9e, 0x80, 0x73, 0xa9,
    0x85, 0xe7, 0x74, 0x6e, 0xa3, 0x59, 0xa2, 0xf6, 0x6f, 0x29, 0xdb, 0x32, 0xaf, 0x45, 0x5e, 0x21,
    0x16, 0x58, 0xd5, 0x67, 0xaf, 0x9e, 0x26, 0x7e, 0xb2, 0x61, 0x4d, 0xc2, 0x1a, 0x66, 0xce, 0x99,
];
