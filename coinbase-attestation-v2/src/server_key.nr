// The AI server's statement key, X || Y (P-256), pinned in the circuit.
//
// The server signs the same 225-byte clientData the app does (client_data.nr),
// as ECDSA P-256 over SHA256(clientData): Cloud KMS asymmetricSign on an
// EC_SIGN_P256_SHA256 key with digest.sha256 = SHA256(clientData). README.md,
// "What the server signs", has the exact procedure.
//
// Pinned since 2026-10-28: the Cloud KMS key version
//   projects/masselabs-zkproofport/locations/us-central1/keyRings/proofport-ai/
//     cryptoKeys/coinbase-kyc-v2-statement/cryptoKeyVersions/1
// (HSM, EC_SIGN_P256_SHA256, SHA256(X || Y) = 0x072479af...0ffac0). One key
// for staging and production: one circuit, one vk, one key -- a second key
// would be a second circuit and verifier. Its private half never leaves the
// HSM; the AI server's service accounts may only ask KMS to sign.
//
// `node scripts/coinbase-attestation-v2/set-server-key.js --show` says which
// key the line below holds. `--test-key` puts back the INSECURE test key of
// scripts/coinbase-attestation-v2/anchors.js (private key = SHA256 of a public
// string; anyone can sign with it), which the synthetic-anchors copy always
// uses; deploy_verifier.sh refuses mainnets while it is here
// (set-server-key.js --require-real). The script rewrites the single line
// below and nothing else.

pub global SERVER_KEY: [u8; 64] = [0xcd, 0x43, 0x25, 0xc9, 0x0e, 0xa4, 0x1a, 0x99, 0xe2, 0xb1, 0xf2, 0xe1, 0xbe, 0x80, 0x80, 0xa6, 0xea, 0x93, 0x22, 0xfe, 0x1d, 0x9f, 0x99, 0x08, 0xf8, 0xda, 0x20, 0xa2, 0x45, 0x72, 0x5a, 0xad, 0x47, 0x42, 0x62, 0x0b, 0xf1, 0x9e, 0xf2, 0xa2, 0x94, 0x3d, 0x89, 0x37, 0x19, 0x2c, 0x45, 0x65, 0x54, 0xfa, 0xf8, 0x12, 0x9c, 0xa4, 0x14, 0xc8, 0xec, 0xfe, 0xd8, 0x1f, 0x29, 0xa7, 0xf8, 0x4f];
