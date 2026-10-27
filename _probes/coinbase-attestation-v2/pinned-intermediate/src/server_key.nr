// The AI server's statement key, X || Y (P-256), pinned in the circuit.
//
// The server signs the same 225-byte clientData the app does (client_data.nr),
// as ECDSA P-256 over SHA256(clientData): Cloud KMS asymmetricSign on an
// EC_SIGN_P256_SHA256 key with digest.sha256 = SHA256(clientData). README.md,
// "What the server signs", has the exact procedure.
//
// PLACEHOLDER. Until the AI server's Cloud KMS key exists this is the INSECURE
// TEST KEY of scripts/coinbase-attestation-v2/anchors.js, whose private key
// is SHA256 of a public string: anyone can sign server statements for it.
// Swap the real key in with
//   node scripts/coinbase-attestation-v2/set-server-key.js --kms <key version>
// which rewrites the single line below and nothing else; deploy_verifier.sh
// refuses mainnets while the test key is here (set-server-key.js --require-real).

pub global SERVER_KEY: [u8; 64] = [0xb8, 0xf9, 0x4f, 0x28, 0x00, 0x82, 0x67, 0xf3, 0x18, 0x8e, 0x5a, 0x63, 0x45, 0xeb, 0x31, 0x60, 0x6c, 0x8b, 0x81, 0x45, 0xc3, 0x59, 0x53, 0x46, 0x8b, 0xb5, 0x56, 0x50, 0x08, 0xc9, 0x51, 0xdd, 0x77, 0x61, 0x4d, 0xbe, 0xc1, 0x59, 0x29, 0xf5, 0x35, 0x65, 0xb3, 0x0e, 0x49, 0xd9, 0x5d, 0x4f, 0x24, 0x9f, 0x96, 0x6a, 0x45, 0xbc, 0x01, 0x5d, 0x41, 0x12, 0x47, 0x0e, 0xfb, 0x84, 0x37, 0xd6];
