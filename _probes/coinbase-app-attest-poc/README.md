# Per-part gate probes

Each probe is one slice of `coinbase_app_attest_poc`, compiled on its own so
`bb gates` can say what that slice costs. They are measurement provenance,
not circuits: no fixtures, no vk, nothing deployed. Run them through
`scripts/coinbase-app-attest-poc/measure.sh`, which compiles each and prints
the table.

| Probe | What it contains |
|---|---|
| `coinbase-base` | Everything except App Attest: request signature (signed_digest), the attestation transaction and its signer, the Merkle proof, the wallet nullifier |
| `p384-verify` | One ECDSA P-384 verification over a 32-byte digest (zkPassport noir-ecdsa v0.3.0) |
| `cert-der-sha` | SHA-256 of the CA key and of the TBS (variable length, up to 1000 bytes), the DER walk that extracts the key / nonce / App ID, and the attestation authData nonce check |
| `p256-assertion` | SHA-256 of clientData, of authenticatorData ++ hash, of the nonce, and the P-256 verification (Barretenberg black box) |

The parts do not add up exactly to the whole: lookup tables (SHA-256,
Keccak, range checks) are shared once in the full circuit and paid once per
probe here.

## Trust-anchor root probes

The proposal in `.claude/agents/circuits-dev.md` ("Open (2026-10-23)"): one
public `trust_anchor_root` over {Apple App Attestation CA key hash, AI server
key hashes}, a private kind byte, and both kinds in one circuit. Run
`scripts/coinbase-app-attest-poc/measure-trust-anchor.sh`, which compiles each,
prints the gates, generates synthetic-key fixtures, checks each accepts or is
refused with its named reason, and proves both accepted kinds under one vk.

| Probe | What it contains |
|---|---|
| `trust-anchor-lib` | Library: leaf = H(kind_byte \|\| key_hash32), fixed-depth Merkle path, keccak256 and Poseidon2 forms, with tests |
| `anchor-keccak-d{2,4,8}` | Membership alone, keccak256 tree, root public as 32 bytes |
| `anchor-poseidon2-d{2,4,8}` | Membership alone, Poseidon2 tree, root public as one Field |
| `trust-anchor-branch` | The merged branch: P-384 certificate signature as a bool, the P-256 signing key from the certificate (app) or the anchor (server) by a private kind byte, the P-256 statement signature, `kind == server \|\| cert_ok`, depth-2 Poseidon2 membership. Fixtures are generated (gitignored `Prover.*.toml`) |
| `anchor-root` | Fixture helper, not a probe: computes the depth-2 Poseidon2 tree for the generator |
