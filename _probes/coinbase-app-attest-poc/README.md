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
