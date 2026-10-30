# coinbase-country-attestation-v2-android-factory

The `coinbase_country_attestation` (v2) circuit id with a FACTORY-provisioned
Android phone as the statement's signer: devices launched with Android 12 or
earlier, whose attestation keys chain to Google's RSA-4096 root. Same public
inputs (215), 227-byte statement and nullifier as
`../coinbase-country-attestation-v2-android`, with the request, transaction,
country-list and statement checks of `../coinbase-country-v2-libs`.

The signer check is `../coinbase-attestation-v2-android-factory`'s: the key
attestation chain (RSA root -> P-384 intermediate -> P-256 batch -> leaf; our
package and Play signing certificate, locked bootloader, verified boot, key
generated in TEE or StrongBox) and a Google Play Integrity verdict for our
app on a device meeting device integrity, with nonce
SHA256(SHA256(statement) || signature).

## Private inputs after the statement

`statement_sig`; `ik_tbs`, `ik_tbs_len`, `ik_sig`; `batch_tbs`,
`batch_tbs_len`, `batch_sig`; `leaf_tbs`, `leaf_tbs_len`, `leaf_sig`;
`integrity_payload_b64`, `integrity_payload_b64_len`, `integrity_signature`;
`rsa_root_modulus`, `rsa_root_redc`, `play_integrity_key` (pinned by
Poseidon2 hash in `../statement-signer`).

## Size

2^21, reference string published in parts. Gate count:
`../coinbase-country-attestation-v2/README.md`, "Measurements".

## Acceptance

`scripts/post-build.sh`: synthetic factory chains under a synthetic RSA root
and verdicts signed with a test Play key (`make-fixtures.sh country-factory`),
every accepted and refused case of the KYC v2 factory package plus the
country ones; the real circuit refuses a synthetic chain and a real
Google-signed Sony chain for another app, and accepts a real phone's capture
when `test-vectors/real_device.toml` is present.
