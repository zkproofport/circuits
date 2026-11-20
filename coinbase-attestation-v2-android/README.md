# coinbase-attestation-v2-android

The `coinbase_attestation` (v2) circuit id with an Android phone as the
revocation statement's signer.

The wallet signature over the request, Coinbase's `attestAccount`
transaction and the 225-byte statement ("ZKProofport/AA/1") are
`../coinbase-v2-libs`, and the nullifier is `../oprf-nullifier-libs`, shared
with `../coinbase-attestation-v2`. The public inputs are the same 133 values
in the same order.

The statement is signed (SHA256withECDSA) by an Android Keystore key that
`../android-key-attestation` vouches for under Google's Key Attestation CA1:
generated in TEE or StrongBox by `com.masselabs.zkproofport` signed with its
Play app signing certificate, on a locked, verified-boot device, with every
certificate of the Remote Key Provisioning chain valid at `attested_at`.

## Private inputs after `client_data`

`statement_sig` (r || s, low s), then the `AndroidChain` fields: `ca2_tbs`,
`ca2_tbs_len`, `ca2_sig`, `ca3_tbs`, `ca3_tbs_len`, `ca3_sig`, `att_tbs`,
`att_tbs_len`, `att_sig`, `leaf_tbs`, `leaf_tbs_len`, `leaf_sig`.

Then the OPRF nullifier's (`../oprf-nullifier-libs`): `oprf_public_key_x`,
`oprf_public_key_y`, `oprf_beta`, `oprf_dlog_e`, `oprf_dlog_s`,
`oprf_response_x`, `oprf_response_y`.

## Size

1,385,874 gates (OPRF nullifier, nargo 1.0.0 / bb 6.0.0), 2^21. The reference string is published in parts
(`target/*.srs.part<N>`, each listed in `target/SHA256SUMS` with the joined
file).

## Acceptance

`scripts/post-build.sh`: a real Coinbase attestation with synthetic Android
chains (`../scripts/coinbase-attestation-v2-android/`), and the real circuit
refusing a synthetic chain and a real Google chain for another app.
