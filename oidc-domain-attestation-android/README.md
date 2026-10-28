# oidc-domain-attestation-android

The `oidc_domain_attestation` circuit id with an Android phone as the
provider-key statement's signer.

Everything about the token -- RSA signature, issuer, audience, `iat <= now <
exp`, nonce binding, verified email in the public domain, nullifier -- and the
313-byte provider-key statement are `../oidc-libs`, shared with
`../oidc-domain-attestation`. The public inputs are the same 214 values in the
same order, so a verifier reads both packages' proofs alike; it picks the
verifier contract for the package that made the proof.

The statement is signed (SHA256withECDSA) by an Android Keystore key that
`../android-key-attestation` vouches for under Google's Key Attestation CA1:
generated in TEE or StrongBox by `com.masselabs.zkproofport` signed with its
Play app signing certificate, on a locked, verified-boot device, with every
certificate of the Remote Key Provisioning chain valid at `now`.

## Private inputs after `signature_limbs`

`statement_sig` (r || s, low s), then the `AndroidChain` fields: `ca2_tbs`,
`ca2_tbs_len`, `ca2_sig`, `ca3_tbs`, `ca3_tbs_len`, `ca3_sig`, `att_tbs`,
`att_tbs_len`, `att_sig`, `leaf_tbs`, `leaf_tbs_len`, `leaf_sig`.

## Size

1,514,177 gates, 2^21. The reference string is published in parts
(`target/*.srs.part<N>`, each listed in `target/SHA256SUMS` with the joined
file).

## Acceptance

`scripts/post-build.sh` (run by `../scripts/build.sh`): synthetic Android
chains under a synthetic root for every accepted and refused case, and the
real circuit refusing a synthetic chain and a real Google chain for another
app. `../scripts/android-key-attestation/mutation-check.sh` shows which code
does each refusal.
