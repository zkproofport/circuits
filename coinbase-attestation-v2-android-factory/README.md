# coinbase-attestation-v2-android-factory

The `coinbase_attestation (v2)` circuit id with a FACTORY-provisioned Android phone as the
statement's signer: devices launched with Android 12 or earlier, whose
attestation keys were installed at the factory and chain to Google's RSA-4096
root. Same public inputs, 225-byte revocation statement and nullifier as `../coinbase-attestation-v2-android`, with
the request, transaction and statement checks of `../coinbase-v2-libs`.

The statement is signed (SHA256withECDSA) by an Android Keystore key that the
key attestation chain vouches for (`../android-key-attestation`
android_factory_signing_key: RSA root -> P-384 intermediate -> P-256 batch
key -> leaf; our package and Play signing certificate, locked bootloader,
verified boot, key generated in TEE or StrongBox). Because a factory key may
have leaked and a circuit cannot read Google's revocation list, the statement
also carries a Google Play Integrity verdict (`../play-integrity`): our app
as Play distributes it on a device meeting device integrity, with nonce
SHA256(SHA256(statement) || signature) -- the pairing zkPassport's Android
FaceMatch circuit uses. Devices with Remote Key Provisioning use
`../coinbase-attestation-v2-android`, which needs neither the verdict nor the relay.

## Private inputs after the statement

`statement_sig`; `ik_tbs`, `ik_tbs_len`, `ik_sig` (RSA-4096 signature, 35 limbs);
`batch_tbs`, `batch_tbs_len`, `batch_sig`; `leaf_tbs`, `leaf_tbs_len`, `leaf_sig`;
`integrity_payload_b64`, `integrity_payload_b64_len`, `integrity_signature`;
`rsa_root_modulus`, `rsa_root_redc`, `play_integrity_key`. The last three are
Google's RSA root and our Play verification key, given as inputs and pinned
by Poseidon2 hash in `../statement-signer` (Barretenberg cannot build them
as constants).

## Size

1,344,762 gates, 2^21. The reference string is published in parts.

## Acceptance

`scripts/post-build.sh`: synthetic factory chains under a synthetic RSA root
and verdicts signed with a test Play key, every accepted and refused case;
the real circuit refuses a synthetic chain and a real Google-signed Sony
chain for another app.
