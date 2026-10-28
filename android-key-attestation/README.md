# android-key-attestation

Android key attestation verified in a Noir circuit: a P-256 key generated in
secure hardware by one app, as Google Play signs it, on a device with a locked
bootloader and verified boot. Used by `statement-signer`'s
`verify_statement_android`, which the `*-android` circuit packages call.

## The chain

Only a Remote Key Provisioning (RKP) chain under Google's Key Attestation CA1
root is accepted, with the root's key pinned by the caller:

| Certificate | Key | Signed by, hash | Checked |
|---|---|---|---|
| Droid CA2 | P-384 | root, SHA-384 | CA, valid at `now` |
| Droid CA3 | P-256 | CA2, SHA-384 | CA, valid at `now` |
| RKP attestation key | P-256 | CA3, SHA-256 | CA, valid at `now`, provisioning-information extension, no key description |
| leaf | P-256 | attestation key, SHA-256 | the key description, below |

RKP certificates are short-lived, so their validity is checked against the
statement's time.

## Factory-provisioned chains

`android_factory_signing_key` takes the chain of devices launched with Android
12 or earlier: Google's RSA-4096 root (pinned by the caller as modulus and
Barrett parameter) -> intermediate (P-384, sha256WithRSAEncryption, a CA) ->
batch key (P-256, ecdsa-with-SHA256) -> leaf, with the same key-description
checks. Validity dates are not read (Google: expired factory certificates stay
trustworthy unless revoked). The keys on Google's revocation list are factory
keys and a circuit cannot read that list, so callers pair this with a Play
Integrity verdict (`../play-integrity`; statement-signer
`verify_statement_android_factory`), as zkPassport does.

## The key description

From the leaf's extension 1.3.6.1.4.1.11129.2.1.17:

- attestation and KeyMint security level: both TrustedEnvironment or both StrongBox;
- `softwareEnforced` [709] attestationApplicationId: exactly one package (the
  caller's) and exactly one signing-certificate SHA-256 (the caller's);
- `hardwareEnforced` [704] rootOfTrust: deviceLocked TRUE, verifiedBootState Verified;
- `hardwareEnforced` [702] origin: GENERATED.

The attestation challenge is not read: the caller checks the key's own
signature over its statement.

## Inputs

`AndroidChain`: each certificate's TBS zero-padded to its limit (CA2 600,
CA3 768, attestation key 512, leaf 1024 bytes) with its length, and the
issuer's signature as r || s with s in low form.
`scripts/android-key-attestation/chain.js` converts a chain as
`KeyStore.getCertificateChain` returns it.

## Tests

`nargo test` runs on real Google-signed chains (`test-vectors/`, Apache-2.0,
from github.com/android/keyattestation testdata): a Pixel TEE and StrongBox
RKP key and a Sony factory key, accepted for their own app and refused for
any other, a Pixel 3 factory key refused for its unlocked bootloader, with
every link, validity edge and key-description field exercised.
`scripts/android-key-attestation/export-vector.js` regenerates
`src/test_vectors.nr` from those files.
