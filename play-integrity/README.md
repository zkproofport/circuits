# play-integrity

A Google Play Integrity verdict (classic request) verified in a Noir circuit,
as zkPassport's Android FaceMatch circuit does
(`zkpassport/circuits` `src/noir/lib/facematch/src/android/token.nr`).

Google answers a classic request with a JWE (A256KW / A256GCM) of a JWS
(ES256). The relay's `POST /api/v1/play-integrity/decrypt` decrypts it with the
app's response-decryption key and returns the JWS segments; this library
checks Google's ES256 signature over `base64url({"alg":"ES256"}) "."
payload` with the app's verification key, then reads the verdict JSON
(zkPassport's JSON parser, vendored in `../deps/noir_json_parser` for
nargo 1.0.0-beta.19):

- `requestDetails.requestPackageName` and `appIntegrity.packageName` are the caller's package;
- `appIntegrity.appRecognitionVerdict` is `PLAY_RECOGNIZED`;
- `deviceIntegrity.deviceRecognitionVerdict` contains `MEETS_DEVICE_INTEGRITY` or `MEETS_STRONG_INTEGRITY`;
- `requestDetails.nonce` is base64url of the caller's 32-byte nonce, unpadded or with the pad Google echoes as `=`.

Inputs (`IntegrityToken`): the payload segment as signed (ASCII, zero-padded
to 1368 bytes, a JSON verdict of at most 1024 bytes) and Google's signature,
r || s with s in low form.

## Tests

`nargo test`: a REAL Google-signed verdict (zkPassport's app,
`test-vectors/zkpassport-real-verdict.json`, Apache-2.0) verifies and is
refused for its unrecognized app and for any other package; synthetic
verdicts signed with an INSECURE test key cover each accepted and refused
field. `scripts/play-integrity/export-vector.js` regenerates
`src/test_vectors.nr`.
