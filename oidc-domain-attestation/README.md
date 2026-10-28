# oidc_domain_attestation (v2)

Proves that a Google or Microsoft ID token, signed with RSA-2048 by the key in
`pubkey_modulus_limbs`, says the holder's verified email ends in `domain`, and
binds the proof to the token's audience, issuer, validity window and (on the
app path) a request nonce. The circuit id is unchanged: `oidc_domain_attestation`.

v1 bound none of `aud`, `iss`, `exp` or `nonce`, so any Google ID token issued
to any site for the same email produced the same nullifier.

Since 2026-10-28 the circuit also requires a **provider-key statement**: a
signer this project trusts -- the phone through Apple App Attest, or the AI
server through Cloud KMS -- says the RSA key the token was checked with was in
the provider's published key list at `now`. Without it, a self-made RSA key
and a self-signed token proved any email on chain, because a contract cannot
fetch a JWKS and Google's and Microsoft's key lists carry no signature of
their own. The public inputs do not change.

## Public inputs (214 field elements)

| Offset | Count | Input | Meaning |
|---|---|---|---|
| 0 | 18 | `pubkey_modulus_limbs` | provider RSA modulus, 120-bit limbs, least significant first |
| 18 | 64 | `domain.storage` | email domain bytes, zero padded |
| 82 | 1 | `domain.len` | |
| 83 | 32 | `scope` | `keccak256(utf8(scope string))`, one byte per element |
| 115 | 32 | `nullifier` | `keccak256(keccak256(email) \|\| scope)` (unchanged from v1) |
| 147 | 1 | `provider` | 0 = Google, 1 = Microsoft |
| 148 | 32 | `aud_hash` | `keccak256(utf8(aud))` of the token's `aud` string |
| 180 | 1 | `nonce_mode` | 1 = nonce bound, 0 = none |
| 181 | 32 | `nonce_binding` | mode 1: the token's `nonce` claim is the 64-character lowercase hex of these bytes; mode 0: all zero |
| 213 | 1 | `now` | unix seconds; the circuit asserts `iat <= now < exp` |

Offsets 0-147 are the v1 layout unchanged; v2 only appends.

What the circuit checks, and what stays with the verifier:

| Circuit | Verifier |
|---|---|
| RSA signature under the public modulus | (off-chain, defence in depth) the modulus is a current Google / Microsoft key (live JWKS) |
| a provider-key statement for this modulus, `provider` and `now`, signed by the app or the server (kind private) | -- |
| `iss`: Google `https://accounts.google.com` or `accounts.google.com`; Microsoft `https://login.microsoftonline.com/{lowercase tenant GUID}/v2.0` | which tenants, if any, to restrict to |
| `keccak256(aud) == aud_hash` | `aud_hash` is one of its client ids |
| `iat <= now < exp` | `now` is close enough to its own clock |
| mode 1: `nonce == hex(nonce_binding)`; mode 0: `nonce_binding == 0` | `nonce_binding == keccak256("zkproofport-oidc-v1" \|\| keccak256(scope) \|\| requestId)` for the request it issued; whether to accept mode 0 at all |
| `email_verified` (Google) / `xms_edov` (Microsoft) is `true`; email ends in `domain`; nullifier | |

Client ids in use (2026-10-27): Google web
`491923400813-5bb3up7dhejns2unvbrt6mku520hrr5g.apps.googleusercontent.com`
(app, mode 1), Google device
`491923400813-pr17m6kpin2rsbbes18jpb60j1s3qmv4.apps.googleusercontent.com`
(CLI / AI device flow, mode 0), Microsoft `8b09c842-d7a8-4d9c-a6ea-46c797412bac`.

## Private inputs and the builder contract

`scripts/oidc-inputs.ts` is the reference builder; the acceptance run uses it.

- The SHA-256 precompute stops at the 64-byte block holding the `.` between
  header and payload (v1 stopped at `"email"`). `partial_data` is therefore the
  header's tail plus the whole payload, because `iss` and `aud` come first in
  both providers' tokens.
- `base64_decode_offset` is the index just after that `.` inside
  `partial_data`, 1..64. The circuit refuses any other value: decoding base64
  from another position yields the payload's bits shifted by 2, 4 or 6, and a
  claim value the user controls (a display name) could be chosen to decode,
  shifted, into something like `"email":"...",`. v1 accepted any offset.
- `MAX_PARTIAL_DATA_LENGTH` is 2048 (v1: 768).
- Ten private inputs follow `signature_limbs`, in this order (the names and
  sizes of coinbase_attestation v2's): `signer_kind` u8 (1 app, 2 server),
  `statement_sig` [u8; 64] (P-256 r || s, s LOW), `credential_tbs` [u8; 1000],
  `credential_tbs_len`, `credential_sig` [u8; 96], `att_auth_data` [u8; 256],
  `att_auth_data_len`, `att_client_data_hash` [u8; 32], `assertion_auth_data`
  [u8; 128], `assertion_auth_data_len`. The server passes zeros for every App
  Attest input. Reference: `serverSigner` / `appSigner` in `scripts/oidc-inputs.ts`.

## Provider-key statement

Built in-circuit from public inputs (`src/provider_key.nr`); the signer writes
the same 313 bytes:

| Offset | Length | Field |
|---|---|---|
| 0 | 16 | `"ZKProofport/PK/1"` |
| 16 | 32 | `keccak256("oidc_domain_attestation")` = `0x90bb379d...8e062b` |
| 48 | 1 | `provider` (0 Google, 1 Microsoft) |
| 49 | 8 | `now`, unix seconds, big-endian |
| 57 | 256 | the RSA modulus `n`, big-endian (the JWKS `n`, base64url-decoded) |

Each 120-bit limb of `pubkey_modulus_limbs` is range-checked and the 14 bytes
above bit 2048 must be zero, so the signed bytes name exactly the modulus the
RSA check used.

Who signs, and how (`../statement-signer`, shared with coinbase_attestation
v2, which pins both keys):

- **server (kind 2)**: the AI server fetches the provider's live JWKS, refuses
  unless `n` is in it, and signs with Cloud KMS `asymmetricSign`,
  `digest.sha256 = SHA256(statement)`, on the key coinbase v2 uses
  (`projects/masselabs-zkproofport/locations/us-central1/keyRings/proofport-ai/cryptoKeys/coinbase-kyc-v2-statement/cryptoKeyVersions/1`);
  DER -> r || s, s put in low form, verified locally before proving.
- **app (kind 1)**: the phone, after the same live-JWKS check, asks App Attest
  for an assertion with clientDataHash = `SHA256(statement)`; the circuit
  checks the credential certificate under Apple's pinned "App Attestation
  CA 1", the attestation authData (production AAGUID, our App ID) and the
  assertion, exactly as in coinbase v2. iOS only: Android has no App Attest.

**One key, two statements.** The KMS key and each device's App Attest key sign
both coinbase v2's 225-byte `"ZKProofport/AA/1"` statement and this 313-byte
one. They differ in magic, circuit tag and length, and each circuit builds or
checks all three, so a signature over one can stand in for the other only by
a SHA-256 collision (refusal cases `stmt_wrong_magic`, `stmt_other_tag`,
`stmt_coinbase_replay_*` here; `oidc_statement_*` in coinbase v2). A separate
key would not narrow anything that matters: the same server process and
service accounts would hold both, the phone has one App Attest key for both,
and the circuit pins its key, so a second key would mean a second pin to keep
in step.

The statement does not bind the request (scope, nonce): it states a public
fact about a key, true for every token that key signed at `now`. Replaying it
helps nobody without a token that key signed, and the verifier already bounds
`now`.

## Token layout

Claims are located by text search in the decoded payload, so order does not
matter (the acceptance run includes Google's order, a reordered Google token,
Microsoft's work-tenant order with `aud` first, and the personal-account order
with `ver` first).

Sizing, `partial_data` = header tail (<= 63) + `.` + base64url payload:

| Token | partial_data |
|---|---|
| real Google token on the app (2026-10-27, Workspace account, measured by the v1 builder: signed data 941 bytes) | at most 877 (941 - one 64-byte block) |
| synthetic Google, every documented claim incl. name/picture/hd/nonce | 945 |
| synthetic Microsoft v2.0, work tenant, `aio` 200 chars, optional `email`/`xms_edov`, nonce | 1241 |
| largest accepted (Microsoft with `aio` grown to the cap) | 2047 |

Microsoft's docs give no length for `aio`/`rh`; the 200-character `aio` is an
assumption, which is why the cap leaves ~800 bytes beyond it. The cap costs no
dyadic size: 1536 and 2048 both land in 2^19.

## Size

`bb gates` with nargo 1.0.0-beta.19 / bb 4.2.0-aztecnr-rc.2:

| | gates | dyadic |
|---|---|---|
| v1 (768) | 235,719 | 2^18 (`.srs` 16,777,428 bytes) |
| v2 (2048) | 352,006 (350,659 before the quote check) | 2^19 (`.srs` 33,554,644 bytes) |

Measured parts at the 1536 cap: signature + SHA 180,332; payload decode
+31,698; seven claim lookups, the `aud` keccak and the issuer / nonce checks
+~80k. Each payload byte costs ~120 gates; a 1216 cap would fit 2^18
(254,614) but not a Microsoft token with a 200-character `aio`.
Proof 9,920 bytes; verifier 2,461 lines; vk 1,888 bytes.

## Known limits

- **Duplicate claims.** The position of a key is a prover hint; the circuit
  does not prove there is no second `"nonce"`. With duplicates, the first
  occurrence is used by an honest witness and either could be used by a
  dishonest one. Neither provider documents or is known to emit duplicate
  claims, and only a token signed by one passes the signature check
  (`doc_duplicate_nonce_first_matches` records this behaviour).
- **Device flow** carries no nonce (mode 0). Freshness and audience still
  bind; replay within the token's hour does not.
- String values may not contain a backslash, so an escaped `aud`, `iss`,
  `email` or `nonce` is refused rather than unescaped.
- String values may not contain a `"` either. A value's length is a prover
  hint, and the closing-quote and `,`/`}` checks also hold at the end of any
  later string claim; without this, `email` could be read as
  `bob@attacker.com","name":"x@victim.com` and `victim.com` proved from a
  token whose display name the holder chose (found 2026-10-28 by the compiler
  warnings audit; `claims::an_email_run_into_the_next_claim_is_refused`).
  v1 has no such check and is affected.
- `email_verified` must be the JSON boolean `true`; the string `"true"` (which
  Google's docs example shows) is refused, as in v1.

## Tests

```
scripts/build.sh oidc-domain-attestation            # build + scripts/post-build.sh
oidc-domain-attestation/scripts/mutation-check.sh   # which code refuses each case
(cd oidc-domain-attestation && nargo test)          # claims checks fed a dishonest value
```

`post-build.sh` regenerates fixtures (`scripts/make-fixtures.ts`: a fresh
RSA-2048 key, tokens shaped like Google's and Microsoft's, both nonce modes),
runs 12 accepted cases (four through `bb prove` / `bb verify` with the 214
public inputs compared to the reference layout) and 31 refusals, each refused
for a named reason.

`mutation-check.sh` deletes or neutralises one assert at a time and requires
the matching refusal fixture to be ACCEPTED by the mutant. On 2026-10-27 all 21
mutations were caught (each mutant accepted its fixture). Guards not in it
cannot be isolated by an honest witness, because another check refuses the
same input first: `base64_decode_offset is outside partial_data` (offset 0
underflows), `payload start is not in the first block` (the shifted read goes
out of bounds), `claim key is not inside the payload object` (the payload
starts with `{`), `claim value mismatch` (needs a dishonest hint), `claim value
has no opening quote`, `claim value has no closing quote`, `claim value is not
terminated`, `number claim is
empty`, `boolean claim is neither true nor false`.
