# coinbase_attestation v2 (`coinbase_attestation_v2`)

Coinbase KYC whose revocation is bound by a signed statement: the prover looks
up the Coinbase EAS attestation right before proving and, only if it is
unrevoked, a key the circuit trusts signs a statement saying so. Two kinds of
signer, one circuit, and the proof does not say which signed:

| Kind | Who | Trust anchor pinned in the circuit |
|---|---|---|
| app | the phone, through Apple App Attest | Apple App Attestation Root CA key (`src/apple_root.nr`) |
| server | the AI server (proofport-ai), through a Cloud KMS key | the server's P-256 key (`src/server_key.nr`) -- **currently the INSECURE test key** |

Built from the `coinbase_app_attest_poc` prototype (circuits `b281485`, build
output `33344e2`, which proofport-app pins; that commit stays reachable on this
branch). The package is `coinbase_attestation_v2` while v1 still lives in
`../coinbase-attestation`. The circuit ID it serves is the canonical
`coinbase_attestation`: the nullifier tag and the clientData's statement kind
are `keccak256("coinbase_attestation")`. Shipping it means replacing v1 in
place (circuits v2.0.0).

Decisions behind it: `.claude/agents/circuits-dev.md`, "Decisions, 2026-10-23"
(App Attest revocation, EIP-712, wallet nullifier) and the user's 2026-10-23
call that keys should not need rotation, so there is no registry contract and
no public trust-anchor input: both anchors are circuit constants.

## What the circuit proves

1. The wallet signed the request -- personal_sign over `signal_hash`, or an
   EIP-712 action (`coinbase_libs::signed_message::signed_digest`, shared with
   `giwa_attestation`; the two modes are mutually exclusive).
2. v1's checks, unchanged: an `attestAccount(wallet)` EIP-1559 transaction to
   Coinbase's attester, signed by a key whose address is in the public signer
   Merkle root.
3. A 225-byte statement (`client_data`, below) naming this wallet, the public
   `attested_at`, Coinbase's KYC schema and attester, revoked = 0, this
   request's digest and this scope, signed with ECDSA P-256 by:
   - **app** (`signer_kind = 1`): a credential key Apple vouches for --
     - Apple's root key (constant) signed the intermediate TBS
       (ECDSA P-384 over SHA-384); the TBS is walked to the intermediate's
       P-384 key, must use ecdsa-with-SHA384, and must carry exactly one
       basicConstraints with cA = TRUE;
     - that intermediate key signed the credential certificate (P-384 over
       SHA-256); the TBS is walked to the P-256 credential key, Apple's nonce
       extension and the App ID item, which must be
       `R4G32CVY29.com.masselabs.zkproofport`;
     - the attestation authData hashes (with its clientDataHash) to that
       nonce, has RP ID hash = SHA256(App ID), counter 0, and the
       **production** AAGUID;
     - the assertion authData has RP ID hash = SHA256(App ID) and counter > 0,
       and the signed digest is SHA256(SHA256(authData || SHA256(client_data))).
   - **server** (`signer_kind = 2`): the pinned server key, over
     SHA256(client_data).
   Any other `signer_kind` is refused.
4. Nullifier = keccak(keccak(wallet ++ CIRCUIT_TAG) ++ scope)
   (`verify_wallet_nullifier`). Existing v1 nullifiers (derived from
   `signal_hash`) do not carry over; accepted in the decision.

### How the private kind byte stays sound

The two kinds end in ONE P-256 check (`std::ecdsa_secp256r1`, a Barretenberg
black box). They differ only in where the key and digest come from: the
server key is a constant, and the app key must come out of a certificate chain
that ends at Apple's root. A prover cannot sign "not revoked" with a key of
their own under either kind.

The app-only checks sit inside `if signer_kind == KIND_APP { ... }`. Noir turns
every constraint inside into one that holds only when the condition is true,
so the server passes **zeros** for every App Attest input -- no dummy
certificate chain (the prototype probe's wart). The price is gates, measured
below: the branch costs 436,243 more than the same checks run unconditionally,
and both versions land in the same 2^21 dyadic size.

### Apple's intermediate is verified here, not pinned

Only the root is a constant: "Apple App Attestation Root CA", valid to
2045-03-15 (apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem,
SHA-256 fingerprint `1C:B9:82:3B:...:C9:32`). When "Apple App Attestation CA 1"
(valid to 2030-03-13) is replaced, devices present the new intermediate and
nothing here changes. This is how zkPassport's FaceMatch circuit treats it.
`scripts/coinbase-attestation-v2/check-apple-vector.js` downloads the PEM and
fails unless `src/apple_root.nr` holds its key; the library tests verify
Apple's real root -> CA 1 -> credential chain in-circuit on Apple's bytes.

Not checked in-circuit: certificate validity dates (there is no trusted clock;
`attested_at` is the prover's claim), names, key identifiers, key usage.

### Production only

`APP_ATTEST_PRODUCTION = true` is a circuit constant, not a public input as in
the prototype. Reasons:

- Development (sandbox) keys chain to the same Apple root and differ only in
  the AAGUID (zkPassport's real vector is a development key under CA 1). A
  public flag would leave every verifier one forgotten check away from
  accepting them.
- It means nothing for the server kind, and a public value that only the app
  kind can set to `false` would reveal the kind whenever it is `false`.
- Nothing needs development keys: Apple's entitlement page says builds from
  TestFlight / the App Store / Enterprise use production whatever the
  entitlement says, and a development build can use production by setting
  `com.apple.developer.devicecheck.appattest-environment` to `production`
  (developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.devicecheck.appattest-environment).
  proofport-app's iOS target sets no such entitlement today, so an Xcode
  development build would use the sandbox and be refused
  (`App Attest environment does not match`) until it does.

## Public inputs

In order. Each byte of a `[u8; 32]` is one field element.

| # | Name | Type | Field elements |
|---|---|---|---|
| 1 | `signal_hash` | `[u8; 32]` | 32 |
| 2 | `domain_separator` | `[u8; 32]` | 32 |
| 3 | `action_hash` | `[u8; 32]` | 32 |
| 4 | `signer_list_merkle_root` | `[u8; 32]` | 32 |
| 5 | `scope` | `[u8; 32]` | 32 |
| 6 | `nullifier` | `[u8; 32]` | 32 |
| 7 | `attested_at` | `u64` (unix seconds) | 1 |

1-6 are `giwa_attestation`'s, in its order. 193 field elements (6,176 bytes as
`bb` writes `public_inputs`). The prototype's `app_attest_ca_key_hash` and
`app_attest_production` are gone (above), and the signer kind is never public.

The App Attest counter is NOT public: two proofs from one phone would carry
consecutive numbers, which links them.

What a verifier must do beyond `verify()`: check `attested_at` against its own
clock (a window, e.g. 10 minutes), and everything it already does for the
signer root, scope and nullifier. There is no trust anchor to compare: both are
in the vk.

## clientData format (what both signers sign)

Fixed 225 bytes, binary, every field at a fixed offset. No JSON or CBOR.

| Offset | Length | Field | Circuit check |
|---|---|---|---|
| 0 | 16 | ASCII `ZKProofport/AA/1` | equal |
| 16 | 32 | `keccak256("coinbase_attestation")` | equal to `CIRCUIT_TAG` |
| 48 | 20 | wallet address | equal to the proven wallet |
| 68 | 8 | timestamp, unix seconds, big-endian | equal to public `attested_at` |
| 76 | 32 | EAS schema uid | Coinbase Verified Account `0xf8b05c79...0de9` |
| 108 | 20 | EAS attester | Coinbase `0x357458739F90461b99789350868CD7CF330Dd7EE` |
| 128 | 32 | attestation uid the signer found | carried only |
| 160 | 1 | revoked: `0x00` = found unrevoked | must be `0x00` |
| 161 | 32 | request digest: the exact 32 bytes the wallet signed (`keccak("\x19Ethereum Signed Message:\n32" ++ signal_hash)` or `keccak(0x1901 ++ domain_separator ++ action_hash)`) | equal to the circuit's `signed_digest` |
| 193 | 32 | scope | equal to public `scope` |

The uid is not checked: the circuit proves the transaction, not the EAS
record, and a uid cannot be tied to the transaction in-circuit. Making it
public would identify the wallet.

## What the server signs

Exactly this, in proofport-ai, for one proof request:

1. Look up the wallet's Coinbase Verified Account attestation (Base EAS,
   schema and attester above) and confirm it is unrevoked. Refuse otherwise.
2. Build the 225-byte `client_data` above, timestamp = now, revoked = `0x00`,
   with the request digest and scope of THIS request.
3. `digest = SHA256(client_data)`.
4. Cloud KMS `asymmetricSign` on the key version pinned in `src/server_key.nr`
   (algorithm `EC_SIGN_P256_SHA256`) with `digest.sha256 = digest`.
   Equivalently: ECDSA P-256 with SHA-256 over the 225 bytes.
5. KMS returns a DER `ECDSA-Sig-Value`. Convert to `r || s`, each 32 bytes
   big-endian, left-padded. If `s > n/2` (n = the P-256 order) replace `s`
   with `n - s`: the black box refuses a high `s`, and Google's
   create-validate-signatures page says nothing about normalising it.
6. Witness: `signer_kind = 2`, `client_data`, `statement_sig = r || s`,
   `attested_at` = the timestamp from step 2, and **zeros for every App Attest
   input** -- `intermediate_tbs`, `intermediate_sig`, `credential_tbs`,
   `credential_sig`, `att_auth_data`, `att_client_data_hash`,
   `assertion_auth_data` all-zero, and `intermediate_tbs_len`,
   `credential_tbs_len`, `att_auth_data_len`, `assertion_auth_data_len` = 0.
   The circuit does not read them for the server kind (fixture
   `server_ignores_chain_fields` passes a full app chain there and is
   accepted), so zeros are a convention, not a requirement.

Use a key that signs nothing else: the only domain separation is the 16-byte
magic and the circuit tag at the front of `client_data`.

What the server kind's trust rests on: whoever can use that KMS key -- the GCP
project's IAM, not hardware (see circuits-dev.md, "TEE review"). The proof does
not reveal the kind, so a dApp cannot choose to accept only app statements.

### The server key: placeholder, test key, and the swap

`src/server_key.nr` holds one line, `pub global SERVER_KEY: [u8; 64] = [...]`
(X || Y). Until the Cloud KMS key exists it is the **INSECURE test key**: its
private key is `SHA256("ZKProofport coinbase_attestation_v2 INSECURE test server key")`
mod n (`scripts/coinbase-attestation-v2/anchors.js`), so anyone can sign
server statements for it.

```
node scripts/coinbase-attestation-v2/set-server-key.js --kms projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V
node scripts/coinbase-attestation-v2/set-server-key.js --pem public.pem
node scripts/coinbase-attestation-v2/set-server-key.js --test-key       # back to the placeholder
node scripts/coinbase-attestation-v2/set-server-key.js --show
node scripts/coinbase-attestation-v2/set-server-key.js --require-real   # exit 1 while the test key is in
```

`--kms` runs `gcloud kms keys versions describe` (refuses any algorithm but
`EC_SIGN_P256_SHA256`) and `get-public-key`, then rewrites that one line and
nothing else. Then rebuild (`scripts/build.sh coinbase-attestation-v2`): the
vk and the verifier change. `scripts/deploy_verifier.sh coinbase-attestation-v2
<base|mainnet>` refuses while the test key is pinned; testnets are allowed.
After the swap, the real circuit can no longer accept a fixture server
statement (nobody has the KMS private key); `real-anchors-check.sh` then
expects `real_server_action` to be REFUSED, and the server cases keep running
in the synthetic-anchors copy.

## Two circuits in the acceptance run

No fixture can carry an Apple-signed credential certificate for our App ID
together with the device key that signs the assertion; that needs a phone.
So `scripts/coinbase-attestation-v2/make-fixtures.sh` builds
`../coinbase-attestation-v2-synthetic-anchors/` (gitignored) from this
circuit's current source, replacing only `src/apple_root.nr` (with a synthetic
P-384 root, private key `SHA256("ZKProofport coinbase_attestation_v2 INSECURE synthetic App Attest root")`)
and `src/server_key.nr` (with the test key). It refuses to continue if any
other file differs. Every acceptance, refusal and mutation case runs there.

`real-anchors-check.sh` runs the cases that need THIS circuit:

| Case | Expected |
|---|---|
| `real_apple_chain`: Apple's real root -> CA 1 -> a real credential certificate (zkPassport's app) | both P-384 checks pass in this circuit; refused at `Credential certificate is for another app` |
| `real_synthetic_root`: the synthetic chain | refused: `Intermediate is not signed by Apple's App Attestation root` |
| `real_server_action`: server statement by the test key | accepted while the test key is pinned; refused after the swap |

## Edge-case matrix

Drawn up before the fixtures. A = acceptance run on the synthetic-anchors copy
(`scripts/action-circuit-acceptance.sh coinbase-attestation-v2-synthetic-anchors`),
R = `real-anchors-check.sh`, U = `../app-attest-libs` unit tests,
M = `mutation-check.sh` (the named check deleted or bypassed, the case is then
ACCEPTED).

| Row | Case | Expected | Where |
|---|---|---|---|
| accept | app kind, action / no-action, real Coinbase tx | accepted; action proof verifies | A `action`, `no_action`, proof |
| accept | server kind, action / no-action | accepted; proof verifies | A `server_action`, `server_no_action`, proof; R `real_server_action` |
| accept | server kind with a full app chain in the ignored inputs | accepted | A `server_ignores_chain_fields` |
| request | both modes; half an action; nothing signed; signature over the other mode | refused | A `both_modes`, `half_action_*`, `nothing_signed`, `signature_from_other_message` |
| nullifier / coinbase | wrong nullifier; wrong signer root | refused | A `wrong_nullifier`, `wrong_signer_root` |
| kind | app statement with kind byte = server | refused | A `kind_flipped_app_to_server` |
| kind | server statement with kind byte = app (zero chain) | refused | A `kind_flipped_server_to_app` |
| kind | server-signed, kind byte 0 / 3 | refused | A `kind_zero`, `kind_unknown`; M |
| kind | app chain present, statement signed by the server key | refused | A `app_chain_with_server_signature`; M (branch condition forced false) |
| server | statement signed by another P-256 key | refused | A `server_other_key`; M |
| server | high-s server signature | refused | A `server_high_s` |
| server | server statement saying revoked | refused | A `server_client_revoked` |
| root | consistent chain under another root | refused | A `app_other_root`; R `real_synthetic_root`; U `another_root_key_does_not_verify_ca_1`; M |
| root | intermediate key replaced, root signature kept | refused | A `intermediate_key_swapped`; U `one_changed_byte_breaks_the_roots_signature`; M |
| root | root-signed certificate that is not a CA | refused | A `intermediate_not_ca`; U `a_certificate_that_is_not_a_ca_is_refused`; M |
| root | root signature in high-s form | refused | A `intermediate_high_s` |
| root | Apple's real root -> CA 1 verifies in-circuit | passes | U `apples_root_signed_ca_1_with_sha384`, `ca_1_parses_to_the_key_that_signed_the_credential`; R `real_apple_chain` |
| intermediate | wrong algorithm; P-521 key; bad length; non-zero padding | refused | U `an_intermediate_with_another_algorithm_is_refused`, `an_intermediate_on_another_curve_is_refused`, `a_wrong_intermediate_length_is_refused`, `bytes_after_the_intermediate_are_refused` |
| credential | signature over another TBS; by a key the root never certified | refused | A `cert_bad_signature`, `cert_other_ca`; M |
| credential | for another app; high s | refused | A `cert_other_app`, `cert_high_s`; R `real_apple_chain`; U |
| attestation | authData not the certified one | refused | A `attestation_not_certified` |
| attestation | development key, consistently certified | refused | A `env_development`; M |
| assertion | another key; wrong RP ID; counter 0; high s | refused | A `assertion_other_key`, `assertion_wrong_rpid`, `assertion_counter_zero`, `assertion_high_s`; M |
| statement | wallet / revoked / schema / request / scope / timestamp changed; stale timestamp re-signed | refused | A `client_*`, `timestamp_changed`, `stale_timestamp_resigned`; M (six) |
| time | old timestamp both signed and public | ACCEPTED -- freshness is the verifier's | N/A (verifier) |
| boundary | intermediate / credential / authData at their maxima (600 / 1000 / 256 / 128 vs real 460 / 852 / 164 / 37) | not exercised | gap |
| hostile | malformed DER | refused by asserts on every tag/length read; the signatures cover the TBS anyway | U, partial |
| authz / race | N/A -- a circuit has no caller beyond the wallet signature, and no async path | | |
| external | the EAS lookup and the network it rides on | outside the circuit (gap below) | |

Mutation status (2026-10-23): seven of the eighteen M cases have been run and
each refusal turned into an acceptance -- the six clientData asserts and the
branch condition forced to `false` (`app_chain_with_server_signature`). The
other eleven (kind assert x2, statement signature x2, root signature x2, not-a-CA,
credential signature, environment, assertion RP ID, counter) are written but
not yet run: the first attempt deleted only the message line of multi-line
asserts, which leaves a message-less assert that still refuses (fixed: those
are now replaced by `true`), and the rerun could not finish under the
machine's load. Run `scripts/coinbase-attestation-v2/mutation-check.sh
'kind_|other_key|other_root|key_swapped|not_ca|other_ca|env_|rpid|counter'`.

## Measurements

2026-10-23/24, Apple M5 Pro, nargo 1.0.0-beta.19, bb 4.2.0-aztecnr-rc.2.
Gates are `bb gates` (deterministic); sizes are the files the build wrote.

| | v1 `coinbase_attestation` | prototype `coinbase_app_attest_poc` | v2 |
|---|---|---|---|
| `bb gates` circuit_size | 397,809 | 860,718 | **1,654,257** |
| ACIR opcodes | 14,646 | 104,144 | 431,835 |
| dyadic size | 2^19 | 2^20 | **2^21** (.srs 134,217,940 bytes) |
| proof | 9,920 bytes | 10,304 bytes | 10,688 bytes |
| public inputs | 128 (4,096 bytes) | 226 (7,232 bytes) | 193 (6,176 bytes) |
| vk / Solidity verifier | 1,888 B / 2,461 lines | 1,888 B / 2,461 lines | 1,888 B / 2,461 lines |

v1 and prototype columns: prototype README at `33344e2` and `bb gates` on v1's
committed json. Where v2's gates go (`../_probes/coinbase-attestation-v2/`):

| Part | circuit_size |
|---|---|
| root link: SHA-384 of the intermediate TBS (<= 600 B) + P-384 by Apple's root + intermediate DER walk (probe `root-link`) | 385,994 |
| of which SHA-384 alone, 5 blocks (probe `sha384-intermediate`) | 176,305 |
| v2 with the app checks run unconditionally (probe `unconditional-app-checks`) | 1,218,014 |
| the `if signer_kind == KIND_APP` branch, i.e. v2 minus that | 436,243 |

The root link's cost INSIDE v2 is not the standalone 385,994: measured by
removing it from the whole circuit (probe `pinned-intermediate`, Apple's CA 1
key pinned instead, 2026-10-27) v2 drops from 1,654,257 to 984,404 gates,
2^20 (vk log size 20), 64,172 under the limit. The difference is predication:
inside `if signer_kind == KIND_APP` the non-native SHA-384 / P-384 work costs
more, and the branch overhead falls from 436,243 to 131,334 once the root link
is out of it. So subtracting 385,994 from 1,654,257 (= 1,268,263, still 2^21)
is the wrong model. Fitting 2^20 means pinning CA 1's key, as the prototype
did, with a circuit release (new vk and verifier) when Apple issues a new
intermediate, or splitting the root link into a separate proof. Per-part
marginal costs of the pinned circuit: `../_probes/coinbase-attestation-v2/README.md`.

NOT YET MEASURED: `bb prove` wall time and peak RSS. The machine ran at load
average 108-124 on 18 cores from other workloads for the whole session (one
mutation case took 2 h instead of ~5 min), so any timing would describe the
load, not the circuit. `scripts/coinbase-attestation-v2/measure.sh 3` produces
them on an idle machine. Expect roughly double the prototype's 3.2-3.5 s and
2.1 GiB (dyadic size doubled) -- an estimate, not a measurement.

## Distribution

The `.srs` for 2^21 is 134,217,940 bytes. GitHub refuses files over 100 MiB
("About large files on GitHub"), so it is NOT committed (`.gitignore` here),
and the app cannot fetch it from a commit as it fetched the prototype's 2^20
one. The json, vk, verifier and SHA256SUMS (which lists the .srs digest) are
committed. Where the .srs is served from is a decision still open.

## Dependencies

- `../app-attest-libs/` (package `app_attest`): DER walk, intermediate,
  credential certificate, attestation authData, assertion digest.
- P-384: `zkpassport/noir-ecdsa` v0.3.0 + `noir-bignum` v0.9.2-1 +
  `noir_bigcurve` v0.13.2-1, the newest tags that compile on beta.19.
- SHA-384: `zkpassport/sha512` v0.1.1 (the version `deps/noir_rsa` already pins).
- P-256: `std::ecdsa_secp256r1`. SHA-256: `noir-lang/sha256` v0.3.0.
- `nargo compile` reports "Brillig function call isn't properly covered by a
  manual constraint" three times: `noir_bigcurve` `ops/msm.nr:217` and
  `noir-lang/sha256` `sha256.nr:167` (twice, the fixed-length `digest` of
  client_data and of the assertion nonce). The prototype at `33344e2` reports
  the same three, so the `if` branch did not introduce them. Upstream code;
  not audited here.

## What a real device must still confirm

- The App ID item: [1204] (`BF 89 34`) in extension 1.2.840.113635.100.8.5,
  undocumented by Apple; the prefix is team id `R4G32CVY29` and changes if the
  app moves to the corporate developer account.
- Assertion authenticatorData length and flags, and whether the CBOR
  extensions Apple now lists appear (the circuit allows 128 bytes and does not
  read them). Attestation authData length with extensions (allows 256).
- The app keeps the attestation object (credCert, authData, its
  clientDataHash) AND the intermediate certificate (x5c[1]) from `attestKey`,
  converts the three DER signatures to r || s, and puts each s in low form.
- Not covered: a device owner who installs their own root CA and rewrites the
  EAS answer the app reads. Certificate pinning narrows it.
