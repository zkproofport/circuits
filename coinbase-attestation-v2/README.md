# coinbase_attestation v2 (`coinbase_attestation_v2`)

Coinbase KYC whose revocation is bound by a signed statement: the prover looks
up the Coinbase EAS attestation right before proving and, only if it is
unrevoked, a key the circuit trusts signs a statement saying so. Two kinds of
signer, one circuit, and the proof does not say which signed:

| Kind | Who | Trust anchor pinned in the circuit |
|---|---|---|
| app | the phone, through Apple App Attest | Apple's App Attest INTERMEDIATE key, "Apple App Attestation CA 1" (`statement-signer/src/apple_ca.nr`) |
| server | the AI server (proofport-ai), through a Cloud KMS key | the server's P-256 Cloud KMS key (`statement-signer/src/server_key.nr`) |

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
     - the pinned intermediate key (CA 1, a constant) signed the credential
       certificate (P-384 over SHA-256); the TBS is walked to the P-256
       credential key, Apple's nonce extension and the App ID item, which
       must be
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
server key is a constant, and the app key must come out of a credential
certificate the pinned Apple intermediate signed. A prover cannot sign "not revoked" with a key of
their own under either kind.

The app-only checks sit inside `if signer_kind == KIND_APP { ... }`. Noir turns
every constraint inside into one that holds only when the condition is true,
so the server passes **zeros** for every App Attest input -- no dummy
certificate chain (the prototype probe's wart). The price is gates, measured
below: the branch costs 436,243 more than the same checks run unconditionally,
and both versions land in the same 2^21 dyadic size.

### Apple's intermediate is pinned, not verified from the root

Decided 2026-10-27 (`.claude/agents/circuits-dev.md`, "DECIDED 2026-10-27"):
the constant is the key of "Apple App Attestation CA 1", the intermediate,
SHA256(X || Y) = `0x8ef85f951d5958d17e728c881f11f059f370aff763503903a96417405b59747f`,
valid 2020-03-18 to 2030-03-13, issued by "Apple App Attestation Root CA"
(valid to 2045-03-15; apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem,
SHA-256 fingerprint `1C:B9:82:3B:...:C9:32`).

Why: verifying root -> intermediate in-circuit (SHA-384 of the intermediate
TBS, P-384 by the root, DER walk, cA = TRUE) costs this circuit 669,935 gates
and makes it 2^21 (1,654,257 gates; .srs 134,217,940 bytes, over GitHub's
100 MiB file limit; about twice the phone's proving cost). Pinned, it is
983,451 gates, 2^20.

The price: when Apple issues a successor intermediate and attestations start
chaining to it, every app-kind proof fails until a NEW release of this
circuit pins the new key (new vk, verifier redeploy on every chain,
app/SDK/AI release). Watch for it from 2029 at the latest.

`scripts/coinbase-attestation-v2/check-apple-vector.js` downloads Apple's root
from apple.com, checks that it signed CA 1's certificate (`apple-vector.json`),
and fails unless `statement-signer/src/apple_ca.nr` holds that certificate's key. The
`../app-attest-libs` tests verify the same root -> CA 1 link in-circuit on
Apple's bytes (`app_attest_signing_key`, the root-pinned entry point, stays in
the library for that reason; this circuit calls `app_attest_signing_key_under_ca`).

Not checked in-circuit: certificate validity dates (there is no trusted clock;
`attested_at` is the prover's claim), names, key identifiers, key usage.

### Production only

`APP_ATTEST_PRODUCTION = true` is a circuit constant, not a public input as in
the prototype. Reasons:

- Development (sandbox) keys chain to the same Apple intermediate and differ
  only in the AAGUID (zkPassport's real vector is a development key under CA 1). A
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
4. Cloud KMS `asymmetricSign` on the key version pinned in `statement-signer/src/server_key.nr`
   (algorithm `EC_SIGN_P256_SHA256`) with `digest.sha256 = digest`.
   Equivalently: ECDSA P-256 with SHA-256 over the 225 bytes.
5. KMS returns a DER `ECDSA-Sig-Value`. Convert to `r || s`, each 32 bytes
   big-endian, left-padded. If `s > n/2` (n = the P-256 order) replace `s`
   with `n - s`: the black box refuses a high `s`, and Google's
   create-validate-signatures page says nothing about normalising it.
6. Witness: `signer_kind = 2`, `client_data`, `statement_sig = r || s`,
   `attested_at` = the timestamp from step 2, and **zeros for every App Attest
   input** -- `credential_tbs`,
   `credential_sig`, `att_auth_data`, `att_client_data_hash`,
   `assertion_auth_data` all-zero, and `credential_tbs_len`,
   `att_auth_data_len`, `assertion_auth_data_len` = 0.
   The circuit does not read them for the server kind (fixture
   `server_ignores_chain_fields` passes a full app chain there and is
   accepted), so zeros are a convention, not a requirement. (Since CA 1 is
   pinned there are no `intermediate_*` inputs.)

Use a key that signs nothing else: the only domain separation is the 16-byte
magic and the circuit tag at the front of `client_data`.

What the server kind's trust rests on: whoever can use that KMS key -- the GCP
project's IAM, not hardware (see circuits-dev.md, "TEE review"). The proof does
not reveal the kind, so a dApp cannot choose to accept only app statements.

### The server key and the test key

`statement-signer/src/server_key.nr` holds one line, `pub global SERVER_KEY: [u8; 64] = [...]`
(X || Y), the AI server's Cloud KMS key. `--test-key` swaps in the **INSECURE
test key** for local work: its private key is
`SHA256("ZKProofport coinbase_attestation_v2 INSECURE test server key")` mod n
(`scripts/coinbase-attestation-v2/anchors.js`), so anyone can sign server
statements for it.

```
node scripts/statement-signer/set-server-key.js --kms projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V
node scripts/statement-signer/set-server-key.js --pem public.pem
node scripts/statement-signer/set-server-key.js --test-key       # back to the placeholder
node scripts/statement-signer/set-server-key.js --show
node scripts/statement-signer/set-server-key.js --require-real   # exit 1 while the test key is in
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
So `scripts/coinbase-attestation-v2/make-fixtures.sh` runs
`scripts/statement-signer/make-synthetic-anchors.sh`, which builds
`../coinbase-attestation-v2-synthetic-anchors/` (this circuit's source,
unchanged) against `../statement-signer-synthetic-anchors/` (the signer
library with only `src/apple_ca.nr` replaced by a synthetic P-384
intermediate, private key `SHA256("ZKProofport coinbase_attestation_v2 INSECURE synthetic App Attest intermediate")`,
and `src/server_key.nr` by the test key); both gitignored. It refuses to
continue if anything else differs. Every acceptance, refusal and mutation
case runs there.

The signer parts (both anchors, the App ID, the private signer kind, the one
P-256 statement check) live in `../statement-signer`, shared with
`oidc_domain_attestation` since 2026-10-28; moving them there left this
circuit's vk, verifier and .srs byte-identical. That circuit's 313-byte
"ZKProofport/PK/1" statement is signed by the same keys; the refusal cases
`oidc_statement_replay` and `oidc_statement_magic_swapped` show its
signature cannot stand in for a clientData here.

`real-anchors-check.sh` runs the cases that need THIS circuit:

| Case | Expected |
|---|---|
| `real_apple_chain`: a real credential certificate CA 1 signed (zkPassport's app) | the P-384 check passes in this circuit; refused at `Credential certificate is for another app` |
| `real_synthetic_ca`: the synthetic chain | refused: `Credential certificate is not signed by the App Attest intermediate` |
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
| pinned CA | the pinned key IS the CA 1 key Apple's root signed | checked | `check-apple-vector.js` (against apple.com's root); U `apples_root_signed_ca_1_with_sha384`, `ca_1_parses_to_the_key_that_signed_the_credential` |
| pinned CA | a chain under another intermediate | refused | A `cert_other_ca`; R `real_synthetic_ca`; M |
| pinned CA | real CA 1 signature on a real credential verifies in-circuit | passes | R `real_apple_chain` |
| root link | root -> intermediate checks (other root, swapped key, not a CA, wrong algorithm/curve/length/padding) | N/A in this circuit (CA 1 is pinned); kept as library tests | U `another_root_key_does_not_verify_ca_1`, `one_changed_byte_breaks_the_roots_signature`, `a_certificate_that_is_not_a_ca_is_refused`, `an_intermediate_*`, `a_wrong_intermediate_length_is_refused`, `bytes_after_the_intermediate_are_refused` |
| credential | signature over another TBS; by a key other than the pinned CA | refused | A `cert_bad_signature`, `cert_other_ca`; M |
| credential | for another app; high s | refused | A `cert_other_app`, `cert_high_s`; R `real_apple_chain`; U |
| attestation | authData not the certified one | refused | A `attestation_not_certified` |
| attestation | development key, consistently certified | refused | A `env_development`; M |
| assertion | another key; wrong RP ID; counter 0; high s | refused | A `assertion_other_key`, `assertion_wrong_rpid`, `assertion_counter_zero`, `assertion_high_s`; M |
| statement | wallet / revoked / schema / request / scope / timestamp changed; stale timestamp re-signed | refused | A `client_*`, `timestamp_changed`, `stale_timestamp_resigned`; M (six) |
| time | old timestamp both signed and public | ACCEPTED -- freshness is the verifier's | N/A (verifier) |
| boundary | credential / authData at their maxima (1000 / 256 / 128 vs real 852 / 164 / 37) | not exercised | gap |
| hostile | malformed DER | refused by asserts on every tag/length read; the signatures cover the TBS anyway | U, partial |
| authz / race | N/A -- a circuit has no caller beyond the wallet signature, and no async path | | |
| external | the EAS lookup and the network it rides on | outside the circuit (gap below) | |

Mutation status (2026-10-28, CA 1 pinned): `mutation-check.sh` runs fifteen
cases and every one is caught -- each named check removed, its refusal case is
then ACCEPTED: the six clientData asserts, the kind assert (kind_unknown,
kind_zero), the branch condition forced false (app_chain_with_server_signature),
the statement signature (server_other_key, assertion_other_key), the credential
signature under the pinned CA (cert_other_ca), the environment, the assertion
RP ID and the counter. The three root-link cases (other root, swapped key,
not-a-CA) are gone with the root link. Until 2026-10-28 five of these cases
never ran correctly: the case list used `|` as its field separator while the
texts contain Noir's `|`, so they compiled broken mutants that "still refused";
the separator is now `~`.

## Measurements

2026-10-28, CA 1 pinned, Apple M5 Pro, nargo 1.0.0-beta.19, bb
4.2.0-aztecnr-rc.2. Gates are `bb gates` (deterministic); sizes are the files
`scripts/build.sh coinbase-attestation-v2` wrote.

| | v1 `coinbase_attestation` | prototype `coinbase_app_attest_poc` | v2, root pinned (fc34588) | **v2, CA 1 pinned** |
|---|---|---|---|---|
| `bb gates` circuit_size | 397,809 | 860,718 | 1,654,257 | **983,451** |
| ACIR opcodes | 14,646 | 104,144 | 431,835 | 152,391 |
| dyadic size | 2^19 | 2^20 | 2^21 (.srs 134,217,940 B) | **2^20** (vk log size 20; .srs 67,109,076 B) |
| proof | 9,920 bytes | 10,304 bytes | 10,688 bytes | 10,304 bytes |
| public inputs | 128 (4,096 bytes) | 226 (7,232 bytes) | 193 (6,176 bytes) | 193 (6,176 bytes) |
| vk / Solidity verifier | 1,888 B / 2,461 lines | 1,888 B / 2,461 lines | 1,888 B / 2,461 lines | 1,888 B / 2,461 lines |

983,451 is 65,125 (6.2%) under 2^20. The probe that decided this
(`../_probes/coinbase-attestation-v2/pinned-intermediate`, 984,404) carries a
measurement sink the circuit does not. Per-part marginal costs of the pinned
circuit, and why the root link cost 669,935 inside the branch rather than its
standalone 385,994: `../_probes/coinbase-attestation-v2/README.md`.

`bb prove` wall time and peak RSS: `scripts/coinbase-attestation-v2/measure.sh 3`
(results recorded in `.claude/agents/circuits-dev.md` with the date and load).

## Distribution

The 2^20 `.srs` is 67,109,076 bytes, under GitHub's 100 MiB file limit, so it
is committed beside the json, vk, verifier and SHA256SUMS, and the app fetches
it from a release tag like every other circuit.

## Dependencies

- `../app-attest-libs/` (package `app_attest`): DER walk, credential
  certificate, attestation authData, assertion digest; this circuit calls
  `app_attest_signing_key_under_ca`. The root -> intermediate code
  (`intermediate.nr`) stays for the library tests and a future root-pinned
  circuit.
- P-384: `zkpassport/noir-ecdsa` v0.3.0 + `noir-bignum` v0.9.2-1 +
  `noir_bigcurve` v0.13.2-1, the newest tags that compile on beta.19.
- SHA-384: `zkpassport/sha512` v0.1.1, used only by the library's
  root -> intermediate tests now.
- P-256: `std::ecdsa_secp256r1`. SHA-256: `noir-lang/sha256` v0.3.0.
- `nargo compile` reports "Brillig function call isn't properly covered by a
  manual constraint" three times: `noir_bigcurve` `ops/msm.nr:217` and
  `noir-lang/sha256` `sha256.nr:167` (twice, the fixed-length `digest` of
  client_data and of the assertion nonce). The prototype at `33344e2` reports
  the same three, so the `if` branch did not introduce them. Each was
  reviewed and is constrained by the code after the call.
