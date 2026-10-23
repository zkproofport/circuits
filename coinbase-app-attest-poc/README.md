# coinbase_app_attest_poc

PROTOTYPE. Coinbase KYC whose revocation is enforced through Apple App
Attest, the way zkPassport's FaceMatch uses App Attest: the app looks up the
Coinbase EAS attestation right before proving, and only if it is unrevoked
asks App Attest to sign a statement saying so; the circuit verifies Apple's
credential certificate and that signature. The same change adds the optional
EIP-712 action and moves the nullifier to the wallet + circuit-tag rule.
Decided 2026-10-23 (`.claude/agents/circuits-dev.md`, "Decisions").

Not canonical and not deployed. The App Attest material in the fixtures is
synthetic; nothing here has seen a real device's assertion yet.

The build output the app downloads is committed (`target/<name>.json`, `.srs`,
`.srs.toolchain`, `SHA256SUMS`, `target/vk/`), so proofport-app's App Attest
development switch can prove this circuit on a phone from this branch. It is
read by commit, not by branch name: the app pins the commit that holds these
files (`proofport-app/src/config/prototypeCircuits.ts`). No verifier contract
exists for it; proofs are checked off-chain only.

## What the circuit proves

1. The wallet signed the request -- personal_sign over `signal_hash`, or an
   EIP-712 action (`coinbase_libs::signed_message::signed_digest`, shared with
   `giwa_attestation`; the two modes are mutually exclusive).
2. `coinbase_attestation`'s checks, unchanged: an `attestAccount(wallet)`
   EIP-1559 transaction to Coinbase's attester, signed by a key whose address
   is in the public signer Merkle root.
3. App Attest:
   - the intermediate CA key hashes to the public `app_attest_ca_key_hash`;
   - it signed the credential certificate (ECDSA P-384 over SHA-256 of the TBS);
   - the TBS is walked with bounded DER parsing to the P-256 credential key,
     Apple's nonce extension, and the App ID item, which must be
     `R4G32CVY29.com.masselabs.zkproofport`;
   - the attestation authData hashes (with its clientDataHash) to that nonce,
     has RP ID hash = SHA256(App ID), counter 0, and the AAGUID of the
     environment named by the public `app_attest_production`;
   - the credential key signed an assertion: P-256 over
     SHA256(SHA256(authenticatorData || SHA256(clientData))), with RP ID hash
     = SHA256(App ID) and counter > 0;
   - clientData (below) names this wallet, the public `attested_at`, Coinbase's
     KYC schema and attester, revoked = 0, this request's digest and this scope.
4. Nullifier = keccak(keccak(wallet ++ CIRCUIT_TAG) ++ scope)
   (`verify_wallet_nullifier`).

### The nullifier tag

`CIRCUIT_TAG = keccak256("coinbase_attestation")`, the canonical id of the
circuit this prototype becomes (circuits v2.0.0), not this package's name. The
nullifiers this produces are the ones the shipped circuit will produce, and
`proofport-ai`'s `computeWalletNullifier(address, circuitId)` derives the tag
from the circuit id. Consequence, already accepted in the decision: existing
`coinbase_attestation` nullifiers (derived from `signal_hash`) do not carry
over. The scope is unchanged: `scope = keccak256(scope_string)`, public. The
same tag is the clientData's statement kind (offset 16), so an assertion made
for this circuit cannot be presented to another one.

### Where the intermediate CA key lives, and why

The chain is Apple root -> "Apple App Attestation CA 1" -> credential
certificate -> assertion. The first link is the same for everyone, so it is
verified outside the circuit (`scripts/coinbase-app-attest-poc/check-apple-vector.js`
does it against Apple's published root). The circuit takes the intermediate
key as a private input and exposes `SHA256(X || Y)` as a public input, rather
than compiling the key in:

- Apple can rotate or add an intermediate (CA 1 is valid to 2030-03-13);
  a public hash changes a verifier's configuration, a compiled-in key changes
  the circuit, its vk and every deployed verifier.
- The same circuit runs the synthetic fixtures and real devices; only the
  pinned hash differs.
- 32 bytes instead of 96 in the public inputs, for one SHA-256 (two blocks).

The verifier MUST compare it with Apple's: `0x8ef85f951d5958d17e728c881f11f059f370aff763503903a96417405b59747f`
for "Apple App Attestation CA 1" (printed by the check script). A proof with
another hash proves nothing about Apple.

## Public inputs

In order. Each byte of a `[u8; 32]` is one field element in the proof's
public-input vector, as in every circuit here.

| # | Name | Type | Bytes | Field elements |
|---|---|---|---|---|
| 1 | `signal_hash` | `[u8; 32]` | 32 | 32 |
| 2 | `domain_separator` | `[u8; 32]` | 32 | 32 |
| 3 | `action_hash` | `[u8; 32]` | 32 | 32 |
| 4 | `signer_list_merkle_root` | `[u8; 32]` | 32 | 32 |
| 5 | `scope` | `[u8; 32]` | 32 | 32 |
| 6 | `nullifier` | `[u8; 32]` | 32 | 32 |
| 7 | `app_attest_ca_key_hash` | `[u8; 32]` | 32 | 32 |
| 8 | `attested_at` | `u64` (unix seconds) | 8 | 1 |
| 9 | `app_attest_production` | `bool` | 1 | 1 |

1-6 are `giwa_attestation`'s, in its order. 226 field elements in all
(7,232 bytes as `bb` writes `public_inputs`).

The counter is NOT public. A per-key counter is a low-entropy, increasing
number: two proofs from one phone in different scopes would carry 41 and 42,
which links them. Freshness comes from `attested_at`; replay into another
proof is blocked by the request digest and scope inside clientData.

What a verifier must do beyond `verify()`: pin `app_attest_ca_key_hash`,
check `attested_at` against its own clock (a window, e.g. 10 minutes),
decide whether it accepts `app_attest_production = false`, and everything it
already does for the signer root, scope and nullifier.

## clientData format (what the app signs)

Fixed 225 bytes, binary, every field at a fixed offset. No JSON or CBOR: a
parser is where two readers disagree about one message.

| Offset | Length | Field | Circuit check |
|---|---|---|---|
| 0 | 16 | ASCII `ZKProofport/AA/1` | equal |
| 16 | 32 | `keccak256("coinbase_attestation")` | equal to `CIRCUIT_TAG` |
| 48 | 20 | wallet address | equal to the proven wallet (`user_address`) |
| 68 | 8 | timestamp, unix seconds, big-endian | equal to public `attested_at` |
| 76 | 32 | EAS schema uid | Coinbase Verified Account `0xf8b05c79...0de9` |
| 108 | 20 | EAS attester | Coinbase `0x357458739F90461b99789350868CD7CF330Dd7EE` |
| 128 | 32 | attestation uid the app found | carried only -- see below |
| 160 | 1 | revoked: `0x00` = found unrevoked | must be `0x00` |
| 161 | 32 | request digest: the exact 32 bytes the wallet signed -- `keccak("\x19Ethereum Signed Message:\n32" ++ signal_hash)` or the EIP-712 digest `keccak(0x1901 ++ domain_separator ++ action_hash)` | equal to the circuit's `signed_digest` |
| 193 | 32 | scope | equal to public `scope` |

The app sends `SHA256(clientData)` as `clientDataHash` to
`DCAppAttestService.generateAssertion`. The attestation uid is not checked:
the circuit proves the transaction, not the EAS record, and a uid cannot be
tied to the transaction in-circuit (it hashes `time`, which the transaction
does not carry). It is in the signed bytes so a later audit of the app can
see what it looked up. Making it public would identify the wallet.

## Edge-case matrix

Drawn up before the fixtures were generated. Every row is a case in
`scripts/action-circuit-acceptance.sh coinbase-app-attest-poc` (A), a unit
test in `../app-attest-libs/src/tests.nr` / `der.nr` (U), or marked N/A.

| Row | Case | Expected | Where |
|---|---|---|---|
| accept | action mode, real Coinbase tx, synthetic App Attest | accepted, proof verifies | A `action` + proof |
| accept | no-action mode | accepted | A `no_action` |
| request | action and signal both set | refused | A `both_modes` |
| request | half an action (no hash / no domain), nothing signed | refused | A `half_action_*`, `nothing_signed` |
| request | user signature over the other mode's message | refused | A `signature_from_other_message` |
| nullifier | wrong nullifier | refused | A `wrong_nullifier` |
| coinbase | wrong signer root | refused | A `wrong_signer_root` |
| CA | public CA hash changed | refused | A `wrong_ca_key_hash` |
| CA | cert signed by another P-384 key (presented with that key) | refused | A `cert_other_ca` |
| CA | right key, signature over another TBS | refused | A `cert_bad_signature` |
| CA | Apple's signature in high-s form | refused (prover must send low s) | A `cert_high_s` |
| cert | real Apple certificate verifies and parses | accepted | U `apple_signed_this_certificate_with_sha256`, `the_real_certificate_parses_to_its_key_and_nonce` |
| cert | one byte of a real certificate changed | signature fails | U `one_changed_byte_breaks_apples_signature` |
| cert | certificate for another app (same length id; different length id) | refused | A `cert_other_app`; U `the_real_certificate_is_not_ours`, `our_app_id_does_not_match_theirs` |
| cert | signature algorithm not ecdsa-with-SHA256 | refused | U `another_signature_algorithm_is_refused` |
| cert | TBS length disagrees with its header; non-zero padding | refused | U `a_wrong_length_is_refused`, `bytes_after_the_tbs_are_refused` |
| DER | non-minimal length, 3-byte length form | refused | U `der.nr` tests |
| attestation | authData not the one the cert's nonce covers | refused | A `attestation_not_certified` |
| attestation | environment differs from public input | refused | A `env_mismatch` |
| assertion | signed by another P-256 key | refused | A `assertion_other_key` |
| assertion | wrong RP ID hash (re-signed) | refused | A `assertion_wrong_rpid` |
| assertion | counter 0 | refused | A `assertion_counter_zero` |
| assertion | high-s P-256 signature | refused (black box) | A `assertion_high_s` |
| clientData | wallet != proven wallet | refused | A `client_wallet_mismatch` |
| clientData | revoked marker set | refused | A `client_revoked` |
| clientData | another schema | refused | A `client_other_schema` |
| clientData | genuine assertion for another request (replay) | refused | A `client_other_request` |
| clientData | another scope | refused | A `client_other_scope` |
| time | public timestamp changed after signing | refused | A `timestamp_changed` |
| time | app signed an old timestamp, public says now | refused | A `stale_timestamp_resigned` |
| time | old timestamp both signed and public | ACCEPTED by the circuit -- freshness is the verifier's check | N/A (verifier) |
| boundary | TBS / authData at their maximum lengths | not exercised; maxima 1000 / 256 / 128 vs 852 / 164 / 37 real | gap |
| hostile | malformed DER from a prover | refused by asserts on every tag/length read; the CA signature covers the TBS anyway | U, partial |
| authz | N/A -- a circuit has no caller identity beyond the wallet signature | | |
| race | N/A -- no async path | | |
| external | N/A in-circuit; the app's EAS lookup and network trust are outside (see gap below) | | |

`scripts/coinbase-app-attest-poc/mutation-check.sh` deletes each clientData
and assertion assert in a copy of the circuit and shows the matching refusal
case is then ACCEPTED, so the case is caused by that assert.

## Measurements

`scripts/coinbase-app-attest-poc/measure.sh`, 2026-10-23, Apple M5 Pro
(18 cores, 64 GB), nargo 1.0.0-beta.19, bb 4.2.0-aztecnr-rc.2, `bb prove -t evm`
with `/usr/bin/time -l`, 3 runs each, synthetic App Attest fixture (action mode).

| | coinbase_attestation | coinbase_app_attest_poc |
|---|---|---|
| `bb gates` circuit_size | 397,809 | 860,718 |
| ACIR opcodes | 14,646 | 104,144 |
| dyadic size (from the .srs) | 2^19 | 2^20 |
| `bb prove` wall time | 1.76 / 1.76 / 1.80 s | 3.46 / 3.26 / 3.22 s |
| peak RSS | 0.94 GiB | 2.09-2.10 GiB |
| proof | 9,920 bytes | 10,304 bytes |
| public inputs | 4,096 bytes (128) | 7,232 bytes (226) |
| vk | 1,888 bytes | 1,888 bytes |
| Solidity verifier | 2,461 lines | 2,461 lines |
| .srs | 33,554,644 bytes | 67,109,076 bytes |

Per part (`bb gates` on the probes in `../_probes/coinbase-app-attest-poc/`,
each compiled alone, so shared lookup tables are counted in each):

| Part | circuit_size |
|---|---|
| Coinbase base (request signature with signed_digest, tx, signer Merkle, wallet nullifier) | 416,151 |
| P-384 credential-certificate signature (one ECDSA verify) | 206,651 |
| SHA-256 of TBS (<= 1000 B) and CA key, DER walk, attestation-nonce check | 196,481 |
| P-256 assertion (three SHA-256s + black-box verify) | 112,782 |

The parts sum to 932,065, 71,347 more than the whole: the tables they share.
The full circuit is 462,909 gates over coinbase_attestation, and 187,858 under
the 2^20 boundary.

## Dependencies

- `../app-attest-libs/` (package `app_attest`) -- the App Attest library (DER walk, certificate, attestation
  authData, assertion), kept separate so the shipped circuit can use it.
- P-384: `zkpassport/noir-ecdsa` v0.3.0 + `zkpassport/noir-bignum` v0.9.2-1 +
  `zkpassport/noir_bigcurve` v0.13.2-1 (git tags), the newest that compile on
  beta.19; the next tags need beta.24 / a nightly. Compiling them prints a
  warning that a Brillig call in `noir_bigcurve` `ops/msm.nr:217` is not
  sufficiently constrained; it is upstream code zkPassport ships, and it was
  not audited here.
- P-256: `std::ecdsa_secp256r1`, a Barretenberg black box.
- SHA-256: `noir-lang/sha256` v0.3.0.

## Fixtures

`scripts/coinbase-app-attest-poc/make-fixtures.sh`: the Coinbase half from
`coinbase-attestation/Prover.toml` (built by
`proofport-ai/scripts/gen-prover-toml.ts` from Base), the wallet key from
`proofport-ai/.env.test`, the App Attest half generated with our own P-384
"CA" and P-256 "device" keys. The credential certificate copies the real one's
structure (same field order, attribute types, extensions and OIDs; the 8.5
items with our App ID; the 8.7 extension verbatim). Deviations from a device:
our signer key, serial and dates; assertion flags `0x00`; no CBOR extensions
in either authData; the attestation clientDataHash is random.

## What the real-device step must confirm

- The App ID item: [1204] (`BF 89 34`) in extension 1.2.840.113635.100.8.5.
  Seen in one real certificate and used by zkPassport; Apple does not
  document it. The App ID prefix is the team id `R4G32CVY29` today; if the
  app moves to the corporate developer account the prefix may change, and
  with it the circuit constant.
- Assertion authenticatorData length and flags, and whether the CBOR
  extensions (`apple_validation_category_01`, `apple_bundle_version_01`)
  Apple's page now lists appear in assertions. The circuit accepts up to 128
  bytes and does not read them; to require an App Store build, they would
  have to be parsed.
- Attestation authData length with extensions (the circuit allows 256).
- The app must keep the attestation object (credCert, authData, its
  clientDataHash) from `attestKey`, convert both DER signatures to r || s,
  and put s in low form.
- Not covered by any of this: the device owner who installs their own root
  CA and rewrites the EAS answer. Certificate pinning in the app narrows it.
