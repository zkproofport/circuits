# coinbase_country_attestation v2 (`coinbase_country_attestation_v2`)

Coinbase Verified Country whose revocation is bound by a signed statement,
built 2026-10-30 as `../coinbase-attestation-v2` (Coinbase KYC v2) is: the
prover looks up the wallet's Coinbase Verified Country attestation right
before proving and, only if it is unrevoked, a key the circuit trusts signs a
statement saying so -- including which country it saw. Same signers, same
optional EIP-712 action, same wallet + circuit-tag nullifier; the country
list rule is v1's, unchanged.

Decisions behind it: `.claude/agents/circuits-dev.md`, "Decisions,
2026-10-23" (revocation binding, EIP-712 action and the wallet nullifier for
"the Coinbase circuits") and the 2026-10-30 call that Country ships with KYC
v2 in the same release.

| Package | Signer | Verifier |
|---|---|---|
| `coinbase-country-attestation-v2` (this one) | iPhone App Attest (`signer_kind = 1`) or the AI server's Cloud KMS key (`signer_kind = 2`) | `CoinbaseCountryAttestationV2` |
| `../coinbase-country-attestation-v2-android` | Android key attestation, Remote Key Provisioning chain | `CoinbaseCountryAttestationV2Android` |
| `../coinbase-country-attestation-v2-android-factory` | Android key attestation, factory chain + Play Integrity | `CoinbaseCountryAttestationV2AndroidFactory` |

The package is `coinbase_country_attestation_v2` while v1 still lives in
`../coinbase-country-attestation`. The circuit ID every package serves is the
canonical `coinbase_country_attestation`: the nullifier tag and the
statement's kind are `keccak256("coinbase_country_attestation")`.

## What the circuit proves

1. The wallet signed the request -- personal_sign over `signal_hash`, or an
   EIP-712 action (`coinbase_libs::signed_message::signed_digest`); the two
   modes are mutually exclusive.
2. v1's checks, unchanged: an `attestCountry(uint256)` EIP-1559 transaction
   to Coinbase's attester for this wallet, signed by a key whose address is in
   the public signer Merkle root; its country (calldata bytes 14-15) is in
   the public list (inclusion) or not in it (exclusion), with 1 to 10 entries
   and entries at or past `country_list_length` ignored.
3. A 227-byte statement (below) naming this wallet, the public `attested_at`,
   Coinbase's Country schema and attester, revoked = 0, this request's
   digest, this scope, and the transaction's country, signed by the app or
   the server exactly as in `../coinbase-attestation-v2` (shared
   `../statement-signer`: CA 1 pinned, production App Attest only, the
   server's P-256 Cloud KMS key).
4. Nullifier = keccak(keccak(wallet ++ CIRCUIT_TAG) ++ scope). v1 Country
   nullifiers (derived from `signal_hash`) do not carry over.

### Why the statement carries the country

A wallet whose country changed holds two attestCountry transactions: the old
one (its attestation since revoked) and the new one. A statement saying only
"this wallet's Country attestation is unrevoked" is true of the NEW
attestation and would let the OLD transaction, with the old country, pass.
The circuit cannot tie the attestation uid to the transaction (the uid is in
the receipt, not the transaction), so the signer writes the `verifiedCountry`
it read from the unrevoked attestation and the circuit requires the
transaction's country to equal it. Fixture `client_other_country` is that
attack; it is refused with `clientData names another country`.

### Why a new library and not ../coinbase-v2-libs

`../coinbase-country-v2-libs` repeats `../coinbase-v2-libs` with the
attestCountry selector, the country list and the 227-byte statement. Editing
`coinbase-v2-libs` instead would change the source text in the file map of
every Coinbase KYC v2 artifact: the same constraints and verifiers, but new
circuit files and digests for what the app, SDK and AI server already pin.

## Public inputs

In order. Each byte of a `[u8; N]` is one field element.

| # | Name | Type | Field offsets |
|---|---|---|---|
| 1 | `signal_hash` | `[u8; 32]` | 0-31 |
| 2 | `domain_separator` | `[u8; 32]` | 32-63 |
| 3 | `action_hash` | `[u8; 32]` | 64-95 |
| 4 | `signer_list_merkle_root` | `[u8; 32]` | 96-127 |
| 5 | `country_list` | `[[u8; 2]; 10]` | 128-147 |
| 6 | `country_list_length` | `u32` | 148 |
| 7 | `is_included` | `bool` | 149 |
| 8 | `scope` | `[u8; 32]` | 150-181 |
| 9 | `nullifier` | `[u8; 32]` | 182-213 |
| 10 | `attested_at` | `u64` (unix seconds) | 214 |

215 field elements (6,880 bytes as `bb` writes `public_inputs`). Coinbase KYC
v2's order with v1 Country's fields where v1 had them (after the signer
root, before scope and nullifier). v1 Country has 150; a v1 proof is refused
by its count.

What a verifier must do beyond `verify()`: check `attested_at` against its
own clock (the SDK/core window is 15 minutes behind, 5 ahead), the signer
root, the scope, the nullifier, and that the public country list and mode
are the ones it asked for.

## clientData format (what every signer signs)

Fixed 227 bytes, binary.

| Offset | Length | Field | Circuit check |
|---|---|---|---|
| 0 | 16 | ASCII `ZKProofport/AA/1` | equal |
| 16 | 32 | `keccak256("coinbase_country_attestation")` | equal to `CIRCUIT_TAG` |
| 48 | 20 | wallet address | equal to the proven wallet |
| 68 | 8 | timestamp, unix seconds, big-endian | equal to public `attested_at` |
| 76 | 32 | EAS schema uid | Coinbase Verified Country `0x1801901fabd0e6189356b4fb52bb0ab855276d84f7ec140839fbd1f6801ca065` |
| 108 | 20 | EAS attester | Coinbase `0x357458739F90461b99789350868CD7CF330Dd7EE` |
| 128 | 32 | attestation uid the signer found | carried only |
| 160 | 1 | revoked: `0x00` = found unrevoked | must be `0x00` |
| 161 | 32 | request digest: the exact 32 bytes the wallet signed | equal to the circuit's `signed_digest` |
| 193 | 32 | scope | equal to public `scope` |
| 225 | 2 | country: the attestation's `verifiedCountry`, two ASCII bytes | equal to the transaction's country |

Bytes 0-224 are Coinbase KYC v2's layout with this circuit's tag and schema;
a KYC statement cannot stand in for one of these (`kyc_statement_replay`,
`client_kyc_tag`, `client_kyc_schema`).

## What a signer does

As `../coinbase-attestation-v2/README.md` "What the server signs", with:

1. Look up the wallet's Coinbase Verified Country attestation (Base EAS,
   schema and attester above), fresh, and confirm it is unrevoked; read its
   `verifiedCountry` (ABI `string`). Refuse unless it is exactly two ASCII
   capitals and equal to the attestCountry transaction's country.
2. Build the 227 bytes above, then sign SHA256 of them (server: Cloud KMS
   `EC_SIGN_P256_SHA256`, low s; app: App Attest assertion; Android: the
   attested Keystore key).

## Acceptance

`scripts/build.sh coinbase-country-attestation-v2` runs `scripts/post-build.sh`:
the App Attest library tests, `../scripts/coinbase-country-attestation-v2/make-fixtures.sh`
(the synthetic-anchors copy, every fixture, from a REAL attestCountry
transaction on Base for the E2E wallet), the shared acceptance run
(`../scripts/action-circuit-acceptance.sh
coinbase-country-attestation-v2-synthetic-anchors`: every Coinbase KYC v2
case plus the country cases below) and
`../scripts/coinbase-attestation-v2/real-anchors-check.sh
coinbase-country-attestation-v2` on this circuit's real anchors.
`../scripts/coinbase-country-attestation-v2/mutation-check.sh` deletes or
bypasses each named check and requires its refusal case to be ACCEPTED.

## Edge-case matrix

Drawn up before the fixtures. A = acceptance run, R = real-anchors check,
M = mutation check. Every row of `../coinbase-attestation-v2/README.md`'s
matrix applies unchanged (same signer library, same fixtures, A); the rows
below are what Country adds.

| Row | Case | Expected | Where |
|---|---|---|---|
| list, accept | inclusion with the country second of two; single entry; ten entries (boundary) | accepted | A `action`, `no_action`, `list_single`, `list_full_ten` |
| list, accept | exclusion, country absent (app and server kind) | accepted; proofs verify | A `exclusion_accepted`, `server_exclusion` |
| list, refuse | exclusion with the country listed | refused | A `exclusion_refused`; M |
| list, refuse | inclusion without the country | refused | A `not_in_inclusion_list`; M |
| list, boundary | the country only past `country_list_length` | refused (ignored entry) | A `match_past_length`; M |
| list, boundary | length 0 / 11 | refused | A `list_length_zero`, `list_length_eleven`; M |
| statement | another country; the same country lowercased; server-signed other country | refused | A `client_other_country`, `client_lowercase_country`, `server_other_country`; M |
| statement | KYC tag; KYC schema; a whole KYC statement re-signed | refused | A `client_kyc_tag`, `client_kyc_schema`, `kyc_statement_replay`; M (tag, schema) |
| transaction | the same wallet's attestAccount (KYC) transaction, statement and list made to match it | refused at the selector | A `kyc_tx`; M |
| nullifier | KYC's tag; arbitrary | refused | A `kyc_nullifier`, `wrong_nullifier` |
| signer | real Apple chain stops at the App ID; synthetic CA refused; test-key server statement | as KYC v2 | R |
| hostile | non-ASCII / wrong-length country | cannot be expressed: two fixed bytes compared to two transaction bytes | N/A |
| empty | unused list slots | ignored by length, not by value | A `match_past_length` |
| time | old timestamp both signed and public | ACCEPTED -- freshness is the verifier's | N/A (verifier) |
| authz / race / external | as KYC v2 (no caller beyond the wallet signature; the EAS lookup is outside the circuit) | | |

## Measurements

Pinned toolchain (nargo 1.0.0-beta.19, bb 4.2.0-aztecnr-rc.2), Apple M5 Pro.
Recorded with the date in `.claude/agents/circuits-dev.md`, "Coinbase
Country v2".

## Dependencies

`../coinbase-country-v2-libs`, `../coinbase-libs`, `../statement-signer`
(and through it `../app-attest-libs`, `../android-key-attestation`,
`../play-integrity`); see `../coinbase-attestation-v2/README.md`.
