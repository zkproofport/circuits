# oprf-nullifier-libs

The nullifier every wallet credential circuit publishes: an OPRF output that
nobody can compute from a wallet address without the OPRF key. Used by
`coinbase-attestation`, `coinbase-country-attestation`, the six
`coinbase-*-attestation-v2*` packages, `giwa-attestation`, `dojang-playground`
and `human-passport-score`.

## Why

A nullifier hashed from the wallet address and values the verifier already
holds can be recomputed for every candidate address, and the addresses that
hold a KYC or score attestation are public on EAS. Trying them all finds the
prover. With an OPRF the nullifier needs a key `k` held by the OPRF nodes;
the nodes only ever see the query multiplied by a random blinding factor, and
the circuit checks their Chaum-Pedersen proof.

## Construction

TACEO's construction for ZKProofport (statement of work, 2026-11-17):

```
query     = Poseidon2(DS_query, address, domain, scope)
A         = beta * encode_to_curve(query)          blinded query (client -> nodes)
B         = k * A                                  the nodes' answer, with a
                                                   Chaum-Pedersen proof (DS_dlog)
P         = B / beta                               unblinded by the client
nullifier = Poseidon2(DS_out, query, P.x, P.y)
key hash  = Poseidon2(DS_key, D.x, D.y),  D = k * G   the OPRF public key
```

| Constant | ASCII string (read as a big-endian integer) |
|---|---|
| `DS_QUERY` | `TACEO_OPRF_zkProofport_query` |
| `DS_OUT` | `TACEO_OPRF_zkProofport_out` |
| `DS_KEY` | `TACEO_OPRF_bjj_key` |
| `DS_DLOG` | `DLOG Equality Proof` |

- `Poseidon2(a, b, ...)` is the BN254 Poseidon2 permutation of width = number
  of inputs, output `state[1]`.
- `address` is the wallet's 20 bytes read as a big-endian integer.
- `domain` and `scope` are field elements: a string maps to
  `keccak256(string) mod p` (p = the BN254 scalar field modulus).
- Hash-to-curve is `encode_to_curve` with the hash-to-field separator
  `OPRF_HashToField_BabyJubJub` (TaceoLabs/oprf-nr v2.0.0, `deps/oprf-nr`).

`verify_oprf_nullifier(address, domain, scope, oprf_key_hash, nullifier, answer)`:

1. `D` is on BabyJubJub and in the prime-order subgroup, and
   `key_hash(D) == oprf_key_hash` ("OPRF key hash mismatch").
2. oprf-nr `verified_oprf`: `beta` is a non-zero scalar below the subgroup
   order; `A` is recomputed from `beta` and the query; `P` is on the curve and
   in the subgroup; `B` is recomputed as `beta * P`; the Chaum-Pedersen proof
   (`e`, `s`; `s` below the subgroup order) shows `log_G(D) = log_A(B)`, with
   none of `D`, `A`, `B` the identity; the output is
   `Poseidon2(DS_out, query, P.x, P.y)`.
3. That output equals `nullifier` ("Nullifier mismatch").

The address is the one the circuit's credential checks proved: each circuit
passes its own `user_address`, so an OPRF answer for another wallet is
refused ("Challenge verification failed").

## In a circuit

Public inputs, in this order, where the circuit had `scope` and `nullifier`
before:

| Name | Type | Meaning |
|---|---|---|
| `oprf_key_hash` | `Field` | hash of the OPRF key the answer came from |
| `domain` | `Field` | `keccak256(domain string) mod p` |
| `scope` | `Field` | `keccak256(scope string) mod p` |
| `nullifier` | `Field` | the OPRF nullifier |

Private inputs, after the circuit's own: `oprf_public_key_x`,
`oprf_public_key_y`, `oprf_beta`, `oprf_dlog_e`, `oprf_dlog_s`,
`oprf_response_x`, `oprf_response_y` (the unblinded `P`).

Each circuit's public-input layout, offset by offset, is in
`.claude/agents/circuits-dev.md` in the parent repository ("OPRF nullifier in
every wallet credential circuit").

## What a verifier checks

- **The key hash.** Pin `oprf_key_hash` to the key registered for the proof
  type it accepts. The circuit accepts an answer from any key that is
  consistent with itself, so a proof under another key hash proves nothing:
  whoever holds that key can compute every address's nullifier under it. One
  key per proof type: the same wallet, domain and scope then give unrelated
  nullifiers in two circuits.
- **Domain and scope.** Compare them with `keccak256(string) mod p` of the
  strings it asked for. Reduce before comparing: a raw keccak256 is at or above
  p for about 81% of strings. nargo refuses an input at or above p ("exceeds
  field modulus"), so a prover cannot publish an unreduced value;
  `scripts/verify-onchain.sh` with `INPUT_PLUS_P_INDEX` reports what the
  Solidity verifier does with one.
- **Order.** `domain` and `scope` swapped is another query and another
  nullifier.

## Tests

`scripts/test.sh oprf-nullifier-libs` -- `src/tests.nr`, one test or more per
case below. Expected values are in `src/test_vectors.nr`, written by
`scripts/oprf-nullifier/make-test-vectors.sh` from TACEO's crates
(`taceo-oprf-core` 0.6.3, `taceo-poseidon2` 0.3.1) with published test values
(TACEO's oprf-testnet test key and beta, anvil account 0); `--check` compares
the committed file with a fresh run.

| Case | Refused with |
|---|---|
| nullifier + 1, - 1, 0 | Nullifier mismatch |
| key hash + 1; another key's hash | OPRF key hash mismatch |
| another key's point under this key's hash | OPRF key hash mismatch |
| another key's point and hash, this key's answer | Challenge verification failed |
| another key's consistent answer, this key's nullifier | Nullifier mismatch |
| public key off the curve / outside the subgroup / identity / (0, 0) | the curve / subgroup / identity check |
| beta + 1 | Challenge verification failed |
| beta = 0 / = r / + r | Beta cannot be zero / scalar range |
| B from another key with this key's proof | Challenge verification failed |
| e + 1, s + 1, e and s swapped, another request's proof | Challenge verification failed |
| s + r (same scalar, other encoding) | scalar range |
| e = s = 0 | Computed points cannot be identity |
| P off the curve / outside the subgroup / identity / (0, 0) / -P | curve / subgroup / identity / Challenge verification failed |
| another address; another wallet's answer | Challenge verification failed |
| domain and scope swapped; the swapped query's answer | Challenge verification failed |
| another domain; another scope | Challenge verification failed |

Accepted on purpose, with the value pinned: the honest evaluation; another
key's consistent answer (another nullifier); another wallet (another
nullifier); domain and scope swapped consistently (another nullifier).

`scripts/oprf-nullifier/mutation-check.sh` removes or weakens each guard in
`src/lib.nr` in a copy and requires the tests to fail: the key-hash assert,
the nullifier assert, the public key's curve and subgroup checks, the
response's curve check, the query's argument order, the address byte order,
the address in the query, the query and output separators, the query's output
index, and the key hash's coordinate order.

Every circuit's acceptance run adds the same cases against its own fixture
(`scripts/oprf-nullifier/acceptance-cases.sh`): nullifier + 1, key hash + 1,
domain and scope swapped, another wallet's answer beside this wallet's
credential, another circuit's answer under this key hash, another circuit's
consistent answer (accepted, with another key hash), and `scope + p` (refused
by nargo: "exceeds field modulus").

## Fixtures

`scripts/oprf-nullifier/oprf.js` gives a fixture generator the OPRF inputs for
a wallet, domain and scope: the nodes' answer is computed by
`scripts/oprf-nullifier` (Rust, TACEO's crates) with a test key per circuit id
derived from a public string. Nothing talks to an OPRF network, and no
deployment key is in this repository.
