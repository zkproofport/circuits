# zktls_notary_libs

Proves a claim about a JSON response body that a TLSNotary session has
committed to, without revealing the body. The claim is up to three assertions,
each a JSON path, a value kind, an operator and an operand, plus a nullifier
member and a scope. One circuit serves every claim, and `claim_hash` binds the
proof to the one it used.

This package holds all of the logic, generic over the prefix size `N` and the
assertion capacity `A` (1 to `A_MAX` = 3: how many assertions a circuit checks).
The circuits fix `N` and use `A = A_MAX`:

| Package | `N` (largest committed prefix) | `A` | Circuit size |
|---|---|---|---|
| `zktls-notary-1k` | 1024 bytes | 3 | 370,878 (2^19) |
| `zktls-notary-2k` | 2048 bytes | 3 | 548,012 (2^20) |
| `zktls-notary-4k` | 4096 bytes | 3 | 902,278 (2^20) |

A claim is proved with the smallest tier that holds its members, whatever its
number of assertions. The prover and the relying party both derive that circuit
from the tier (`CIRCUITS` / `circuit_for` in
`docs/research/tlsn-mobile-bench/bench/src/claim.rs`), so a proof made with any
other circuit is refused.

### Capacities

Each assertion slot costs 32,449 gates (one path binding of 8 segments, the
operator and the unused-slot checks), whatever the tier. Every combination was
measured with `scripts/measure-gates.sh` (nargo 1.0.0, bb 6.0.0):

| Tier | A = 1 | A = 2 | A = 3 |
|---|---|---|---|
| 1k | 305,980 (2^19) | 338,429 (2^19) | 370,878 (2^19) |
| 2k | 483,114 (2^19) | 515,563 (2^19) | 548,012 (2^20) |
| 4k | 837,380 (2^20) | 869,829 (2^20) | 902,278 (2^20) |

The proving size is the power of two, not the gate count, so only 2k at A = 2
lands in a smaller size than A = 3. It was built and measured on a Galaxy A23:
26.8-26.9 s and 847 MB peak against 29.4-30.1 s and 943 MB for `zktls-notary-2k`,
about 10% on both. That is below the 30% a second circuit per tier has to save, so
every tier has one circuit, at A = 3.

The claim encoding keeps all `A_MAX` slots at every capacity (slots past `A`
are zero), so one claim has one `claim_hash` whichever circuit proves it. An
encoding sized to the capacity was measured too, and it moves no circuit across
a power of two: 1k at A = 1 270,306 (still 2^19, 8,162 over 2^18), 1k at A = 2
318,619, 2k at A = 1 447,440 and at A = 2 495,753 (2^19, as with the full
encoding), 4k at A = 1 801,705 and at A = 2 850,019 (2^20).

## The commitment it opens

The prover commits to a **prefix of the HTTP response body**, starting at the
first byte after the blank line that ends the headers, as one received-direction
range with a SHA-256 hash commitment. The rest of the body is neither revealed
nor committed. The circuit recomputes:

```
commitment = SHA-256(body[0..P] || blinder)      blinder = 16 bytes
```

`P` is chosen by the prover and checked by the verifier:

- the prover picks the smallest tier `N` that holds every member the claim
  reads, including the byte that closes each value;
- `P = min(body_len, N)`: the whole body when it fits, otherwise exactly `N`.
  Rounding up to the tier means `P` tells the verifier only the tier, not where
  the members sit;
- the verifier accepts only a commitment that starts at the body start and whose
  length is the whole body or exactly a tier size of a longer body. It passes
  `whole = (P == body_len)` to the circuit as a public input.

The JSON state at a byte depends only on the bytes before it, so a prefix is
enough to place a member: bytes after the prefix cannot change what the prefix
says.

The hash order is the one TLSNotary uses, at `tlsn` tag `v0.1.0-alpha.15` (`47aee45b`):

- `crates/core/src/transcript/hash.rs:12-16`: `hash_plaintext` documents
  "plaintext is hashed as `H(msg | blinder)`" and calls
  `hasher.hash_prefixed(msg, blinder.as_bytes())`.
- `crates/core/src/hash.rs:302-306`: the SHA-256 `hash_prefixed(prefix, data)`
  feeds `prefix` and then `data`, so the bytes hashed are `msg` then `blinder`.
- `crates/core/src/hash.rs:243`: `pub struct Blinder([u8; 16])`.
- `crates/tlsn/src/transcript_internal/commit/hash.rs:163-167`: the protocol-side
  hasher updates with each committed range in order, then with the blinder.

## What it proves

1. `prefix[..prefix_len]` opens `commitment`. `prefix_len <= N`, and when
   `whole` is false, `prefix_len == N`.
2. The prefix is a JSON text: the root is an object or an array, and JSON
   whitespace (space, tab, CR, LF) may come before and after it, nothing else.
   A bare scalar root, a byte-order mark, a second root and trailing garbage are
   refused. Brackets close the kind they opened. When `whole` is true the root
   must have opened and closed, outside any string.
3. The scan keeps, before every byte, whether it is inside a string and the
   innermost container (`cont`). The prover supplies `cont`; the scan checks every
   entry against the running value, so the prover has no freedom in it. There is
   no nesting limit.
4. Each of up to `A` assertions (ANDed; 1 <= `n_asserts` <= `A`, so a circuit refuses a
   claim with more assertions than it has slots rather than leaving some unchecked)
   reads the value at its **JSON path**: up to
   8 segments, each an object key or `[]` ("some element of this array"), e.g.
   `kakao_account.age_range`, `email`, `[].login`, `data.items[].owner.login`,
   `[][].c`. The zkPass form `a|b|c` is accepted as an input alias by the claim
   builder. For every segment the prover names its token (a key's opening quote, or
   an element's first byte) and the start of its value; the circuit checks:
   - the token's innermost container is the previous segment's value (the root
     for the first segment);
   - a key segment is applied to an object, a `[]` segment to an array;
   - a key token is the exact name, outside any string, followed by JSON
     whitespace around one colon (at most 8 bytes);
   - an element token starts a value directly inside the array (an object, an
     array, a string, or a literal preceded by `[` or `,`);
   - the value a key or an element is followed into is an object when the next
     segment is a key, and an array when it is `[]`;
   - slots past the path length are empty.
   A same-named key at another depth, in a sibling object, or inside a string at
   any depth, and an element of another array, do not match. `[]` means some
   element **inside the committed prefix**.
5. The value is the whole value: a string closed by `"` (no quote or backslash
   inside, 1 to 32 bytes), or a bare literal (number, `true`, `false`, `null`)
   ending at `,`, `}`, `]` or whitespace. It and the byte that closes it lie inside
   the prefix. Each assertion's operator holds against its operand.
6. `nullifier = keccak256(len | value[32] | scope[32])` over a top-level member
   named by the claim (`sub` as a string, `id` as a number). A claim with
   `nf_kind = NF_NONE` (2) reads no account member, and the nullifier is then
   `keccak256(0 | 0[32] | scope[32])`.
7. `claim_hash = SHA-256(...)` over the whole claim, 994 bytes, version 4:
   `version | tier[2] | n_asserts | 3 x (n_segs | 8 x (seg_kind | seg_len |
   key[32]) | value_kind | op | operand_len | operand[32]) | nf_key_len |
   nf_key[32] | nf_kind | scope[32]`, unused assertions and segments all zero.
   The encoding has 3 assertion slots at every capacity `A`, so the hash does not
   depend on the circuit; `n_asserts` and the tier are in it.
   Every claim field is a private input: a relying party recomputes `claim_hash`
   from its proof request and compares it with the public input. A claim hash for
   another tier, path, operand or scope does not verify.
8. `request_hash` (32 bytes) is a public input carried unchanged, so a proof is
   bound to the request it answers; the relying party compares it with the hash of
   its own request. The proof date is public too; the relying party checks it.

Scope of a path: it ends at a string without escapes or at a bare literal; `[]`
is existential (an element's position is not part of a claim, since servers do not
promise an order, and a fixed index would cost a per-byte count for each index
segment); the root is an object or an array, as every API response is.

The scan is not a full JSON validator. It enforces what path binding needs: string
and escape state, root uniqueness and surrounding whitespace, matching brackets,
and, along every bound path, key tokens, colons, element delimiters and the value
grammar. Token-level errors elsewhere in the body (a bad number, a missing comma
between unrelated members) are not checked: the body is a server response
authenticated by TLS, and a server's JSON encoder escapes every user-controlled
string, so a prover cannot place such bytes in it. See the JSONTestSuite results
in `docs/research/tlsn-mobile-bench/README.md`.

## Operators

| Code | Name | Meaning |
|---|---|---|
| 0 | `EQ` | value bytes equal the operand |
| 1 | `NEQ` | value bytes differ from the operand |
| 2–5 | `GT` `LT` `GTE` `LTE` | value and operand as unsigned decimal integers |
| 6 | `AGE_GTE` | value is `YYYY-MM-DD` (completed years on the proof date) or `YYYY` (proof year minus birth year); year `0000` is rejected |
| 7 | `RANGE_MIN_GTE` | value is `<min>~<max>` or `<min>~`; `min` is at least the operand |
| 8 | `ENDS_WITH` | the value's last bytes equal the operand (not empty). For an email domain the operand must include the `@` (`@example.com`), or `evilexample.com` would match |
| 9 | `DATE_BEFORE` | value and operand start with `YYYY-MM-DD` (anything after must start with `T`, as in an ISO-8601 timestamp); the value's date is strictly earlier |
| 10 | `CONTAINS` | the operand (not empty) occurs in the value |
| 11 | `IN` | the operand is a comma-separated list (`KR,JP,US`); the value equals one item. A value containing a comma is refused |

## Inputs (tier `main`, in ABI order)

| Private | |
|---|---|
| `prefix[N]`, `prefix_len` | committed prefix, zero-padded |
| `blinder[16]` | commitment blinder |
| `root` | the root's opening bracket |
| `cont[N]` | innermost container before each byte (`N` outside all) |
| `n_asserts`, `asserts[A]` | each `{ path { n, kinds[8], keys[8][32], lens[8] }, value_kind, op, operand[32], operand_len }` |
| `hints[A]` | each `{ tok[8], open[8], value_offset, value_len }` |
| `nf_key[32]`, `nf_key_len`, `nf_kind`, `nf_hint` | nullifier member (top level); kind 2 = none |
| `scope[32]` | nullifier scope |

| Public | |
|---|---|
| `commitment[32]` | the TLSNotary hash |
| `whole` | true when the commitment covers the entire body (set by the verifier) |
| `claim_hash[32]` | see above |
| `request_hash[32]` | the proof request this proof answers |
| `proof_year`, `proof_month`, `proof_day` | date used by `AGE_GTE` and checked by the relying party |
| `nullifier[32]` | the nullifier |

## Size and speed

Each package built with `scripts/build.sh zktls-notary-<name>` (nargo 1.0.0, bb 6.0.0,
Keccak oracle, ZK, keccak256 v0.1.3 and sha256 v0.3.0 from `deps/`) on an M5 Pro Mac.
Prove times are `bb prove` wall time through
`docs/research/tlsn-mobile-bench/bench/src/bin/claim_prove.rs` (median of 5 interleaved
rounds, 2026-11-17, with another build holding the load average at 10-12):

| Package | ACIR opcodes | Circuit size | Witness | Prove (Mac) | Proof |
|---|---|---|---|---|---|
| `zktls-notary-1k` | 203,660 | 370,878 (2^19) | 0.29 s | 0.86 s | 9,920 B |
| `zktls-notary-2k` | 303,740 | 548,012 (2^20) | 0.44 s | 1.25 s | 10,304 B |
| `zktls-notary-4k` | 503,900 | 902,278 (2^20) | 0.71 s | 1.91 s | 10,304 B |

Every package has 132 public inputs. Where the gates go: one assertion slot 32,449
(measured as the difference between capacities), the SHA-256 claim hash over the 994-byte
encoding about 64k, and the per-byte scan (string state, container hint, bracket kinds,
root whitespace) about 169k per KB (both measured on 1k variants before nargo 1.0.0).

## Tests

`nargo test` here runs 529 tests against the 1 KB tier (or a smaller size where a test
names it): the 176 claim tests at every capacity, plus 8 capacity tests. Bodies and
commitments are generated outside the circuit (standard SHA-256
over `prefix || blinder`) in `src/vectors.nr` (Kakao shapes), `src/vectors_ws.nr`
(Google and GitHub shapes) and `src/vectors_deep.nr` (general paths, root kinds, guard
cases). `src/testkit.nr` holds the claim builders and a hint derivation the tier
packages' tests reuse. Each tier package runs 3 tests through its own `main`.

**Every claim test runs at every capacity.** A test is written once, generic over
`let A: u32`, under `#[capacities(min, "expected failure")]` (a comptime attribute in
`src/testkit.nr`), which generates `<name>_a1`, `<name>_a2` and `<name>_a3` for each
capacity from `min` up. The test's claim always has the encoding's 3 slots;
`fit_asserts` hands a capacity-`A` circuit the first `A` and refuses ("test claim does
not fit this capacity") a claim with anything in a slot past `A`, so a claim never
silently loses an assertion. Seven tests use slot 2 (two assertions, or junk in an
unused second slot) and start at `min = 2`: run at A = 1 they fail with that refusal,
which is how they were found. 169 x 3 + 7 x 2 = 521 runs, plus:

- `src/tests_capacity.nr`: a two-assertion claim given to a capacity-1 circuit is
  refused (`bad assertion count`), and claiming one assertion instead does not match
  the two-assertion claim's hash (`claim hash mismatch`); the same claim and hints
  prove at capacity 2 (the positive control); three assertions refused at capacity 2;
  four assertions refused at capacity 3, the one every tier uses; `n_asserts = 0`
  refused at capacities 1 and 2 (and at every capacity through
  `test_guard_no_assertion`); the claim hash is the same computed at capacity 1, 2 and 3.

- `src/tests.nr`, `src/tests_ws.nr`: the Kakao, Google and GitHub claims, the
  operators, prefix commitments, and every earlier attack (escaped fake keys, forged
  `properties.age_range` or top-level `age_range`, nested `birthdate`, offsets shifted
  by one, a key in an array element that is an array, wide separators, a key without a
  colon), now through general paths.
- `src/tests_deep.nr`: `data.items[].owner.login` (compact and pretty-printed), `a[].b[].c`,
  an 8-segment path and a refused 9th segment; the same key at the wrong depth, a key in a
  sibling object, an element of another array, `[]` applied to an object and a key applied
  to an array, a path truncated or extended by one segment, escaped fake keys inside
  strings at depths 1, 2 and 4; string and literal elements; `CONTAINS` and `IN`; two
  assertions ANDed, one false; unused assertion slots; whitespace around a root object
  and a root array, a root array of arrays, a refused byte-order mark, garbage before or
  after the root, a second root, a root scalar, an unclosed root array as a whole body,
  a mismatched closing bracket, and 33 levels of nesting elsewhere in the body.
- `src/tests_guards.nr`: one test per guard that no claim test reaches as the deciding
  check, found by the mutation check: a tampered container hint, a whitespace-only body,
  a root past the prefix, not a bracket, or nested; a key token that is not a quote, a
  key name that is a prefix of the real one, a key with a quote, an empty key, key
  padding; a key-shaped string in a root array; an element in an object, with a key
  length, with its value moved, inside a string, inside a literal; segments and hints
  past the path length; an empty value, the value of another member, a value with an
  escape, a literal read as a string, a value at byte 0; empty `CONTAINS` and `IN`
  operands and a value with a comma under `IN`; the operator helpers' input checks (two
  tildes, a letter or four digits in an age range; a short date, year `0000`, a bad month
  or day; an eight-digit, slashed, future or not-yet-reached birth date; an empty, overlong
  or non-numeric number; an operand longer than 32 bytes or with padding); unused-slot
  and nullifier padding; no assertion, a one-byte prefix, a bad proof month or day.
