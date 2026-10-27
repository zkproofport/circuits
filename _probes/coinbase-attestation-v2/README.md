# coinbase_attestation_v2 gate probes

Since 2026-10-28 the circuit itself pins CA 1 (the `pinned-intermediate`
design below, 983,451 gates); `root-link`, `sha384-intermediate` and the
`PINNED = false` control measure the root-pinned design it replaced.

Measurement provenance for `../../coinbase-attestation-v2`, not circuits: no
fixtures, no vk, nothing deployed. `scripts/coinbase-attestation-v2/measure.sh`
compiles each and prints `bb gates` beside the whole circuit.

| Probe | What it contains |
|---|---|
| `coinbase-base` | GENERATED from v2's main.nr: everything except the statement (request signature, attestation transaction and signer, Merkle proof, wallet nullifier) |
| `unconditional-app-checks` | GENERATED from v2's source with `if signer_kind == KIND_APP {` replaced by `{`: what the circuit would cost if the App Attest checks were not inside the branch. It refuses every server-kind witness, so it only measures |
| `root-link` | What v2 added over the prototype: SHA-384 of the intermediate TBS (<= 600 bytes), ECDSA P-384 by Apple's root (a constant), and the intermediate DER walk |
| `sha384-intermediate` | The SHA-384 of the intermediate TBS alone (zkpassport/sha512 v0.1.1, five 128-byte blocks) |
| `pinned-intermediate` | v2 with Apple's intermediate (CA 1) key PINNED: no root -> intermediate link. `WITH_*` / `APP_BRANCH` / `PINNED` globals switch one part off at a time; `scripts/coinbase-attestation-v2/measure-pinned-intermediate.sh` compiles each variant (into the gitignored `pinned-intermediate-variants/`) and prints `bb gates` and the dyadic size from `bb write_vk -t evm`. `PINNED = false` puts the root link back and is the control: it must land on v2's own count |

Each probe pays its own lookup tables, so parts do not add up to the whole.
The prototype's per-part probes are in `../coinbase-app-attest-poc/`.

## Pinned intermediate (2026-10-27)

`scripts/coinbase-attestation-v2/measure-pinned-intermediate.sh 7`, nargo
1.0.0-beta.19, bb 4.2.0-aztecnr-rc.2. Every row is the WHOLE pinned circuit
with one part switched off, so tables are shared as in the real circuit and
"saved" is that part's marginal cost. Dyadic = 2^(first field of the vk).

| Variant | circuit_size | saved | dyadic |
|---|---|---|---|
| pinned CA 1, everything on | 984,404 | -- | 2^20 |
| control: root link back in (`PINNED = false`) | 1,654,339 | -669,935 | 2^21 (v2 itself: 1,654,257) |
| app checks unconditional (`APP_BRANCH = false`) | 853,070 | 131,334 | 2^20 |
| no app kind at all: server-only (`WITH_APP = false`) | 516,872 | 467,532 | 2^19 |
| credential: P-384 ECDSA by CA 1 | 656,733 | 327,671 | 2^20 |
| credential: SHA-256 of the TBS (<= 1000 B) | 909,192 | 75,212 | 2^20 |
| credential: DER walk (key, nonce, App ID) | 963,353 | 21,051 | 2^20 |
| attestation authData (SHA-256, RP ID, counter, AAGUID) | 956,161 | 28,243 | 2^20 |
| assertion digest (SHA-256 x2, RP ID, counter) | 961,253 | 23,151 | 2^20 |
| clientData field checks | 984,582 | -178 (noise: the probe's sink costs more) | 2^20 |
| P-256 statement signature | 917,285 | 67,119 | 2^20 |
| PART 1 wallet secp256k1 + signed_digest (EIP-712 / personal) | 895,923 | 88,481 | 2^20 |
| PART 2 Coinbase tx: keccak, secp256k1, Merkle, calldata | 706,734 | 277,670 | 2^20 |
| PART 4 wallet nullifier | 949,834 | 34,570 | 2^20 |

The root link costs v2 669,935 gates, not the 385,994 the standalone
`root-link` probe shows: inside `if signer_kind == KIND_APP` every constraint
of the non-native P-384 / SHA-384 work is predicated, and the branch overhead
drops from 436,243 (v2) to 131,334 once the root link is out of it. Pinning CA 1
lands at 984,404, 64,172 under 2^20 (6.1% headroom).
Cross-checked the repo's other way: `scripts/generate_srs.sh
_probes/coinbase-attestation-v2/pinned-intermediate` wrote a 67,109,076-byte
.srs = 2^20 + 3 points of 64 bytes (v2's is 134,217,940 = 2^21), which is
under GitHub's 100 MiB limit, so a pinned circuit's .srs could be committed
as the prototype's was.
