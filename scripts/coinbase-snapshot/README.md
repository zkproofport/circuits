# Coinbase KYC snapshot tree (prototype)

A Poseidon Merkle tree of every Base address holding an unrevoked Coinbase KYC
attestation at a fixed block. `coinbase-snapshot-poc` proves membership in it;
`src/SnapshotRootRegistry.sol` records published roots and which are still
accepted. Revocation is enforced by acceptance: a wallet revoked after a root
was built stays in that root, so old roots stop verifying.

| File | What it does |
|---|---|
| `config.json` | The rule (schema, attester, tree depth) and the operating knobs |
| `build-snapshot.js` | Builds the tree for one block and writes `coinbase-snapshot-poc/snapshots/<block>.json` |
| `tree.js` | The tree itself: leaf, node, empty values, path. No network |
| `generate-prover-toml.js` | A Prover.toml from a snapshot, computing the path from the whole file |
| `make-fixtures.sh` | Snapshot if none, then the accepted and refused fixtures |

## The update interval, and how it was chosen

Measured 2026-10-22 on Base (EAS explorer GraphQL, Base RPC):

| Observation | Value |
|---|---|
| Coinbase KYC revocations, last 30 days | 1,195 |
| Per day | 14 to 66, median 37 |
| Per hour | mean 1.66, max 17 |
| Median gap between revocations | 20 minutes |
| `finalized` behind `latest` | 1,078 s (about 18 minutes), one reading |
| Base block time | 2 s |

Chosen: **`intervalBlocks` 900 (30 minutes), `acceptedRoots` 2, `basisBlockTag` finalized.**

How long a revoked wallet can still pass is roughly finality lag + time to the
next basis block + build and publish + one extra accepted root:
18 + up to 30 + a few + 30 = about 80 minutes at worst, about an hour typically.
At 1.66 revocations an hour, one or two revoked wallets are inside that window at
any moment, and only if they actively try.

Shorter costs little on chain (a publish is about 91k gas including the 21k base;
at 0.006 gwei that is about 0.0013 USD) but every update is another snapshot the
app may have to fetch, and a proof started just before an update needs the
previous root to still count. Longer widens the window linearly.

## Tuning it

| Knob | Where | Effect |
|---|---|---|
| Update interval | `config.json` `intervalBlocks` | How often a basis block occurs (900 = 30 min) |
| Accepted roots | `SnapshotRootRegistry.setAcceptedRoots(n)`, owner only | How many newest roots verify. 1 is strictest; 2 lets a proof begun before an update land |
| Basis | `config.json` `basisBlockTag` | `finalized` (about 18 min behind, reproducible) or `safe` (under a minute behind, a reorg could move it) |

Changing `schema`, `attester` or `treeDepth` changes the rule: every root
changes, and `treeDepth` must match `TREE_DEPTH` in the circuit.

## Why the candidates come from the explorer

Inclusion is decided by `EAS.getAttestation(uid)` read at the basis block, so
the explorer can only cause an omission, never admit a revoked or invented
uid. It is used because no free RPC serves this schema's event history
(2026-10-22: Alchemy free allows 10 blocks per `eth_getLogs`, drpc free refused
every range tried, publicnode requires an archive token, 1rpc caps at 50
blocks). A paid log provider would let the candidate list come from `Attested`
events directly, which is what an auditor should do to check completeness.

## First measurements (2026-10-22, M5 Pro)

| What | Value |
|---|---|
| Basis block | 52,930,800 |
| Live attestations / distinct addresses | 313,961 / 313,955 |
| Explorer said live, chain at the basis block said otherwise | 10 revoked, 2 not yet attested |
| Build time | candidates 329 s (first run; cached after), on-chain check 223 s, tree 47 s |
| Snapshot file | 14.1 MB JSON (addresses as hex; 6.3 MB as raw bytes) |
| Circuit | 166,334 gates (`bb gates`); `coinbase_attestation` is 395,851 |
| `bb prove` | 1.03 to 1.06 s, 0.68 GB RSS (3 runs); `coinbase_attestation` 1.9 s, 1.28 GB |
| Acceptance | 10 of 10 (`scripts/action-circuit-acceptance.sh coinbase-snapshot-poc`) |

Open: rebuilding the whole tree in JavaScript took 46 to 48 s here, about
75 microseconds a hash; a phone will be slower. The app should not hash
314k leaves. Publishing one upper level of the tree beside the leaves lets it
hash only its own chunk (for 1,024-leaf chunks, about 2,000 hashes) and still
download everything, so nobody learns which chunk it wanted.

Open, and a defect in the prototype registry: roots age out only when newer
ones are published. If the publishing job stops, the last root stays accepted
forever and a wallet revoked after it keeps passing. A real registry also needs
a maximum age in time -- which then makes every proof fail while the job is
down. Running the job is the cost of this design: a scheduler, a funded
publisher key, an RPC quota for about 1,250 multicalls per run, public hosting
for a 14 MB file, and monitoring.
