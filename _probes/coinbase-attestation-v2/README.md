# coinbase_attestation_v2 gate probes

Measurement provenance for `../../coinbase-attestation-v2`, not circuits: no
fixtures, no vk, nothing deployed. `scripts/coinbase-attestation-v2/measure.sh`
compiles each and prints `bb gates` beside the whole circuit.

| Probe | What it contains |
|---|---|
| `coinbase-base` | GENERATED from v2's main.nr: everything except the statement (request signature, attestation transaction and signer, Merkle proof, wallet nullifier) |
| `unconditional-app-checks` | GENERATED from v2's source with `if signer_kind == KIND_APP {` replaced by `{`: what the circuit would cost if the App Attest checks were not inside the branch. It refuses every server-kind witness, so it only measures |
| `root-link` | What v2 added over the prototype: SHA-384 of the intermediate TBS (<= 600 bytes), ECDSA P-384 by Apple's root (a constant), and the intermediate DER walk |
| `sha384-intermediate` | The SHA-384 of the intermediate TBS alone (zkpassport/sha512 v0.1.1, five 128-byte blocks) |

Each probe pays its own lookup tables, so parts do not add up to the whole.
The prototype's per-part probes are in `../coinbase-app-attest-poc/`.
