# GIWA proof-of-concept scripts

The GIWA attester is ours: `MockGiwaAttester` on GIWA Sepolia, at the address
in `circuits/.env.development`. It exposes the same `attestAccount(address)`
selector as the Coinbase attester, so the circuit's raw-transaction path is
unchanged from the Coinbase fork.

## The fixture, and why you do not have to search for it again

`giwa_attestation` is exercised against a REAL attestation transaction:

| | |
|---|---|
| attestation tx | `0x961ac707e3805289ba2a8fb7118080cb54a0bf60b7a4ad4f7f3ac42c8c8878f7` |
| block | 25424198, GIWA Sepolia (chain 91342) |
| attested wallet | `0x5A3E649208Ae15ec52496c1Ae23b2Ff89Ac02f0c` — the key in `.env.development`, which is why this wallet can sign |
| attester | `0xEE099845CDfF93e73aDcBcB36A9B93578bcCed4b` |

That hash is the default inside `generate-prover-toml.js`. A synthetic
transaction would have tested the RLP parser against bytes we invented; these
are the bytes the chain holds.

## Commands

```bash
# Both fixtures, no arguments. Needs .env.development and the GIWA Sepolia RPC.
scripts/giwa-poc/make-fixtures.sh

# One fixture, explicitly
node scripts/giwa-poc/generate-prover-toml.js [--action] [--out PATH] [0x<tx>]

# Attest another address (costs gas on GIWA Sepolia)
node scripts/giwa-poc/attest-account.js
```

`Prover.toml` is gitignored across this repository, so the fixtures are not
committed. The acceptance run regenerates them when they are missing, and
skips itself with a message when `.env.development` is absent.

## What the acceptance run covers

`scripts/giwa-poc/acceptance.sh`, which `scripts/build.sh` invokes through the
forwarder at `giwa-attestation/scripts/post-build.sh` — the one path that
script looks for. Run it directly with `scripts/giwa-poc/acceptance.sh`. Both modes are accepted against the real attestation, and seven
tampered fixtures are refused, each with a named reason. The tampered fixtures
are derived from the good ones by rewriting one field
(`tamper-fixture.js`), so no network is needed to prove the circuit says no.
