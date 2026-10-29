#!/usr/bin/env python3
"""Checks that a verifier deployed on one chain runs the same code as on another.

    python3 scripts/compare-verifier-code.py <ReferenceChainId> <ChainId>... -- <Name>...

    python3 scripts/compare-verifier-code.py 84532 8453 1 -- \
        OidcDomainAttestation OidcDomainAttestationAndroid

Typical use: after deploying to mainnet, show that each new contract is
byte-for-byte the testnet contract real proofs were verified against. Reads
deployments/<chain>/<Name>.json and deployments/<chain>/ZKTranscriptLib.json,
fetches each contract's runtime code with `cast code`, replaces the linked
library address (it differs per chain) and drops the trailing Solidity
metadata (its IPFS hash differs between builds of the same source), then
compares. Exit 1 on any difference or missing record.

RPC URLs come from the circuits env files, never from the command line:
.env.development (BASE_SEPOLIA_RPC_URL, SEPOLIA_RPC_URL) and .env.production
(BASE_RPC_URL, MAINNET_RPC_URL).
"""
import json
import os
import subprocess
import sys

REPO = subprocess.run(['git', 'rev-parse', '--show-toplevel'], capture_output=True, text=True, check=True).stdout.strip()

RPC_VARS = {
    84532: ('.env.development', 'BASE_SEPOLIA_RPC_URL'),
    11155111: ('.env.development', 'SEPOLIA_RPC_URL'),
    8453: ('.env.production', 'BASE_RPC_URL'),
    1: ('.env.production', 'MAINNET_RPC_URL'),
}

METADATA_MARKER = 'a264697066735822'  # CBOR {"ipfs": bytes(34)...}


def env_value(env_file, name):
    path = os.path.join(REPO, env_file)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith(name + '='):
                return line.split('=', 1)[1].strip().strip('"').strip("'")
    raise SystemExit(f'{name} not set in {env_file}')


def rpc(chain):
    if chain not in RPC_VARS:
        raise SystemExit(f'Unknown chain {chain}. Known: {", ".join(map(str, RPC_VARS))}.')
    return env_value(*RPC_VARS[chain])


def record(chain, name):
    path = os.path.join(REPO, 'deployments', str(chain), f'{name}.json')
    if not os.path.exists(path):
        raise SystemExit(f'No record {path}')
    with open(path) as f:
        return json.load(f)['address'].lower()


def runtime(chain, name):
    out = subprocess.run(['cast', 'code', record(chain, name), '--rpc-url', rpc(chain)],
                         capture_output=True, text=True, check=True).stdout.strip().lower()
    if out in ('', '0x'):
        raise SystemExit(f'No code for {name} on {chain}')
    code = out[2:].replace(record(chain, 'ZKTranscriptLib')[2:], 'L' * 40)
    cut = code.rfind(METADATA_MARKER)
    return code[:cut] if cut > 0 else code


def main(argv):
    if '--' not in argv:
        raise SystemExit(__doc__)
    split = argv.index('--')
    chains = [int(c) for c in argv[:split]]
    names = argv[split + 1:]
    if len(chains) < 2 or not names:
        raise SystemExit(__doc__)
    ref, others = chains[0], chains[1:]
    failed = False
    for name in names:
        expected = runtime(ref, name)
        for chain in others:
            same = runtime(chain, name) == expected
            failed |= not same
            print(f"{'same' if same else 'DIFFERENT':9} {name} on {chain} {record(chain, name)} vs {ref} {record(ref, name)} ({len(expected) // 2} bytes)")
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
