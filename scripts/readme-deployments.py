#!/usr/bin/env python3
"""Regenerate README.md's "Reference deployments" tables from broadcast records.

    python3 scripts/readme-deployments.py            # rewrite README.md
    python3 scripts/readme-deployments.py --check    # exit 1 if README.md is stale

The tables used to be written by hand from `broadcast/**/run-latest.json`, so
every deploy needed someone to copy an address correctly. This reads the same
records: the HonkVerifier CREATE in each Deploy<Contract>.s.sol/<chain>
run-latest.json whose receipt has status 1.

The section names the commit it was synchronized at: HEAD when the working tree
has no uncommitted broadcast change, otherwise the caller passes --revision.

Every broadcast directory must be listed below, either as a circuit or as
excluded with its reason. An unknown one is an error, not a silent omission.
"""
import argparse
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(
    subprocess.run(['git', 'rev-parse', '--show-toplevel'], capture_output=True,
                   text=True, check=True).stdout.strip())
README = REPO / 'README.md'
BROADCAST = REPO / 'broadcast'

# Order is the README's order.
CHAINS = [
    (11155111, 'Ethereum Sepolia'),
    (84532, 'Base Sepolia'),
    (8453, 'Base Mainnet'),
    (91342, 'GIWA Sepolia'),
]
# Chains with broadcasts that the README does not publish, and why.
EXCLUDED_CHAINS = {
    # Not in the README when the generator was introduced (0a2d988); its
    # broadcasts are the April 2026 beta.8 deploys. Publishing them is a
    # decision, not something this script should do on its own.
    1: 'Ethereum mainnet: not listed in the README as of 0a2d988',
}

CIRCUITS = [
    ('CoinbaseAttestation', 'Coinbase KYC'),
    ('CoinbaseAttestationV2', 'Coinbase KYC v2 (pre-release)'),
    ('CoinbaseCountryAttestation', 'Coinbase Country'),
    ('OidcDomainAttestation', 'OIDC Domain'),
    ('OidcDomainAttestationAndroid', 'OIDC Domain (Android)'),
    ('CoinbaseAttestationV2Android', 'Coinbase KYC v2 (Android)'),
    ('OidcDomainAttestationAndroidFactory', 'OIDC Domain (Android, factory keys)'),
    ('CoinbaseAttestationV2AndroidFactory', 'Coinbase KYC v2 (Android, factory keys)'),
    ('CoinbaseCountryAttestationV2', 'Coinbase Country v2 (pre-release)'),
    ('CoinbaseCountryAttestationV2Android', 'Coinbase Country v2 (Android)'),
    ('CoinbaseCountryAttestationV2AndroidFactory', 'Coinbase Country v2 (Android, factory keys)'),
    ('GiwaAttestation', 'GIWA attestation'),
    ('DojangPlayground', 'Dojang Playground'),
]
EXCLUDED_SCRIPTS = {
    'NullifierRegistry': 'deprecated nullifier registry, not a verifier',
    'ZKProofPortNullifierRegistry': 'deprecated nullifier registry, not a verifier',
    'CoinbaseAppAttestPoc': 'prototype superseded by coinbase_attestation v2 (2026-10-23), not shipped',
    # deploy_verifier.sh deploys the library through script/DeployTranscriptLib.s.sol
    # since 2026-10-23; its address is recorded in deployments/<chain>/ZKTranscriptLib.json.
    'TranscriptLib': 'ZKTranscriptLib library linked by every verifier, not a verifier',
}

BEGIN = '## Reference deployments\n'
END = '## Deploying verifiers\n'


def verifier_from(record: pathlib.Path) -> str:
    data = json.loads(record.read_text())
    receipts = {r['transactionHash']: r for r in data.get('receipts', [])}
    hits = []
    for tx in data['transactions']:
        if tx.get('transactionType') != 'CREATE' or tx.get('contractName') != 'HonkVerifier':
            continue
        receipt = receipts.get(tx['hash'])
        if receipt is None:
            raise SystemExit(f'{record}: no receipt for {tx["hash"]}')
        if int(receipt['status'], 16) != 1:
            raise SystemExit(f'{record}: deploy {tx["hash"]} has status {receipt["status"]}')
        hits.append(tx['contractAddress'].lower())
    if len(hits) != 1:
        raise SystemExit(f'{record}: expected one HonkVerifier CREATE, found {len(hits)}')
    return hits[0]


def collect() -> dict:
    known = {name for name, _ in CIRCUITS} | set(EXCLUDED_SCRIPTS)
    chain_ids = {cid for cid, _ in CHAINS} | set(EXCLUDED_CHAINS)
    found = {}
    for script_dir in sorted(BROADCAST.iterdir()):
        name = script_dir.name.removeprefix('Deploy').removesuffix('.s.sol')
        if name not in known:
            raise SystemExit(f'Unknown broadcast {script_dir.name}. Add it to CIRCUITS or '
                             f'EXCLUDED_SCRIPTS. Known: {", ".join(sorted(known))}.')
        if name in EXCLUDED_SCRIPTS:
            continue
        for chain_dir in sorted(script_dir.iterdir()):
            cid = int(chain_dir.name)
            if cid not in chain_ids:
                raise SystemExit(f'Unknown chain {cid} in {chain_dir}. Add it to CHAINS or '
                                 f'EXCLUDED_CHAINS. Known: {", ".join(map(str, sorted(chain_ids)))}.')
            if cid in EXCLUDED_CHAINS:
                continue
            record = chain_dir / 'run-latest.json'
            if not record.exists():
                raise SystemExit(f'{chain_dir} has no run-latest.json')
            found[(cid, name)] = (verifier_from(record), record.relative_to(REPO).as_posix())
    return found


def render(found: dict, revision: str) -> str:
    out = [BEGIN, '\n',
           'The tables below are generated by `scripts/readme-deployments.py` from '
           '`broadcast/**/run-latest.json` at revision '
           f'[`{revision}`](https://github.com/zkproofport/circuits/commit/{revision}).\n',
           '\n']
    for cid, chain_name in CHAINS:
        rows = [(display, *found[(cid, name)], name) for name, display in CIRCUITS if (cid, name) in found]
        if not rows:
            continue
        out += [f'### {chain_name} — chain ID {cid}\n', '\n',
                '| Circuit | Verifier | Deployment record |\n', '|---|---|---|\n']
        for display, address, record, name in rows:
            out.append(f'| {display} | `{address}` | [`Deploy{name}`]({record}) |\n')
        out.append('\n')
    return ''.join(out)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--revision', help='commit the broadcast records were taken from')
    args = parser.parse_args()

    revision = args.revision
    if revision is None:
        dirty = subprocess.run(['git', 'status', '--porcelain', '--', 'broadcast'],
                               capture_output=True, text=True, check=True, cwd=REPO).stdout
        if dirty.strip():
            raise SystemExit('broadcast/ has uncommitted changes; commit them first or pass --revision')
        revision = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True,
                                  check=True, cwd=REPO).stdout.strip()

    text = README.read_text()
    start, end = text.find(BEGIN), text.find(END)
    if start < 0 or end < 0 or end < start:
        raise SystemExit(f'README.md must contain "{BEGIN.strip()}" followed by "{END.strip()}"')
    new = text[:start] + render(collect(), revision) + text[end:]

    if args.check:
        current = text[start:end]
        generated = render(collect(), revision)
        # The revision line differs whenever HEAD moves; compare the tables only.
        strip = lambda s: [l for l in s.splitlines() if not l.startswith('The tables below')]
        if strip(current) != strip(generated):
            print('README.md deployment tables are stale; run scripts/readme-deployments.py', file=sys.stderr)
            sys.exit(1)
        print('README.md deployment tables match the broadcast records')
        return
    README.write_text(new)
    print(f'README.md deployment tables regenerated at {revision}')


if __name__ == '__main__':
    main()
