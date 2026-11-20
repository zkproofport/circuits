#!/usr/bin/env python3
"""Checks that a deployed verifier runs exactly the code this checkout builds.

    python3 scripts/check-deployed-code.py <chainId> <Name>...
    python3 scripts/check-deployed-code.py 91342 GiwaAttestation DojangPlayground

For each <Name> it reads deployments/<chainId>/<Name>.json (written by
deploy_verifier.sh), takes the HonkVerifier artifact forge compiled from the
record's `deployedFrom` source (out/<File>.sol/HonkVerifier.json; run
`forge build` first), fills the link placeholders with the record's library
addresses, and compares it with the code at the recorded address byte for
byte. Not compared: the artifact's immutable slots, which the constructor
fills, and the trailing CBOR metadata, whose hash covers the compiler settings
(the --libraries a deploy passes are among them). Each linked library's code on chain is hashed the way
scripts/lib/verifier-libraries.sh does and must equal the codeHash in the
record and the hash of that library compiled from the same source. It prints
keccak256 of the deployed runtime code too. Exit 1 on any difference or a
missing record or artifact.

RPC URLs come from the circuits env files, never from the command line.
"""
import json
import os
import subprocess
import sys

CIRCUITS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RPC_VARS = {
    84532: ('.env.development', 'BASE_SEPOLIA_RPC_URL'),
    11155111: ('.env.development', 'SEPOLIA_RPC_URL'),
    91342: ('.env.development', 'GIWA_SEPOLIA_RPC_URL'),
    8453: ('.env.production', 'BASE_RPC_URL'),
    1: ('.env.production', 'MAINNET_RPC_URL'),
}


def env_value(env_file, name):
    with open(os.path.join(CIRCUITS, env_file)) as f:
        for line in f:
            line = line.strip()
            if line.startswith(name + '='):
                return line.split('=', 1)[1].strip().strip('"').strip("'")
    sys.exit(f'{name} not set in {env_file}')


def rpc(chain):
    if chain not in RPC_VARS:
        sys.exit(f'Unknown chain {chain}. Known: {", ".join(map(str, RPC_VARS))}.')
    return env_value(*RPC_VARS[chain])


def cast(*args):
    return subprocess.run(['cast', *args], capture_output=True, text=True, check=True).stdout.strip()


def code_at(address, url):
    code = cast('code', address, '--rpc-url', url).lower().removeprefix('0x')
    if not code:
        sys.exit(f'no code at {address}')
    return bytes.fromhex(code)


def library_hash(raw):
    """scripts/lib/verifier-libraries.sh library_code_hash, on bytes."""
    if raw[0] == 0x73 and len(raw) > 21:
        raw = raw[:1] + bytes(20) + raw[21:]
    if len(raw) >= 2:
        meta = int.from_bytes(raw[-2:], 'big')
        if meta + 2 <= len(raw) and raw[len(raw) - meta - 2] in (0xa1, 0xa2, 0xa3):
            raw = raw[:len(raw) - meta - 2]
    return cast('keccak', '0x' + raw.hex())


def artifact(sol, contract):
    path = os.path.join(CIRCUITS, 'out', os.path.basename(sol), f'{contract}.json')
    if not os.path.exists(path):
        sys.exit(f'no artifact {path}; run forge build')
    return json.load(open(path))['deployedBytecode']


def check(chain, name, url):
    path = os.path.join(CIRCUITS, 'deployments', str(chain), f'{name}.json')
    if not os.path.exists(path):
        sys.exit(f'no record {path}')
    record = json.load(open(path))
    sol = record.get('deployedFrom')
    libs = record.get('libraries')
    if not sol or not libs:
        sys.exit(f'{path} has no deployedFrom/libraries (not a deploy_verifier.sh bb 6 record)')
    art = artifact(sol, 'HonkVerifier')
    obj = art['object'].removeprefix('0x')
    # Fill link placeholders by position (linkReferences), not by text.
    hexchars = list(obj)
    for _file, by_lib in art['linkReferences'].items():
        for lib, refs in by_lib.items():
            if lib not in libs:
                sys.exit(f'{name}: artifact links {lib}, record has no address for it')
            addr = libs[lib]['address'].lower().removeprefix('0x')
            for r in refs:
                s = r['start'] * 2
                hexchars[s:s + 40] = list(addr)
    expected = bytearray(bytes.fromhex(''.join(hexchars)))
    deployed = bytearray(code_at(record['address'], url))
    masked = 0
    for refs in art.get('immutableReferences', {}).values():
        for r in refs:
            s, n = r['start'], r['length']
            expected[s:s + n] = bytes(n)
            deployed[s:s + n] = bytes(n)
            masked += 1
    # The trailing CBOR metadata is not compared: it hashes the compiler
    # settings, and deploy_verifier.sh's --libraries are part of them, so a
    # plain `forge build` of the same source carries another IPFS hash.
    meta = int.from_bytes(deployed[-2:], 'big')
    cut = len(deployed) - meta - 2
    if not (0 < cut and deployed[cut] in (0xa1, 0xa2, 0xa3)):
        sys.exit(f'{name}: no CBOR metadata at the end of the deployed code')
    ok = len(expected) == len(deployed) and expected[:cut] == deployed[:cut]
    print(f'{name} {record["address"]} on {chain}: runtime {len(deployed)} bytes, '
          f'{"MATCHES" if ok else "DIFFERS FROM"} {sol} (HonkVerifier; {masked} immutable slots and the {meta + 2}-byte metadata not compared); '
          f'keccak256(runtime) {cast("keccak", "0x" + code_at(record["address"], url).hex())}')
    for lib, entry in sorted(libs.items()):
        onchain = library_hash(code_at(entry['address'], url))
        built = library_hash(bytes.fromhex(artifact(sol, lib)['object'].removeprefix('0x')))
        lib_ok = onchain == entry['codeHash'] == built
        ok = ok and lib_ok
        print(f'  {lib} {entry["address"]}: code hash {onchain} '
              f'{"= record = build" if lib_ok else f"!= (record {entry["codeHash"]}, build {built})"}')
    return ok


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    chain = int(sys.argv[1])
    url = rpc(chain)
    results = [check(chain, name, url) for name in sys.argv[2:]]
    sys.exit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
