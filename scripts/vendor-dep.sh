#!/usr/bin/env bash
#
# Replace the copy under deps/<dir> with an upstream ref, the way
# scripts/check-deps.sh expects copies to be made, and record it in
# deps/MANIFEST.json.
#
#   ./scripts/vendor-dep.sh <dir> <ref>                  # ref = tag, or a commit for an untagged fix
#   ./scripts/vendor-dep.sh <dir> <ref> --drop-patches   # the new ref no longer needs PATCHES.md
#   ./scripts/vendor-dep.sh <dir> <ref> --keep-patches   # keep PATCHES.md; re-apply its files by hand
#
# What it does:
#   1. clones the manifest entry's repo and checks out <ref>;
#   2. replaces deps/<dir> with that tree, minus .git, .github, target, node_modules;
#   3. rewrites every `git =` dependency in its Nargo.toml files (the root one,
#      or each package's in a multi-package repository) to a `path` into deps/,
#      honouring `directory = "<sub>"`:
#      the upstream repo is looked up in the manifest first, then the dependency's
#      package name among the vendored copies (noir-jwt asks for noir-lang's
#      bignum, and this repository has one bignum: zkpassport's). A dependency
#      that matches neither is an error -- add that library first;
#   4. sets `ref`, `ref_is_tag`, `commit` and `content_sha256` in the manifest.
#      `newest_reviewed` and `hold` are left for a person: they record a review.
#
# A copy with a PATCHES.md is refused unless one of the two flags says what to
# do with it. --keep-patches keeps PATCHES.md and prints the files it lists,
# which now hold upstream's text again; re-apply each change, then run
# `./scripts/check-deps.sh --hash <dir>` and put that hash in the manifest.
#
# Every circuit compiled with a changed dependency gets a new verification key.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"

exec python3 -I - "$CIRCUITS_DIR" "$@" <<'PY'
import json, os, re, shutil, subprocess, sys, tempfile

root = sys.argv[1]
args = sys.argv[2:]
if len(args) not in (2, 3) or (len(args) == 3 and args[2] not in ('--drop-patches', '--keep-patches')):
    sys.exit('usage: vendor-dep.sh <dir> <ref> [--drop-patches | --keep-patches]')
d, ref = args[0], args[1]
flag = args[2] if len(args) == 3 else None

deps_dir = os.path.join(root, 'deps')
manifest_path = os.path.join(deps_dir, 'MANIFEST.json')
manifest = json.load(open(manifest_path, encoding='utf-8'))
entries = {e['dir']: e for e in manifest['deps']}
if d not in entries:
    sys.exit(f'deps/{d} is not in deps/MANIFEST.json. Known: {", ".join(sorted(entries))}.')
entry = entries[d]
dest = os.path.join(deps_dir, d)
patches = os.path.join(dest, 'PATCHES.md')
if os.path.exists(patches) and flag is None:
    sys.exit(f'deps/{d} has a PATCHES.md. Pass --drop-patches if {ref} no longer needs it, '
             f'or --keep-patches to keep it and re-apply its changes by hand.')

SKIP = {'.git', '.github', 'target', 'node_modules'}

def package_name(nargo):
    m = re.search(r'^\s*name\s*=\s*"([^"]+)"', open(nargo, encoding='utf-8').read(), re.M)
    return m.group(1) if m else None

by_repo = {e['repo'].lower(): e['dir'] for e in manifest['deps']}
by_package = {}
for other in os.listdir(deps_dir):
    n = os.path.join(deps_dir, other, 'Nargo.toml')
    if other != d and os.path.isfile(n):
        by_package[package_name(n)] = other

with tempfile.TemporaryDirectory() as tmp:
    clone = os.path.join(tmp, 'src')
    subprocess.run(['git', 'clone', '-q', f'https://github.com/{entry["repo"]}', clone], check=True)
    r = subprocess.run(['git', '-C', clone, 'checkout', '-q', ref], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f'{entry["repo"]} has no ref {ref}: {r.stderr.strip()}')
    commit = subprocess.run(['git', '-C', clone, 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()
    is_tag = subprocess.run(['git', '-C', clone, 'show-ref', '--verify', '-q', f'refs/tags/{ref}']).returncode == 0

    kept = open(patches, encoding='utf-8').read() if flag == '--keep-patches' and os.path.exists(patches) else None
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    shutil.copytree(clone, dest, ignore=lambda cur, names: [n for n in names if n in SKIP])
    if kept is not None:
        open(patches, 'w', encoding='utf-8').write(kept)

# Point git dependencies at the vendored copies. A repository may hold one
# package at its root or several in subfolders with no root Nargo.toml
# (TaceoLabs/oprf-nr, TaceoLabs/noir-poseidon); every Nargo.toml in the tree is
# rewritten, and a `directory = "<sub>"` names the package inside the target.
nargos = sorted(os.path.join(cur, 'Nargo.toml') for cur, _, files in os.walk(dest) if 'Nargo.toml' in files)
if not nargos:
    sys.exit(f'{entry["repo"]} {ref} has no Nargo.toml anywhere; it is not a Noir library.')
rewritten = []
for nargo in nargos:
    nrel = os.path.relpath(nargo, deps_dir)
    lines, out, in_deps = open(nargo, encoding='utf-8').read().split('\n'), [], False
    for line in lines:
        s = line.strip()
        if s.startswith('['):
            in_deps = s == '[dependencies]'
        m = re.match(r'^(\s*)([A-Za-z0-9_\-]+)\s*=\s*\{(.*)\}(.*)$', line) if in_deps else None
        if m and re.search(r'\bgit\s*=', m.group(3)):
            key, body, tail = m.group(2), m.group(3), m.group(4)
            url = re.search(r'git\s*=\s*"([^"]+)"', body).group(1)
            repo = re.sub(r'^https://github\.com/|/$|\.git$', '', url.rstrip('/')).lower()
            target = by_repo.get(repo) or by_package.get(key)
            if target is None:
                sys.exit(f'deps/{nrel} needs {key} from {url}, which no vendored copy provides. '
                         f'Vendor it first and list it in deps/MANIFEST.json.')
            if target == d:
                sys.exit(f'deps/{nrel} depends on itself through {url}')
            sub = re.search(r'directory\s*=\s*"([^"]+)"', body)
            target_dir = os.path.join(deps_dir, target, sub.group(1)) if sub else os.path.join(deps_dir, target)
            if not os.path.isfile(os.path.join(target_dir, 'Nargo.toml')):
                sys.exit(f'deps/{nrel} needs {key} from {url}'
                         f'{" directory " + sub.group(1) if sub else ""}, but '
                         f'{os.path.relpath(target_dir, root)} holds no Nargo package.')
            rel_path = os.path.relpath(target_dir, os.path.dirname(nargo))
            line = f'{m.group(1)}{key} = {{ path = "{rel_path}" }}{tail}'
            tag = re.search(r'(?:tag|rev|branch)\s*=\s*"([^"]+)"', body)
            asked = tag.group(1) if tag else 'no ref'
            rewritten.append(f'{nrel}: {key} -> {os.path.relpath(target_dir, root)} (upstream asked for {url} {asked})')
        out.append(line)
    open(nargo, 'w', encoding='utf-8').write('\n'.join(out))

h = subprocess.run([os.path.join(root, 'scripts', 'check-deps.sh'), '--hash', d],
                   capture_output=True, text=True, check=True).stdout.strip()
entry.update({'ref': ref, 'commit': commit, 'content_sha256': h})
if is_tag:
    entry.pop('ref_is_tag', None)
else:
    entry['ref_is_tag'] = False
open(manifest_path, 'w', encoding='utf-8').write(json.dumps(manifest, indent=2) + '\n')

print(f'deps/{d} = {entry["repo"]} {ref} ({commit}){"" if is_tag else ", not a tag"}')
for r in rewritten:
    print(f'  {r}')
print(f'  content_sha256 {h}')
if kept is not None:
    from_listed = [l for l in kept.splitlines() if l.startswith(('- `', '* `'))]
    print('  PATCHES.md kept. These files hold upstream text again; re-apply the changes, then refresh the hash:')
    for l in from_listed:
        print('    ' + l)
print('  Review `newest_reviewed` / `hold` in deps/MANIFEST.json by hand.')
PY
