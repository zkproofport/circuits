#!/usr/bin/env bash
#
# Every Noir library a circuit compiles comes from one local copy under deps/,
# pinned to an upstream release, and nothing changes that copy silently.
#
#   ./scripts/check-deps.sh              # offline: run before every commit and in CI
#   ./scripts/check-deps.sh --upstream   # network: compare each copy with its upstream tag
#   ./scripts/check-deps.sh --hash <dir> # print the content hash of deps/<dir>
#
# Why: until 2026-11-16 the circuits mixed git dependencies with hand-made
# copies. keccak256 v0.1.1 was copied into deps/ two months after upstream had
# fixed a padding bug in v0.1.2, while coinbase-libs and nodash kept fetching
# the same buggy tag from git. sha256 came in at two versions. Nothing said so.
#
# The offline check fails when:
#   - a Nargo.toml outside _archived-poc/ and _probes/ uses `git =`;
#   - a path dependency points outside deps/ without being a package of this
#     repository, or into a deps/ folder the manifest does not list;
#   - two folders under deps/ declare the same package name (two versions of
#     one library);
#   - a folder under deps/ differs from the content hash in deps/MANIFEST.json.
#     The hash covers every vendored file except the Nargo.toml files (their
#     dependency lines point at deps/ instead of git; a multi-package library
#     has one per package), PATCHES.md, and the files that
#     PATCHES.md lists as changed from upstream.
#
# --upstream also clones each pinned tag and fails when:
#   - the vendored files (minus the patched ones) are not the tag's files;
#   - upstream has published a tag newer than the manifest's `newest_reviewed`.
#     Raise `newest_reviewed` only after looking at that release; when it
#     cannot be taken (for example it needs a newer nargo than toolchain.env
#     pins), say why in `hold`.
#
# Changing a dependency: copy the new tag into deps/<dir> (without .git or
# .github), re-apply the changes PATCHES.md lists, point its Nargo.toml at
# deps/, then update `ref`, `commit`, `newest_reviewed` and `content_sha256`
# (`--hash <dir>`) in deps/MANIFEST.json. Every circuit compiled with it gets
# a new verification key, so it ships with that circuit's next release.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"

exec python3 -I - "$CIRCUITS_DIR" "$@" <<'PY'
import hashlib, json, os, re, subprocess, sys, tempfile

root = sys.argv[1]
args = sys.argv[2:]
deps_dir = os.path.join(root, 'deps')
manifest_path = os.path.join(deps_dir, 'MANIFEST.json')
SKIP_DIRS = {'.git', '.github', 'target', 'node_modules'}
EXCLUDED_TREES = ('_archived-poc', '_probes', 'lib', 'node_modules', 'out', 'cache', 'broadcast')

def patched_files(dep_path):
    """Files PATCHES.md lists under '## Changed files' as top-level `path` items."""
    p = os.path.join(dep_path, 'PATCHES.md')
    if not os.path.exists(p):
        return set()
    files, in_section = set(), False
    for line in open(p, encoding='utf-8'):
        if line.startswith('## '):
            in_section = line.strip().lower() == '## changed files'
            continue
        # Top-level items only; every `path` before the item's first ': ' counts.
        m = re.match(r'^[-*]\s+((?:`[^`]+`[,\s]*(?:and\s+)?)+):', line)
        if in_section and m:
            files.update(re.findall(r'`([^`]+)`', m.group(1)))
    return files

def content_hash(dep_path, patched):
    lines = []
    for cur, dirs, files in os.walk(dep_path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            rel = os.path.relpath(os.path.join(cur, f), dep_path)
            if os.path.basename(rel) == 'Nargo.toml' or rel == 'PATCHES.md' or rel in patched:
                continue
            with open(os.path.join(cur, f), 'rb') as fh:
                lines.append(f'{rel}\t{hashlib.sha256(fh.read()).hexdigest()}')
    return hashlib.sha256('\n'.join(sorted(lines)).encode()).hexdigest()

def package_name(nargo):
    m = re.search(r'^\s*name\s*=\s*"([^"]+)"', open(nargo, encoding='utf-8').read(), re.M)
    return m.group(1) if m else None

def nargo_files():
    for cur, dirs, files in os.walk(root):
        rel = os.path.relpath(cur, root)
        top = rel.split(os.sep)[0]
        if top in EXCLUDED_TREES or any(d in SKIP_DIRS for d in rel.split(os.sep)):
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if 'Nargo.toml' in files:
            yield os.path.join(cur, 'Nargo.toml')

def dependency_lines(nargo):
    out, in_deps = [], False
    for n, line in enumerate(open(nargo, encoding='utf-8'), 1):
        s = line.split('#', 1)[0].strip()
        if s.startswith('['):
            in_deps = s == '[dependencies]'
            continue
        if in_deps and '=' in s:
            out.append((n, s))
    return out

if args[:1] == ['--hash']:
    if len(args) != 2:
        sys.exit('usage: check-deps.sh --hash <dir under deps/>')
    d = os.path.join(deps_dir, args[1])
    if not os.path.isdir(d):
        sys.exit(f'No such folder: {d}')
    print(content_hash(d, patched_files(d)))
    sys.exit(0)
if args not in ([], ['--upstream']):
    sys.exit('usage: check-deps.sh [--upstream | --hash <dir>]')

if not os.path.exists(manifest_path):
    sys.exit(f'Missing {manifest_path}.')
manifest = json.load(open(manifest_path, encoding='utf-8'))
entries = {e['dir']: e for e in manifest['deps']}

errors = []

# 1. No git dependencies; every path dependency resolves to a manifest entry
#    or to a package of this repository.
for nargo in sorted(nargo_files()):
    rel = os.path.relpath(nargo, root)
    for n, s in dependency_lines(nargo):
        if re.search(r'\bgit\s*=', s):
            errors.append(f'{rel}:{n}: fetches from git: {s}')
            continue
        m = re.search(r'\bpath\s*=\s*"([^"]+)"', s)
        if not m:
            errors.append(f'{rel}:{n}: dependency without a path: {s}')
            continue
        target = os.path.normpath(os.path.join(os.path.dirname(nargo), m.group(1)))
        if not os.path.isfile(os.path.join(target, 'Nargo.toml')):
            errors.append(f'{rel}:{n}: path does not hold a Nargo package: {m.group(1)}')
            continue
        trel = os.path.relpath(target, root)
        if trel.startswith('deps' + os.sep):
            dep_top = trel.split(os.sep)[1]
            if dep_top not in entries:
                errors.append(f'{rel}:{n}: deps/{dep_top} is not listed in deps/MANIFEST.json')
        elif trel.startswith('..') or trel.split(os.sep)[0] in EXCLUDED_TREES:
            errors.append(f'{rel}:{n}: path leaves the live circuits: {m.group(1)}')

# 2. One folder per library, and every manifest entry exists.
by_package = {}
for d in sorted(os.listdir(deps_dir)):
    nargo = os.path.join(deps_dir, d, 'Nargo.toml')
    if not os.path.isfile(nargo):
        continue
    if d not in entries:
        errors.append(f'deps/{d} is not listed in deps/MANIFEST.json')
    by_package.setdefault(package_name(nargo), []).append(d)
for pkg, dirs in sorted(by_package.items()):
    if len(dirs) > 1:
        errors.append(f'package "{pkg}" is vendored more than once: ' + ', '.join(f'deps/{d}' for d in dirs))
for d, e in sorted(entries.items()):
    path = os.path.join(deps_dir, d)
    if not os.path.isdir(path):
        errors.append(f'deps/MANIFEST.json lists deps/{d}, which does not exist')
        continue
    # 3. Content matches the manifest.
    got = content_hash(path, patched_files(path))
    if got != e['content_sha256']:
        errors.append(f'deps/{d} differs from its manifest entry ({e["repo"]} {e["ref"]}): '
                      f'content {got}, manifest {e["content_sha256"]}. A change to a vendored '
                      f'file belongs in PATCHES.md; a new upstream tag needs a new manifest entry.')
    listed = patched_files(path)
    for f in sorted(listed):
        if not os.path.isfile(os.path.join(path, f)):
            errors.append(f'deps/{d}/PATCHES.md lists {f}, which does not exist')

# 4. Optional: compare with upstream.
def tags_of(repo):
    out = subprocess.run(['git', 'ls-remote', '--tags', '--refs', f'https://github.com/{repo}'],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f'cannot list tags of {repo}: {out.stderr.strip()}')
    return [l.split('refs/tags/', 1)[1] for l in out.stdout.splitlines() if 'refs/tags/' in l]

def version_key(tag):
    nums = [int(x) for x in re.findall(r'\d+', tag)]
    return nums + [0] * (6 - len(nums))

if args == ['--upstream']:
    with tempfile.TemporaryDirectory() as tmp:
        for d, e in sorted(entries.items()):
            path = os.path.join(deps_dir, d)
            clone = os.path.join(tmp, d)
            r = subprocess.run(['git', 'clone', '-q', 'https://github.com/' + e['repo'], clone],
                               capture_output=True, text=True)
            if r.returncode != 0:
                errors.append(f'deps/{d}: cannot clone {e["repo"]}: {r.stderr.strip()}')
                continue
            subprocess.run(['git', '-C', clone, 'checkout', '-q', e['commit']], check=True)
            if e.get('ref_is_tag', True):
                tag_commit = subprocess.run(['git', '-C', clone, 'rev-list', '-n', '1', e['ref']],
                                            capture_output=True, text=True).stdout.strip()
                if tag_commit != e['commit']:
                    errors.append(f'deps/{d}: tag {e["ref"]} is {tag_commit}, manifest says {e["commit"]}')
            want = content_hash(clone, patched_files(path))
            got = content_hash(path, patched_files(path))
            if want != got:
                errors.append(f'deps/{d}: vendored files are not {e["repo"]} {e["ref"]} (apart from PATCHES.md)')
            if e.get('ref_is_tag', True):
                # Only tags in the pinned tag's naming scheme ("v1.2.3", "v0.9.2-1"):
                # nodash also publishes "aztec-v0.62.0" for another toolchain.
                family = re.match(r'^[^0-9]*', e['ref']).group(0)
                tags = [t for t in tags_of(e['repo']) if re.match(re.escape(family) + r'[0-9]', t)]
                newest = max(tags, key=version_key) if tags else None
                if newest and newest != e['newest_reviewed']:
                    errors.append(f'deps/{d}: {e["repo"]} has published {newest}; manifest has reviewed '
                                  f'up to {e["newest_reviewed"]}. Review it, then move `ref` or record `hold`.')
            print(f'checked upstream: deps/{d} = {e["repo"]} {e["ref"]}')

if errors:
    print('Dependency check FAILED:')
    for e in errors:
        print('  - ' + e)
    sys.exit(1)
print(f'Dependency check passed: {len(entries)} vendored libraries, no git dependencies, '
      f'one copy each, contents match deps/MANIFEST.json.')
PY
