#!/usr/bin/env bash
#
# Publish the SHA-256 of every file the app downloads.
#
# The app already verifies each downloaded circuit file against a published
# digest — but when no digest is published it falls back to comparing the byte
# count, and says so in its log rather than pretending. Until this script ran,
# nothing was ever published, so every install on every device took the
# fallback: a file that arrived truncated at exactly the right length, or was
# swapped at the CDN, passed.
#
# WHERE THE FILES GO, AND WHY IT IS ONE PER DIRECTORY
#
# The app derives the manifest URL from the file it is about to fetch: it takes
# the file's own directory and asks for SHA256SUMS there. The verifying key sits
# one level deeper than the circuit and its reference string, so each circuit
# needs two:
#
#   <circuit>/target/SHA256SUMS      covers <name>.json and <name>.srs
#   <circuit>/target/vk/SHA256SUMS   covers vk
#
# Keys are BARE FILE NAMES, matching the lookup — no leading ./ and no path.
#
# Run this after any rebuild that changes an artefact, and commit the result in
# the SAME commit as the artefact. A manifest that lags its files is worse than
# no manifest: every install fails verification and the cause looks like a
# corrupt download.
#
# Usage:  scripts/write-digests.sh [--check]
#           --check  recompute and diff instead of writing; exits non-zero when
#                    a manifest is missing or stale. For CI.

set -euo pipefail

cd "$(dirname "$0")/.."

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

# Only what the app actually downloads. Solidity sources, proofs and vk_hash
# are not fetched by the app, so digesting them would invite a stale-manifest
# failure for a file no device ever reads.
DOWNLOADED_IN_TARGET='*.json *.srs'
DOWNLOADED_IN_VK='vk'

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

status=0
wrote=0

emit() {
  local dir="$1"; shift
  local names=("$@")

  local body=''
  for name in "${names[@]}"; do
    [[ -f "$dir/$name" ]] || continue
    body+="$(sha256_of "$dir/$name")  $name"$'\n'
  done

  # A directory with none of the downloaded files has nothing to vouch for.
  if [[ -z "$body" ]]; then
    return
  fi

  local out="$dir/SHA256SUMS"
  if (( CHECK )); then
    if [[ ! -f "$out" ]]; then
      echo "MISSING  $out"
      status=1
    elif ! diff -q <(printf '%s' "$body") "$out" >/dev/null; then
      echo "STALE    $out"
      diff <(printf '%s' "$body") "$out" || true
      status=1
    else
      echo "ok       $out"
    fi
  else
    printf '%s' "$body" > "$out"
    echo "wrote    $out"
    wrote=$((wrote + 1))
  fi
}

for target in */target; do
  [[ -d "$target" ]] || continue

  names=()
  for pattern in $DOWNLOADED_IN_TARGET; do
    for f in "$target"/$pattern; do
      [[ -f "$f" ]] && names+=("$(basename "$f")")
    done
  done
  (( ${#names[@]} )) && emit "$target" "${names[@]}"

  [[ -d "$target/vk" ]] && emit "$target/vk" $DOWNLOADED_IN_VK
done

if (( CHECK )); then
  (( status == 0 )) && echo "every manifest matches its files"
  exit $status
fi

echo "$wrote manifest(s) written"
