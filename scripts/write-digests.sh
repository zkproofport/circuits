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
#
# AN ARRAY, NOT A STRING. Written as `'*.json *.srs'` and iterated unquoted,
# the shell expanded the glob in the SCRIPT'S OWN directory before splitting:
# `circuits/` holds package.json and package-lock.json, so the loop ran over
# `package-lock.json package.json *.srs` and the circuits' compiled json was
# never digested. Every manifest ever written covered only the .srs, while the
# header three lines up claimed it covered both -- and the app, finding no
# digest for the json it downloads, fell back to comparing byte counts. That
# fallback is the exact weakness these manifests exist to close. Found
# 2026-09-09, by noticing the trace ran the outer loop three times for two
# patterns.
DOWNLOADED_IN_TARGET=('*.json' '*.srs')
DOWNLOADED_IN_VK=('vk')

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

status=0
wrote=0
missing=0

# The directories the app downloads, from the customer SDK's own key-path
# table. Reading it rather than repeating it means a circuit added there is
# covered here without anyone remembering to add it twice.
SDK_CIRCUITS="../proofport-app-sdk/dist/circuits.js"
if [[ -f "$SDK_CIRCUITS" ]]; then
  SHIPPED_DIRS="$(node -e '
    const c = require(process.argv[1]);
    console.log(Object.values(c.CIRCUIT_VK_PATHS)
      .map(p => p.replace(/\/target\/vk\/vk$/, ""))
      .join(" "));
  ' "$(cd "$(dirname "$SDK_CIRCUITS")" && pwd)/$(basename "$SDK_CIRCUITS")" 2>/dev/null || true)"
fi
if [[ -z "${SHIPPED_DIRS:-}" ]]; then
  echo "Cannot read the shipped circuit list from $SDK_CIRCUITS." >&2
  echo "Build the customer SDK first:  npm --prefix ../proofport-app-sdk run build" >&2
  echo "Refusing to guess which circuits ship." >&2
  exit 1
fi
status=${status:-0}

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

# Both depths, because the Korea mobile ID circuits live one level deeper
# (mdl/kr-ownership, mdl/kr-age, mdl/kr-region). A single-level `*/target` walk
# skipped all three, so those were the only circuits shipping with no published
# digest at all — while proofport-app/src/config/contracts.ts downloads exactly
# them. The app then fell back to comparing byte counts, which is the weakness
# the digests were introduced to close. Found 2026-09-04.
for target in */target */*/target; do
  [[ -d "$target" ]] || continue
  # Retired proof-of-concept circuits are not published and not downloaded by
  # anything, so digesting them would only create manifests that go stale.
  [[ "$target" == _archived-poc/* ]] && continue

  names=()
  for pattern in "${DOWNLOADED_IN_TARGET[@]}"; do
    for f in "$target"/$pattern; do
      [[ -f "$f" ]] && names+=("$(basename "$f")")
    done
  done
  # A SHIPPED circuit that compiled but has no reference string or no verifying
  # key is not deployable, and a manifest written over that gap publishes
  # digests for an incomplete set -- which reads as "verified" to every reader.
  # Refuse.
  #
  # Shipped means the app downloads it, which is decided by the customer SDK's
  # key-path table, not by a list here. An earlier draft required the artefacts
  # of every directory holding a compiled json and failed on coinbase-kyc and
  # zktls -- circuits that exist, are not canonical ids, and no device ever
  # fetches.
  circuit_dir="${target%/target}"
  if [[ " $SHIPPED_DIRS " == *" $circuit_dir "* ]]; then
    stem=''
    for f in "$target"/*.json; do
      [[ -f "$f" ]] && stem="$(basename "$f" .json)" && break
    done
    if [[ ! -f "$target/$stem.srs" ]]; then
      echo "MISSING ARTEFACT  $target/$stem.srs" >&2
      echo "  Generate it:  ./scripts/generate_srs.sh $(dirname "$target")" >&2
      status=1
      missing=$((missing + 1))
      continue
    fi
    if [[ ! -f "$target/vk/vk" ]]; then
      echo "MISSING ARTEFACT  $target/vk/vk" >&2
      echo "  Generate it:  ./scripts/build.sh $(dirname "$target")" >&2
      status=1
      missing=$((missing + 1))
      continue
    fi
  fi

  (( ${#names[@]} )) && emit "$target" "${names[@]}"

  [[ -d "$target/vk" ]] && emit "$target/vk" "${DOWNLOADED_IN_VK[@]}"
done

# A shipped circuit whose manifests were never written is the same failure as a
# missing key: the app finds no digest for the file it just downloaded and
# falls back to comparing byte counts, which passes for a file truncated at
# exactly the right length. --check has to say so, not report "ok" on the
# circuits it happened to look at.
if (( CHECK )); then
  for dir in $SHIPPED_DIRS; do
    for manifest in "$dir/target/SHA256SUMS" "$dir/target/vk/SHA256SUMS"; do
      if [[ ! -f "$manifest" ]]; then
        echo "MISSING MANIFEST  $manifest" >&2
        echo "  Publish it:  ./scripts/write-digests.sh" >&2
        status=1
        missing=$((missing + 1))
      fi
    done
  done
fi

if (( missing )); then
  echo "" >&2
  echo "$missing artefact(s) or manifest(s) are missing." >&2
  echo "Deployment must not proceed: a device that cannot fetch a .srs cannot" >&2
  echo "prove, one that cannot fetch a vk cannot verify what it proved, and one" >&2
  echo "that finds no digest checks the file by BYTE COUNT -- which a file" >&2
  echo "truncated at exactly the right length passes." >&2
  exit 1
fi

if (( CHECK )); then
  (( status == 0 )) && echo "every manifest matches its files"
  exit $status
fi

echo "$wrote manifest(s) written"
