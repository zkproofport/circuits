#!/bin/bash
# Gate count and dyadic size of one circuit or probe directory, with the
# pinned toolchain. Deterministic (no timing), so it is safe on a loaded
# machine.
#
#   scripts/measure-gates.sh <dir> [<dir> ...]     e.g. _probes/android-key-attestation/chain-only
#
# Prints, per directory:
#   circuit_size   `bb gates` circuit_size (gates incl. lookup tables)
#   acir_opcodes   `bb gates` acir_opcodes
#   dyadic         2^k, k = the first 32-byte field of `bb write_vk -t evm`'s vk
#                  (log2 of the proving size: 2^20 and 2^21 differ ~2x in
#                  phone memory, and 2^21's .srs is 134 MB, over GitHub's
#                  100 MiB file limit)
# Outputs go to <dir>/target (gitignored for probes); nothing is committed.
set -eu

[ $# -ge 1 ] || { echo "usage: $0 <circuit-dir> [...]" >&2; exit 1; }
CIRCUITS=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
# shellcheck disable=SC1091
. "$CIRCUITS/toolchain.env"
[ "$(bb --version)" = "$BB_VERSION" ] || { echo "bb is $(bb --version), toolchain.env pins $BB_VERSION" >&2; exit 1; }
[ "$(nargo --version | sed -n 's/^nargo version = //p')" = "$NARGO_VERSION" ] || { echo "nargo is not $NARGO_VERSION" >&2; exit 1; }

for arg in "$@"; do
  d=$(cd "$CIRCUITS" && cd "$arg" && pwd)
  [ -f "$d/Nargo.toml" ] || { echo "$arg is not a Noir package" >&2; exit 1; }
  pkg=$(grep -m1 '^name' "$d/Nargo.toml" | sed 's/.*= *"\(.*\)"/\1/')
  (cd "$d" && nargo compile --silence-warnings > "$d/target-compile.log" 2>&1) \
    || { tail -30 "$d/target-compile.log" >&2; echo "$arg: nargo compile failed" >&2; exit 1; }
  rm -f "$d/target-compile.log"
  json="$d/target/$pkg.json"
  [ -s "$json" ] || { echo "$arg: no $json after compile" >&2; exit 1; }
  gates=$(bb gates -b "$json" 2>/dev/null)
  size=$(printf '%s' "$gates" | python3 -c 'import json,sys; d=json.load(sys.stdin)["functions"][0]; print(d["circuit_size"], d["acir_opcodes"])')
  mkdir -p "$d/target/measure-vk"
  bb write_vk -b "$json" -o "$d/target/measure-vk" -t evm > /dev/null 2>&1 \
    || { echo "$arg: bb write_vk failed" >&2; exit 1; }
  k=$(head -c 32 "$d/target/measure-vk/vk" | xxd -p | tr -d '\n' | python3 -c 'import sys; print(int(sys.stdin.read(), 16))')
  read -r cs ops <<< "$size"
  echo "$arg: circuit_size $cs, acir_opcodes $ops, dyadic 2^$k"
done
