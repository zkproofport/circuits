#!/bin/bash
# Measure coinbase_country_attestation v2 (all three packages) beside
# coinbase_attestation v2 and Country v1, with the pinned toolchain.
#
#   scripts/coinbase-country-attestation-v2/measure.sh [runs]     (default 3)
#
# Needs, first, each package built with its acceptance run (the witnesses
# proved here are the ones those runs leave):
#   scripts/build.sh coinbase-country-attestation-v2
#   scripts/build.sh coinbase-country-attestation-v2-android
#   scripts/build.sh coinbase-country-attestation-v2-android-factory
#
# Prints `bb gates` (deterministic) for each, then `bb prove -t evm` wall time
# and peak RSS (macOS /usr/bin/time -l) per run for:
#   standard, server kind    the REAL circuit (test server key pinned)
#   standard, app kind       the synthetic-anchors copy (only anchors differ)
#   android, android_factory the synthetic-anchors copies
# Timings depend on the machine's load; quote them with `uptime`.
set -eu

RUNS=${1:-3}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck disable=SC1091
. "$CIRCUITS/toolchain.env"
[ "$(bb --version)" = "$BB_VERSION" ] || { echo "bb is $(bb --version), toolchain.env pins $BB_VERSION" >&2; exit 1; }
[ "$(nargo --version | sed -n 's/^nargo version = //p')" = "$NARGO_VERSION" ] || { echo "nargo is not $NARGO_VERSION" >&2; exit 1; }

gates() { bb gates -b "$1" 2>/dev/null | sed -n 's/.*"circuit_size": *\([0-9]*\).*/\1/p' | head -1; }
opcodes() { bb gates -b "$1" 2>/dev/null | sed -n 's/.*"acir_opcodes": *\([0-9]*\).*/\1/p' | head -1; }
row() { printf '  %-52s %12s %12s\n' "$1" "$(gates "$2")" "$(opcodes "$2")"; }

echo "uptime: $(uptime)"
echo ""
echo "bb gates ($BB_VERSION, nargo $NARGO_VERSION)"
printf '  %-52s %12s %12s\n' "circuit" "circuit_size" "acir_opcodes"
row "coinbase_country_attestation v1" "$CIRCUITS/coinbase-country-attestation/target/coinbase_country_attestation.json"
for p in coinbase-attestation-v2 coinbase-attestation-v2-android coinbase-attestation-v2-android-factory \
         coinbase-country-attestation-v2 coinbase-country-attestation-v2-android coinbase-country-attestation-v2-android-factory; do
  pkg=$(grep -m1 '^name' "$CIRCUITS/$p/Nargo.toml" | sed 's/.*= *"\(.*\)"/\1/')
  row "$pkg" "$CIRCUITS/$p/target/$pkg.json"
done

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
prove() {
  local label="$1" dir="$2" witness="$3"
  local pkg json vk
  pkg=$(grep -m1 '^name' "$dir/Nargo.toml" | sed 's/.*= *"\(.*\)"/\1/')
  json="$dir/target/$pkg.json"; vk="$dir/target/vk/vk"
  [ -f "$dir/target/$witness.gz" ] || { echo "$dir/target/$witness.gz missing: run its build (acceptance run) first" >&2; exit 1; }
  echo ""
  echo "bb prove -t evm: $label ($RUNS runs)"
  for i in $(seq 1 "$RUNS"); do
    mkdir -p "$OUT/$label"
    /usr/bin/time -l bb prove -b "$json" -w "$dir/target/$witness.gz" -k "$vk" -o "$OUT/$label" -t evm > "$OUT/$label.log" 2>&1 \
      || { echo "  prove failed:"; tail -5 "$OUT/$label.log"; exit 1; }
    printf '  run %d: %6s s  peak RSS %s GiB\n' "$i" \
      "$(awk '/ real /{print $1}' "$OUT/$label.log" | tail -1)" \
      "$(awk '/maximum resident set size/{printf "%.2f", $1/1024/1024/1024}' "$OUT/$label.log")"
  done
  bb verify -p "$OUT/$label/proof" -i "$OUT/$label/public_inputs" -k "$vk" -t evm > /dev/null 2>&1 \
    && echo "  verified" || { echo "  bb verify FAILED"; exit 1; }
  echo "  proof $(wc -c < "$OUT/$label/proof" | tr -d ' ') bytes, public inputs $(wc -c < "$OUT/$label/public_inputs" | tr -d ' ') bytes, vk log size $(od -An -tu1 -j31 -N1 "$vk" | tr -d ' ')"
}
prove standard_server_real "$CIRCUITS/coinbase-country-attestation-v2" witness_real_server_action
prove standard_app_synthetic "$CIRCUITS/coinbase-country-attestation-v2-synthetic-anchors" witness_action
prove android_synthetic "$CIRCUITS/coinbase-country-attestation-v2-android-synthetic-anchors" witness_action
prove android_factory_synthetic "$CIRCUITS/coinbase-country-attestation-v2-android-factory-synthetic-anchors" witness_action
