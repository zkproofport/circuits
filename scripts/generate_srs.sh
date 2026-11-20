#!/bin/bash
# Write a circuit's SRS (structured reference string) into its target/.
#
#   ./scripts/generate_srs.sh <circuit-dir>      e.g. coinbase-attestation
#
# The file is the first max(2^k, 512) + 1 G1 points of Aztec's public CRS
# (https://crs.aztec.network/g1.dat) plus the fixed G2 point, in the layout
# noir-rs's LocalSrs reads (bincode of `Srs { g1_data, g2_data, num_points }`)
# -- the noir-rs the phone proves with, NOIR_RS_TAG in toolchain.env.
#
# k is read from the circuit's verification key (target/vk/vk, written by the
# pinned bb at build step 2): its first 32-byte field is log2 of the proving
# size. So the size comes from the bb that defines the circuit, not from a
# second decoder of the bytecode. The floor of 512 is the vendored noir-rs's
# rule (`get_srs_size`, MIN_ZK_SRS_SIZE): bb 6.0.0's ZK prover sizes its
# commitment key to at least 2 * SUBGROUP_SIZE = 512 points however small the
# circuit, and the phone loads get_srs_size + 1 points. No shipped circuit is
# below 2^9, so for all of them this is 2^k + 1.
#
# WHY NOT noir-rs's srs_downloader any more (2026-11-17). It sizes the file by
# decoding the circuit's bytecode with its own copy of Noir, and when it
# cannot decode it, it does not fail: `get_circuit_size` returns 0, the
# subgroup size becomes 1, and it writes a 276-byte file holding two points,
# reporting success. That is what the beta.19 srs_downloader did with every
# circuit compiled by nargo 1.0.0. Deriving k from the vk removes the second
# decoder, and build.sh now also checks the file's point count against the vk.
#
# The layout was checked byte for byte against srs_downloader's output: for
# the committed beta.19-era files (2^19, 2^20, 2^21 circuits) this script
# writes identical bytes. If a later noir-rs changes LocalSrs, change this
# writer and NOIR_RS_TAG together.
#
# Lives in this repository because build.sh needs it and CI checks out this
# repository alone. Needs python3 and curl, and the network.

set -eu

if [ -z "${1:-}" ]; then
    echo "Usage: ./scripts/generate_srs.sh <circuit-dir>   (path under circuits/, e.g. coinbase-attestation)"
    exit 1
fi

CIRCUIT_DIR_NAME="$1"
CIRCUITS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CIRCUIT_DIR="${CIRCUITS_DIR}/${CIRCUIT_DIR_NAME}"
TARGET_DIR="${CIRCUIT_DIR}/target"

echo "=================================================="
echo "SRS generation - ${CIRCUIT_DIR_NAME}"
echo "=================================================="

if [ ! -d "$CIRCUIT_DIR" ]; then
    echo "Error: Circuit directory not found: $CIRCUIT_DIR" >&2
    exit 1
fi

CIRCUIT_JSON=$(find "$TARGET_DIR" -maxdepth 1 -name "*.json" -type f 2>/dev/null | head -1)
if [ -z "$CIRCUIT_JSON" ] || [ ! -f "$TARGET_DIR/vk/vk" ]; then
    echo "Error: $TARGET_DIR needs the compiled .json and vk/vk." >&2
    echo "Build it first: ./scripts/build.sh ${CIRCUIT_DIR_NAME}" >&2
    exit 1
fi
CIRCUIT_NAME=$(basename "$CIRCUIT_JSON" .json)
OUTPUT_SRS="${TARGET_DIR}/${CIRCUIT_NAME}.srs"

# shellcheck disable=SC1091
. "${CIRCUITS_DIR}/toolchain.env"
[ -n "${NOIR_RS_TAG:-}" ] || { echo "Error: NOIR_RS_TAG missing from toolchain.env" >&2; exit 1; }

python3 -I - "$TARGET_DIR/vk/vk" "$OUTPUT_SRS" <<'PY'
import os, struct, subprocess, sys, tempfile

vk_path, out_path = sys.argv[1], sys.argv[2]
vk = open(vk_path, 'rb').read()
if len(vk) < 32:
    sys.exit(f'{vk_path} is {len(vk)} bytes; not a verification key')
k = int.from_bytes(vk[:32], 'big')
if not 1 <= k <= 25:
    sys.exit(f'{vk_path}: first field is {k}, not a log2 circuit size in 1..25. Has the vk layout changed?')
MIN_ZK_SRS_SIZE = 512  # mopro/vendor/noir-rs utils.rs; keep in step with scripts/build.sh
num_points = max(1 << k, MIN_ZK_SRS_SIZE) + 1
g1_len = num_points * 64

# The fixed G2 point noir-rs hardcodes (noir/src/backends/barretenberg/srs/mod.rs, const G2).
G2 = bytes.fromhex(
    '0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0'
    '260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1'
    '22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55'
    '04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4')
assert len(G2) == 128

print(f'circuit size 2^{k} (from the vk): {num_points} G1 points (max(2^k, 512) + 1), {g1_len} bytes from crs.aztec.network')
with tempfile.NamedTemporaryFile(dir=os.path.dirname(out_path), delete=False) as tmp:
    part = tmp.name
try:
    subprocess.run(['curl', '-fsSL', '--retry', '3', '-r', f'0-{g1_len - 1}',
                    '-o', part, 'https://crs.aztec.network/g1.dat'], check=True)
    g1 = open(part, 'rb').read()
finally:
    os.unlink(part)
if len(g1) != g1_len:
    sys.exit(f'downloaded {len(g1)} bytes of G1 data, expected {g1_len}')

# bincode, default config: Vec<u8> = u64 LE length + bytes; u32 LE.
blob = (struct.pack('<Q', len(g1)) + g1 + struct.pack('<Q', len(G2)) + G2
        + struct.pack('<I', num_points))
tmp_out = out_path + '.partial'
with open(tmp_out, 'wb') as f:
    f.write(blob)
os.replace(tmp_out, out_path)
print(f'wrote {out_path}: {len(blob)} bytes')
PY

echo "SRS generation complete: $(wc -c < "$OUTPUT_SRS") bytes (layout of noir-rs ${NOIR_RS_TAG})"
