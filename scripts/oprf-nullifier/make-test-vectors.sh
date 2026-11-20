#!/bin/bash
# Regenerate oprf-nullifier-libs/src/test_vectors.nr: the values the library's
# tests check the Noir code against, computed by TACEO's crates in
# scripts/oprf-nullifier (oprf-fixture) with published test values only.
#
#   scripts/oprf-nullifier/make-test-vectors.sh
#
# Inputs (none secret, none fetched):
#   wallet  anvil's well-known account 0, 0xf39f...2266;
#   key     TACEO's oprf-testnet test key 0x1234...abcd (its public key is
#           TACEO's published test vector);
#   other   a second test key (constants.sh), for the wrong-key cases;
#   beta    TACEO's oprf-testnet test beta;
#   domain  keccak256("zkproofport.app") mod p, scope keccak256("oprf-fixture") mod p.
# The Chaum-Pedersen nonces come from --seed 1, so the file regenerates byte
# for byte. With --check it writes nothing and fails when the committed file
# differs from a fresh run.
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="$CIRCUITS/oprf-nullifier-libs/src/test_vectors.nr"
TOOL="$SCRIPT_DIR/target/release/oprf-fixture"

"$SCRIPT_DIR/build-tool.sh"

. "$SCRIPT_DIR/constants.sh"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT
"$TOOL" noir-vectors --address "$FIXTURE_ADDRESS" --domain "$FIXTURE_DOMAIN" --scope "$FIXTURE_SCOPE" \
  --key "$FIXTURE_KEY" --other-key "$FIXTURE_OTHER_KEY" --beta "$FIXTURE_BETA" --seed 1 > "$TMP"

if [ "${1:-}" = "--check" ]; then
  cmp -s "$TMP" "$OUT" || { echo "$OUT differs from what the tool writes now" >&2; diff "$OUT" "$TMP" >&2; exit 1; }
  echo "test vectors up to date"
else
  cp "$TMP" "$OUT"
  echo "wrote $OUT"
fi
