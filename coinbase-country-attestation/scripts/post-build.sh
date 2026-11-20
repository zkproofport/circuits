#!/bin/bash
# scripts/build.sh runs a hook at exactly <circuit>/scripts/post-build.sh; the
# acceptance run (fixture conversion for the OPRF nullifier, refusals, proof)
# lives with the OPRF nullifier's scripts.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts/oprf-nullifier" && pwd)/v1-acceptance.sh" coinbase-country-attestation
