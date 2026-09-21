#!/bin/bash
# Same acceptance run as giwa-attestation: the two circuits share the contract
# (an EIP-712 action or a signal hash, never both) and so share the checks.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts" && pwd)/action-circuit-acceptance.sh" arc-eligibility
