#!/bin/bash
# The acceptance run lives with the other scripts, under circuits/scripts/, and
# is shared with arc-eligibility. This file exists only because
# scripts/build.sh looks for a hook at exactly <circuit>/scripts/post-build.sh.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts" && pwd)/action-circuit-acceptance.sh" giwa-attestation
