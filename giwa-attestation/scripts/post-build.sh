#!/bin/bash
# The acceptance run lives with the other scripts, under circuits/scripts/, so
# any circuit with the same signing branch can share it. This file exists only because
# scripts/build.sh looks for a hook at exactly <circuit>/scripts/post-build.sh.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts" && pwd)/action-circuit-acceptance.sh" giwa-attestation
