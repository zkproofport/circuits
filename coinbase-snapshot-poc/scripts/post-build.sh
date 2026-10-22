#!/bin/bash
# scripts/build.sh looks for a hook at exactly <circuit>/scripts/post-build.sh;
# the acceptance run itself is shared under circuits/scripts/.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts" && pwd)/action-circuit-acceptance.sh" coinbase-snapshot-poc
