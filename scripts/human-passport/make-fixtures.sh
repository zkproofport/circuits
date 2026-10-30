#!/bin/bash
# Every human_passport_score fixture, from one real Human Passport issuance on
# Base. Needs network (Base RPC: BASE_RPC_URL, else circuits/.env.production)
# and nothing secret: the only keys involved are insecure test keys derived from
# public strings in generate-fixtures.js.
#
#   scripts/human-passport/make-fixtures.sh [<verifyAndAttest tx hash>]
#
# The default tx is RECORDED_TX in generate-fixtures.js.
set -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec node "$SCRIPT_DIR/generate-fixtures.js" "$@"
