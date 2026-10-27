#!/bin/bash
# scripts/build.sh runs a hook at exactly <circuit>/scripts/post-build.sh; the
# acceptance run itself lives with the fixture generator.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts/human-passport" && pwd)/acceptance.sh"
