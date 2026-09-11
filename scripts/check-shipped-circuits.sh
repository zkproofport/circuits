#!/usr/bin/env bash
#
# Every circuit the app downloads must be in the build workflow's loop.
#
# The loop is typed out, and a typed-out list is how arc_eligibility came to be
# built locally, published in the customer SDK's key-path table, and never
# built in CI -- which stayed green while the artefact it publishes did not
# exist. This compares the two.
#
#   ./scripts/check-shipped-circuits.sh
#
# The shipped set is read from the customer SDK rather than repeated here, so a
# circuit added there is covered without anyone remembering to add it twice.
# When the SDK cannot be read this REFUSES rather than passing: a check that
# quietly finds nothing to compare is worse than no check.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"
WORKFLOW="$CIRCUITS_DIR/.github/workflows/build-circuits.yml"
SDK="$CIRCUITS_DIR/../proofport-app-sdk/dist/circuits.js"

if [[ ! -f "$WORKFLOW" ]]; then
  echo "Workflow not found: $WORKFLOW" >&2
  exit 1
fi

if [[ ! -f "$SDK" ]]; then
  echo "Cannot read the shipped circuit list from $SDK" >&2
  echo "  It is the customer SDK's build output, one level above this submodule." >&2
  echo "  Build it:  npm --prefix ../proofport-app-sdk run build" >&2
  echo "  Refusing to guess which circuits ship." >&2
  exit 1
fi

# Paths are absolute so this behaves the same from any working directory --
# an earlier version used a relative require and resolved it against whatever
# directory it happened to be started from.
node -e '
  const [sdkPath, workflowPath] = process.argv.slice(1);
  const fs = require("fs");
  const mod = require(sdkPath);
  const workflow = fs.readFileSync(workflowPath, "utf8");

  const shipped = Object.values(mod.CIRCUIT_VK_PATHS)
    .map((p) => p.replace(/\/target\/vk\/vk$/, ""));

  // A word boundary, not a guessed delimiter. Matching `dir + " "` reported
  // mdl/kr-region missing because it is the LAST item in the loop and is
  // followed by ";" -- the check would have failed CI on a correct workflow.
  const listed = (dir) => {
    const escaped = dir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp("(^|\\s)" + escaped + "(\\s|;|\\\\|$)", "m").test(workflow);
  };

  const missing = shipped.filter((d) => !listed(d));
  if (missing.length) {
    console.error("::error::These circuits ship but are not in the build loop: " + missing.join(", "));
    console.error("Add them to the `for dir in ...` list in " + workflowPath);
    process.exit(1);
  }
  console.log("every shipped circuit is in the build loop: " + shipped.join(", "));
' "$SDK" "$WORKFLOW"
