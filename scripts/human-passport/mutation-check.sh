#!/bin/bash
# Mutation check for human_passport_score: delete one guard at a time and show
# that the acceptance case written for it is then ACCEPTED. A refusal case that
# still fails with the guard gone is refused for some other reason, and was
# never testing that guard.
#
#   scripts/human-passport/mutation-check.sh            # all mutations
#   scripts/human-passport/mutation-check.sh <regex>    # those whose name matches
#
# Needs the fixtures (run scripts/build.sh human-passport-score first).
# Works on a throwaway copy under human-passport-mutant/ (gitignored).
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MUT="$CIRCUITS_ROOT/human-passport-mutant"
FILTER="${1:-.}"

# name | file under human-passport-libs/src | exact guard line | case that must now be accepted
MUTATIONS=$(cat <<'M'
score_threshold|issuer.nr|    assert(head.score >= min_score, "Score below threshold");|below_threshold
expiry|issuer.nr|    assert(now < req.expiration_time, "Attestation expired");|expired_at_boundary
issuer_list|issuer.nr|    assert(root == signer_list_merkle_root, "Issuer not in valid list");|wrong_attester_key
issuer_signature|issuer.nr|    assert(valid, "Invalid issuer signature");|tampered_score
scorer_id|issuer.nr|    assert(head.scorer_id == scorer_id, "Scorer id mismatch");|wrong_scorer_id
decimals|score_data.nr|    assert(decimals == SCORE_DECIMALS as Field, "score data: decimals is not 4");|other_decimals
score_padding|score_data.nr|    assert(clean, "score data: score has non-zero padding");|dirty_score_padding
M
)

PASSED=0; FAILED=0
while IFS='|' read -r name file line case; do
  [ -n "$name" ] || continue
  echo "$name" | grep -qE "$FILTER" || continue
  rm -rf "$MUT" && mkdir -p "$MUT"
  cp -R "$CIRCUITS_ROOT/human-passport-libs" "$MUT/libs"
  cp -R "$CIRCUITS_ROOT/human-passport-score" "$MUT/circuit"
  rm -rf "$MUT/circuit/target"
  sed -i.bak "s#path = \"../#path = \"$CIRCUITS_ROOT/#; s#path = \"$CIRCUITS_ROOT/human-passport-libs\"#path = \"../libs\"#" "$MUT/circuit/Nargo.toml"
  sed -i.bak "s#path = \"../#path = \"$CIRCUITS_ROOT/#" "$MUT/libs/Nargo.toml"
  # Replace the guard with nothing, and prove the file actually changed:
  # a mutation that matched no line would "survive" for the wrong reason.
  if ! python3 -I - "$MUT/libs/src/$file" "$line" <<'PY'
import sys
p, line = sys.argv[1], sys.argv[2]
s = open(p).read()
n = s.count(line + "\n")
if n != 1:
    sys.exit(f"guard line found {n} times in {p}")
open(p, "w").write(s.replace(line + "\n", "", 1))
PY
  then echo "  FAILED   $name  (could not apply the mutation)"; FAILED=$((FAILED + 1)); continue; fi
  if (cd "$MUT/circuit" && nargo execute w --prover-name "test-vectors/$case") > "$MUT/run.log" 2>&1; then
    echo "  ok       $name  -> $case is accepted without the guard"; PASSED=$((PASSED + 1))
  else
    echo "  FAILED   $name  -> $case still refused without the guard:"
    grep -m2 -E 'error|Failed' "$MUT/run.log" | sed 's/^/           /'
    FAILED=$((FAILED + 1))
  fi
done <<< "$MUTATIONS"
rm -rf "$MUT"
echo ""
echo "  $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
