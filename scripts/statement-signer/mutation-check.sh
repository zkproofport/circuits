#!/bin/bash
# Prove that a refusal in an acceptance run is caused by the code it names,
# for a circuit that verifies statements through ../statement-signer.
#
#   scripts/statement-signer/mutation-check.sh <circuit-dir> <cases-file> [fixture-regex]
#
# Used by scripts/coinbase-attestation-v2/mutation-check.sh,
# oidc-domain-attestation/scripts/mutation-check.sh and
# scripts/android-key-attestation/mutation-check.sh, which hold the cases.
# Runs against <circuit-dir>-synthetic-anchors and its fixtures
# (scripts/statement-signer/make-synthetic-anchors.sh, then the circuit's
# fixture generator).
#
# For each case: copy the synthetic-anchors circuit, the synthetic-anchors
# statement-signer library, the App Attest library and the Android key
# attestation library to sibling `-mutant` directories (so ../deps still
# resolves), point each at the next copy, apply ONE mutation to any of the four, and run the named refusal fixture. The
# mutant must ACCEPT it -- otherwise something else was doing the refusing and
# the acceptance case proves nothing about that code.
#
# Cases file, one per line (blank lines and lines starting with # skipped):
#   delete~<assert message>~<fixture>          delete the one line carrying the message
#                                              (single-line asserts only)
#   replace~<exact text>~<new text>~<fixture>  replace text occurring exactly once
# The separator is `~` because the texts contain Noir's `|` (boolean or). With
# `|` as the separator, five coinbase cases split in the wrong places and
# compiled broken mutants that "still refused" for the wrong reason (found
# 2026-10-28). The originals are never edited; the copies are removed on exit.
set -u

[ $# -ge 2 ] || { echo "usage: $0 <circuit-dir> <cases-file> [fixture-regex]" >&2; exit 1; }
CIRCUITS=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
NAME="$1"
CASES_FILE="$2"
ONLY="${3:-}"
SYN="$CIRCUITS/$NAME-synthetic-anchors"
SYN_SIGNER="$CIRCUITS/statement-signer-synthetic-anchors"
MUTANT="$CIRCUITS/$NAME-mutant"
MUTANT_SIGNER="$CIRCUITS/statement-signer-mutant"
MUTANT_LIB="$CIRCUITS/app-attest-libs-mutant"
MUTANT_ANDROID="$CIRCUITS/android-key-attestation-mutant"
MUTANT_PLAY="$CIRCUITS/play-integrity-mutant"

[ -d "$SYN/test-vectors" ] && [ -d "$SYN_SIGNER/src" ] \
  || { echo "$NAME-synthetic-anchors or its fixtures are missing: run the circuit's fixture script" >&2; exit 1; }
[ -f "$CASES_FILE" ] || { echo "$CASES_FILE missing" >&2; exit 1; }
for d in "$MUTANT" "$MUTANT_SIGNER" "$MUTANT_LIB" "$MUTANT_ANDROID" "$MUTANT_PLAY"; do
  [ ! -e "$d" ] || { echo "$d exists; remove it (a previous run was interrupted)" >&2; exit 1; }
done
trap 'rm -rf "$MUTANT" "$MUTANT_SIGNER" "$MUTANT_LIB" "$MUTANT_ANDROID" "$MUTANT_PLAY" "$CIRCUITS/oidc-libs-mutant" "$CIRCUITS/coinbase-v2-libs-mutant"' EXIT

repoint() { # file from to
  sed -i.bak "s#\"$2\"#\"$3\"#" "$1" && rm -f "$1.bak"
  grep -q "\"$3\"" "$1" || { echo "could not point $1 at $3" >&2; exit 1; }
}

PASSED=0
FAILED=0
while IFS= read -r c || [ -n "$c" ]; do
  case "$c" in ''|'#'*) continue ;; esac
  IFS='~' read -r kind a b d <<< "$c"
  if [ "$kind" = delete ]; then msg="$a"; vector="$b"; label="without \"$msg\""
  elif [ "$kind" = replace ]; then from="$a"; to="$b"; vector="$d"; label="with \"$(echo "$from" | sed 's/^ *//')\" -> \"$(echo "$to" | sed 's/^ *//')\""
  else echo "  FAILED   unknown case kind '$kind' in: $c"; FAILED=$((FAILED + 1)); continue; fi
  if [ -n "$ONLY" ] && ! echo "$vector" | grep -Eq "$ONLY"; then continue; fi
  [ -f "$SYN/test-vectors/$vector.toml" ] || { echo "  FAILED   fixture $vector.toml missing"; FAILED=$((FAILED + 1)); continue; }

  rm -rf "$MUTANT" "$MUTANT_SIGNER" "$MUTANT_LIB" "$MUTANT_ANDROID" "$MUTANT_PLAY"
  mkdir -p "$MUTANT" "$MUTANT_SIGNER" "$MUTANT_LIB" "$MUTANT_ANDROID" "$MUTANT_PLAY"
  cp -R "$SYN/Nargo.toml" "$SYN/src" "$SYN/test-vectors" "$MUTANT/"
  cp -R "$SYN_SIGNER/Nargo.toml" "$SYN_SIGNER/src" "$MUTANT_SIGNER/"
  cp -R "$CIRCUITS/app-attest-libs/Nargo.toml" "$CIRCUITS/app-attest-libs/src" "$MUTANT_LIB/"
  cp -R "$CIRCUITS/android-key-attestation/Nargo.toml" "$CIRCUITS/android-key-attestation/src" "$MUTANT_ANDROID/"
  repoint "$MUTANT/Nargo.toml" ../statement-signer-synthetic-anchors ../statement-signer-mutant
  repoint "$MUTANT_SIGNER/Nargo.toml" ../app-attest-libs ../app-attest-libs-mutant
  repoint "$MUTANT_SIGNER/Nargo.toml" ../android-key-attestation ../android-key-attestation-mutant
  repoint "$MUTANT_ANDROID/Nargo.toml" ../app-attest-libs ../app-attest-libs-mutant
  cp -R "$CIRCUITS/play-integrity/Nargo.toml" "$CIRCUITS/play-integrity/src" "$MUTANT_PLAY/"
  repoint "$MUTANT_SIGNER/Nargo.toml" ../play-integrity ../play-integrity-mutant
  SRCS=("$MUTANT/src" "$MUTANT_SIGNER/src" "$MUTANT_LIB/src" "$MUTANT_ANDROID/src" "$MUTANT_PLAY/src")
  # The circuit's own shared library (the token / Coinbase checks moved out of
  # main.nr so each circuit id's packages share them): copied and repointed
  # too, so its asserts can be mutated like the rest.
  for shared in oidc-libs coinbase-v2-libs; do
    if grep -q "\"../$shared\"" "$MUTANT/Nargo.toml"; then
      rm -rf "$CIRCUITS/$shared-mutant"
      mkdir -p "$CIRCUITS/$shared-mutant"
      cp -R "$CIRCUITS/$shared/Nargo.toml" "$CIRCUITS/$shared/src" "$CIRCUITS/$shared-mutant/"
      repoint "$MUTANT/Nargo.toml" "../$shared" "../$shared-mutant"
      SRCS+=("$CIRCUITS/$shared-mutant/src")
    fi
  done

  if [ "$kind" = delete ]; then
    # Exactly one line may carry the message, and exactly one line must go.
    count=$(grep -rcF "\"$msg\"" "${SRCS[@]}" | awk -F: '{s+=$2} END {print s}')
    if [ "$count" != 1 ]; then
      echo "  FAILED   $msg: found on $count lines, need exactly 1"; FAILED=$((FAILED + 1)); continue
    fi
    hits=$(grep -rlF "\"$msg\"" "${SRCS[@]}")
    if ! grep -F "\"$msg\"" "$hits" | grep -q "assert("; then
      echo "  FAILED   $msg: not a single-line assert; use replace"; FAILED=$((FAILED + 1)); continue
    fi
    before=$(wc -l < "$hits")
    grep -vF "\"$msg\"" "$hits" > "$hits.new" && mv "$hits.new" "$hits"
    after=$(wc -l < "$hits")
    if [ $((before - after)) != 1 ]; then
      echo "  FAILED   $msg: the deletion removed $((before - after)) lines"; FAILED=$((FAILED + 1)); continue
    fi
  else
    count=$(grep -rcF -- "$from" "${SRCS[@]}" | awk -F: '{s+=$2} END {print s}')
    if [ "$count" != 1 ]; then
      echo "  FAILED   \"$from\": found on $count lines, need exactly 1"; FAILED=$((FAILED + 1)); continue
    fi
    hits=$(grep -rlF -- "$from" "${SRCS[@]}")
    FROM="$from" TO="$to" python3 -I -c 'import os,sys; p=sys.argv[1]; s=open(p).read(); n=s.replace(os.environ["FROM"], os.environ["TO"]); assert n != s; open(p,"w").write(n)' "$hits" \
      || { echo "  FAILED   could not apply the replacement"; FAILED=$((FAILED + 1)); continue; }
  fi

  if (cd "$MUTANT" && nargo execute w --prover-name "test-vectors/$vector" > "$MUTANT/run.log" 2>&1); then
    echo "  ok       $label, $vector is ACCEPTED -- that code is what refuses it"
    PASSED=$((PASSED + 1))
  else
    echo "  FAILED   $label, $vector is still refused:"
    grep -m1 "Assertion failed\|error\|Failed" "$MUTANT/run.log" | sed 's/^/           /'
    FAILED=$((FAILED + 1))
  fi
done < "$CASES_FILE"

echo ""
echo "  $PASSED caught, $FAILED not"
[ "$PASSED" -gt 0 ] || { echo "  no case ran" >&2; exit 1; }
exit $([ "$FAILED" -eq 0 ] && echo 0 || echo 1)
