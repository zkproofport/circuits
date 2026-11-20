#!/bin/bash
# Each probe must return exactly the plaintext node:crypto encrypted, and the
# GCM and fields probes must refuse a tag with one bit flipped. Run make-vectors.mjs and make-fields-vector.mjs first.
set -u
cd "$(dirname "$0")"
fail=0
for d in ctr-* gcm-* fields; do
  out=$(cd "$d" && nargo execute 2>&1) || { echo "$d: execute failed"; echo "$out" | tail -3; fail=1; continue; }
  got=$(printf '%s\n' "$out" | sed -n 's/.*Circuit output: //p')
  if python3 - "$got" "$d/expected.json" <<'PY'
import json, sys
got = [int(x, 16) for x in sys.argv[1].strip('[]').split(', ')]
exp = [int(x) for x in json.load(open(sys.argv[2]))]
sys.exit(0 if got == exp else 1)
PY
  then echo "$d: plaintext matches"; else echo "$d: PLAINTEXT DIFFERS"; fail=1; fi
  if [ -f "$d/Prover_badtag.toml" ]; then
    if (cd "$d" && nargo execute -p Prover_badtag > /dev/null 2>&1); then
      echo "$d: ACCEPTED A WRONG TAG"; fail=1
    else echo "$d: wrong tag refused"; fi
  fi
done
exit $fail
