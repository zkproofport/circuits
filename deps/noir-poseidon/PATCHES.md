# Changes from TaceoLabs/noir-poseidon v0.6.1

v0.6.1 is the tag TaceoLabs/oprf-nr v1.0.0 and v2.0.0 ask for. Only its
`poseidon2` package is compiled by a circuit here (through deps/oprf-nr); the
`poseidon` package is patched so `scripts/test.sh --all` can test it.

## Changed files

- `poseidon/src/bn254.nr`, `poseidon/src/bn254/default_perm.nr`: `use dep::hash_utils`
  becomes `use hash_utils`. nargo 1.0.0 removed the `dep::` prefix ("Could not
  resolve 'dep' in path"); with the change its 15 tests pass.
