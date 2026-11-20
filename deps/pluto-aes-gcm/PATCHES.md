# Changes from pluto/noir-aes-gcm (main, cbd84f6, untagged)

Upstream has no releases and has not changed since 2024-10. Only the zkTLS
proof of concept uses this copy.

## Changed files

- `src/aes.nr`: adds `aes_256` (14 rounds) and `key_expansion_256`, verified
  against the NIST FIPS-197 vectors.
- `src/lib.nr`, `src/gctr.nr`, `src/utils.nr`: modules, `gctr`, `increment_32`
  and the `Stream`/`Block` types made public so the zkTLS circuit can call them.
- `src/ghash.nr`: the box-drawing diagram in a comment rewritten in ASCII,
  because the nargo 1.0.0-beta.8 lexer rejected non-ASCII comments.
