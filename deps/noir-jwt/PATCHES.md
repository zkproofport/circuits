# Changes from zkemail/noir-jwt v0.5.1

v0.5.1 is the newest release. It was written against sha256 v0.2.1 and
noir-bignum v0.8.0; this copy is compiled against the versions in
deps/MANIFEST.json.

## Changed files

- `src/lib.nr`:
  - `sha256_var` takes the length as `u32` from sha256 v0.3.0 on, so the
    `as u64` cast on that one call is removed. The partial-hash call uses this
    library's own `partial_hash.nr`, which still takes `u64`, and is unchanged.
  - The test vectors' `redc_params_limbs` are recomputed for noir-bignum >= 0.9.
    From that version on the Barrett parameter is `floor(2^(2*MOD_BITS + 6) / n)`;
    before, it was `+ 4` (noir-lang/noir-bignum PR #241). With the old values
    every test failed in `__barrett_reduction` (`assert(__is_zero(remainder))`).
  - `prepare_haystack` zeroes the bytes past the payload before base64
    decoding. It rotated the whole buffer and relied on
    `BoundedVec::from_parts` to zero the tail; nargo 1.0.0 no longer does
    (noir-lang/noir #11679), and noir_base64's `decode_var` refuses any
    non-zero byte past the length, so every claim test failed with
    "DecodeError: invalid symbol". The live circuits do not call this
    function (`oidc-libs` decodes the payload itself).
