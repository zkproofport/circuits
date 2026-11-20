# zktls_secret_header_libs

Proves that a hidden secret request-header value in a zkTLS session is one well-formed header
value. The value is an Authorization or Cookie value that the TLSNotary verifier never sees.

- **Statement:** `value[0..len]` opens `commitment = SHA-256(value[0..len] || blinder[16])`,
  the format TLSNotary uses for hash commitments, and every byte is HTAB (0x09) or
  0x20..0xFF except DEL (0x7F). CR, LF, NUL and the other control bytes are refused, so the
  value cannot end its header line or add another one.
- **Public input:** `commitment` (32 bytes).
- **Private inputs:** `value` (zero-padded to the tier), `len`, `blinder`.
- **Binding:** the verifier requires one sent commitment covering each hidden range exactly,
  and signs the list into its result. The relying party checks that each proof's commitment
  equals the signed one.

The size tiers are [`../zktls-secret-header-512`](../zktls-secret-header-512) (bearer tokens)
and [`../zktls-secret-header-2k`](../zktls-secret-header-2k) (session cookies).

Tests (`nargo test`), 15:
- accepted: a bearer token, HTAB, bytes 0x80..0xFF, exactly 512 bytes;
- refused: CR, LF, CRLF with an injected header line, NUL, DEL, a wrong blinder, a changed
  byte, a truncated length, length 0, the tier size plus one, another value's commitment.

The vectors in `src/vectors.nr` are fake values with commitments computed outside the circuit.
Removing any one of the four guards (the byte check, the hash check, `len <= N`, `len > 0`)
makes at least one test fail.
