# zktls_notary_2k

The 2k size tier of the zkTLS claim circuit. It proves a schema-defined claim
over a TLSNotary-committed prefix of a JSON response body of at most 2048 bytes:
the whole body when it fits, otherwise exactly its first 2048 bytes.

All logic, the commitment format, the inputs and the tests are described in
[`../zktls-notary-libs/README.md`](../zktls-notary-libs/README.md). This
package only fixes the size (`TIER = 2048` in `src/main.nr`) and runs its own
tier tests (`src/tests.nr`).

Build: `scripts/build.sh zktls-notary-2k` (or `/build-circuit zktls-notary-2k`).
