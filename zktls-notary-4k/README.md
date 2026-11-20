# zktls_notary_4k

The 4k size tier of the zkTLS claim circuit. It proves a schema-defined claim
over a TLSNotary-committed prefix of a JSON response body of at most 4096 bytes:
the whole body when it fits, otherwise exactly its first 4096 bytes.

All logic, the commitment format, the inputs and the tests are described in
[`../zktls-notary-libs/README.md`](../zktls-notary-libs/README.md). This
package only fixes the size (`TIER = 4096` in `src/main.nr`) and runs its own
tier tests (`src/tests.nr`).

Build: `scripts/build.sh zktls-notary-4k` (or `/build-circuit zktls-notary-4k`).
