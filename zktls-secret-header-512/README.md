# zktls_secret_header_512

The 512 tier of the secret header value proof: a hidden header value of at most 512 bytes
opens its TLSNotary commitment and holds no control byte. All logic and the tests are
described in [`../zktls-secret-header-libs/README.md`](../zktls-secret-header-libs/README.md).
This package only fixes the size (`TIER = 512`) and runs its own tier tests.

Build: `scripts/build.sh zktls-secret-header-512` (or `/build-circuit zktls-secret-header-512`).
