# zktls_secret_header_2k

The 2k tier of the secret header value proof: a hidden header value of at most 2048 bytes
opens its TLSNotary commitment and holds no control byte. All logic and the tests are
described in [`../zktls-secret-header-libs/README.md`](../zktls-secret-header-libs/README.md).
This package only fixes the size (`TIER = 2048`) and runs its own tier tests.

Build: `scripts/build.sh zktls-secret-header-2k` (or `/build-circuit zktls-secret-header-2k`).
