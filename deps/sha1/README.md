# sha1

> [!WARNING]  
> This library has not been reviewed by the Noir team and is unaudited. Use at your own risk.

> [!WARNING]  
> SHA1 is not a secure hash function!  
> Only use if required to support legacy web2 crypto.  
> As of 2017 it is possible to compute SHA1 collisions.  
> See https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html

Library that implements SHA1

## Noir version compatibility

This library is tested against all stable versions of noir from 1.0.0-beta.3.

## Benchmarks

Benchmarks are ignored by `git` and checked on pull-request. As such, benchmarks may be generated
with the following command.

```bash
# execute the following
./scripts/build-gates-report.sh
```

The benchmark will be generated at `./gates_report.json`.

## Installation

In your _Nargo.toml_ file, add the version of this library you would like to install under dependency:

```toml
[dependencies]
sha1= { tag = "v0.1.0", git = "https://github.com/noir-lang/sha1" }
```

