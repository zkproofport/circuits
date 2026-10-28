# Privacy-Preserving Credential Circuits

Open-source Noir reference implementations and EVM verifiers for privacy-preserving credential [CIPs](https://github.com/zkproofport/CIPs).

This repository contains executable circuit code, shared Noir libraries, generated verifier contracts, scripts, and deployment records. Normative statement semantics, trust assumptions, privacy boundaries, and conformance requirements are documented separately in the CIPs repository.

## CIP mapping and maturity

| CIP | Specification | Reference path | Implementation maturity |
|---|---|---|---|
| CIP-1 | [Coinbase KYC Attestation](https://github.com/zkproofport/CIPs/blob/main/CIPS/cip-1.md) | [`coinbase-attestation`](coinbase-attestation) | Reference |
| CIP-2 | [Coinbase Country Predicate](https://github.com/zkproofport/CIPs/blob/main/CIPS/cip-2.md) | [`coinbase-country-attestation`](coinbase-country-attestation) | Reference |
| CIP-3 | [OIDC Domain Attestation](https://github.com/zkproofport/CIPs/blob/main/CIPS/cip-3.md) | [`oidc-domain-attestation`](oidc-domain-attestation) | Reference |
| CIP-4 | [GIWA Dojang Verified Address Proof](https://github.com/zkproofport/CIPs/blob/main/CIPS/cip-4.md) | [`giwa-attestation`](giwa-attestation) | PoC |
| CIP-5 | [Korean Mobile ID Selective Disclosure Profile](https://github.com/zkproofport/CIPs/blob/main/CIPS/cip-5.md) | [`mdl/kr-*`](mdl) | Beta |

[`dojang-playground`](dojang-playground) is a GIWA Sepolia demo circuit outside the CIP mapping.

[`coinbase-attestation-v2`](coinbase-attestation-v2) is the next version of CIP-1's circuit, in development on a branch: revocation bound by an Apple App Attest or AI-server statement, an optional EIP-712 action, and a wallet nullifier. Its README has the statement format and measurements. It is not deployed to a mainnet.

`coinbase-libs` is a shared implementation library. `coinbase-kyc` is an older reference-only circuit. `_archived-poc` and `zktls` are outside the current credential CIP mapping.

## Implemented circuits

### Coinbase KYC attestation — Reference

Proves control of an address named by a signed Coinbase `attestAccount(address)` transaction while keeping the address, transaction, and signatures private. The circuit verifies user ownership, EIP-1559 transaction structure and signature, signer membership in a public Merkle root, target calldata, and a signal- and scope-bound nullifier.

### Coinbase country predicate — Reference

Extends the Coinbase transaction profile with a private two-byte country code and a public inclusion or exclusion list of up to ten ISO 3166-1 alpha-2 values.

### OIDC domain attestation — Reference

Verifies a Google Workspace or Microsoft 365 OIDC JWT with RSA-2048 and proves that its private email ends in a public domain. It exposes a provider identifier and an email-derived scope-bound nullifier.

v2 (214 public inputs) also checks the provider's issuer in-circuit and binds the token's audience (`aud_hash`), validity window (`iat <= now < exp`) and, on the app path, a request nonce (`nonce_binding`). The verifier still decides which provider keys, client ids and `now` values to accept; see [`oidc-domain-attestation/README.md`](oidc-domain-attestation/README.md). The verifier addresses below were deployed from v1 (148 public inputs) and do not verify v2 proofs.

### GIWA attestation — PoC

GIWA Sepolia proof flow using a test `MockGiwaAttester`, mobile-compatible UltraHonk proof generation, and an EVM verifier.

### Dojang Playground — Demo

Proves that a wallet signed the request and that the same key signed a GIWA Sepolia `payAndIssueEAS()` call to the Playground faucet (`0x63CCe2b569A7bC35895ee24306c1512fefc06121`), the call that issues a Dojang attestation to its sender. Legacy (EIP-155) and EIP-1559 transactions are both accepted. The issuance is self-signed, so there is no issuer check and no inclusion check; the circuit demonstrates the flow.

### Korean Mobile ID predicates — Beta

Three circuits under `mdl/` implement ownership/selective field commitment, year-based age threshold, and region-token predicates. They share `keccak256(keccak256(ci) || scope)` nullifiers.

ZKProofport is registered with the Ministry of the Interior and Safety as a Korea Mobile ID integration service (모바일 신분증 연계서비스).

## Shared nullifier schemes

### Coinbase transaction profiles

```text
user_secret = keccak256(user_address || signal_hash)
nullifier   = keccak256(user_secret || scope)
```

Duplicate-detection behavior depends on both `signal_hash` and `scope` remaining stable for the relevant action.

### GIWA and Dojang Playground

```text
user_secret = keccak256(user_address || keccak256(circuit_name))
nullifier   = keccak256(user_secret || scope)
```

The circuit name is compiled in, so one wallet has one nullifier per scope and per circuit.

### OIDC domain profile

```text
nullifier = keccak256(keccak256(email) || scope)
```

### Korean Mobile ID profile

```text
nullifier = keccak256(keccak256(ci) || scope)
```

Nullifier storage is application-specific. `NullifierRegistry` and `ZKProofportNullifierRegistry` are deprecated and are retained only as historical source references.

## Building

The current generated artifacts were built with:

- `nargo 1.0.0-beta.19`
- `bb 4.2.0-aztecnr-rc.2`

Both are pinned in [`toolchain.env`](toolchain.env); install them with `./scripts/install-toolchain.sh`.

```bash
./scripts/build.sh coinbase-attestation
./scripts/build.sh coinbase-country-attestation
./scripts/build.sh oidc-domain-attestation
./scripts/build.sh giwa-attestation
./scripts/build.sh dojang-playground
./scripts/build.sh mdl/kr-ownership
./scripts/build.sh mdl/kr-age
./scripts/build.sh mdl/kr-region
```

Generated Solidity verifiers expose the common interface:

```solidity
function verify(bytes calldata proof, bytes32[] calldata publicInputs)
    external
    view
    returns (bool);
```

See each pinned CIP for semantic public-input ordering and conformance requirements.

## Reference deployments

The tables below are generated by `scripts/readme-deployments.py` from `broadcast/**/run-latest.json` at revision [`a8de9ceb223b7fb6d8ef5dfef99a05f3ecd866f1`](https://github.com/zkproofport/circuits/commit/a8de9ceb223b7fb6d8ef5dfef99a05f3ecd866f1).

### Ethereum Sepolia — chain ID 11155111

| Circuit | Verifier | Deployment record |
|---|---|---|
| Coinbase KYC | `0x7fc2059a73cef2b572c8deee911c72963dcb4a8a` | [`DeployCoinbaseAttestation`](broadcast/DeployCoinbaseAttestation.s.sol/11155111/run-latest.json) |
| Coinbase Country | `0x0b3af3dfc67dc65e0145c37ee00230139d579f64` | [`DeployCoinbaseCountryAttestation`](broadcast/DeployCoinbaseCountryAttestation.s.sol/11155111/run-latest.json) |
| OIDC Domain | `0x8e8f481d98149f13fb756cab69376814fa854180` | [`DeployOidcDomainAttestation`](broadcast/DeployOidcDomainAttestation.s.sol/11155111/run-latest.json) |

### Base Sepolia — chain ID 84532

| Circuit | Verifier | Deployment record |
|---|---|---|
| Coinbase KYC | `0x42d165a48256ae184e1de4e7e6372e870e2bc883` | [`DeployCoinbaseAttestation`](broadcast/DeployCoinbaseAttestation.s.sol/84532/run-latest.json) |
| Coinbase KYC v2 (pre-release) | `0x1885aa2283db21ad0fc63a2df98efe92f31908e6` | [`DeployCoinbaseAttestationV2`](broadcast/DeployCoinbaseAttestationV2.s.sol/84532/run-latest.json) |
| Coinbase Country | `0x9deea2189ae694d7a36f65fb7d7dbe9f75abddce` | [`DeployCoinbaseCountryAttestation`](broadcast/DeployCoinbaseCountryAttestation.s.sol/84532/run-latest.json) |
| OIDC Domain | `0xea5933abc598401c89f63b3f13ae56a7e78984e8` | [`DeployOidcDomainAttestation`](broadcast/DeployOidcDomainAttestation.s.sol/84532/run-latest.json) |
| Mobile ID ownership | `0x49c03b925583aa8528bbfba5a1a4e1f9b157c95a` | [`DeployMdlKrOwnership`](broadcast/DeployMdlKrOwnership.s.sol/84532/run-latest.json) |
| Mobile ID age | `0x45d4850a9b197ceba185b5069fb13ce0be1dc6d6` | [`DeployMdlKrAge`](broadcast/DeployMdlKrAge.s.sol/84532/run-latest.json) |
| Mobile ID region | `0x044116df792eb424c9648df2deeda97afa617ac0` | [`DeployMdlKrRegion`](broadcast/DeployMdlKrRegion.s.sol/84532/run-latest.json) |

### Base Mainnet — chain ID 8453

| Circuit | Verifier | Deployment record |
|---|---|---|
| Coinbase KYC | `0xf7ded73e7a7fc8fb030c35c5a88d40abe6865382` | [`DeployCoinbaseAttestation`](broadcast/DeployCoinbaseAttestation.s.sol/8453/run-latest.json) |
| Coinbase KYC v2 (pre-release) | `0x6fc22d3576fb70457d1529b3f70f711a3cba7a7f` | [`DeployCoinbaseAttestationV2`](broadcast/DeployCoinbaseAttestationV2.s.sol/8453/run-latest.json) |
| Coinbase Country | `0x8e89f11e65f219203f5be9d6a69a4da084630c56` | [`DeployCoinbaseCountryAttestation`](broadcast/DeployCoinbaseCountryAttestation.s.sol/8453/run-latest.json) |
| OIDC Domain | `0x9677ba46ad226ce8b3c4517d9c0143e4d458beae` | [`DeployOidcDomainAttestation`](broadcast/DeployOidcDomainAttestation.s.sol/8453/run-latest.json) |

### GIWA Sepolia — chain ID 91342

| Circuit | Verifier | Deployment record |
|---|---|---|
| GIWA attestation | `0xf6edb9d6114b2546b6e559997fdde08caeea83b3` | [`DeployGiwaAttestation`](broadcast/DeployGiwaAttestation.s.sol/91342/run-latest.json) |
| Dojang Playground | `0xad6c9bfa60f3ee618dee9dc2027a69c57f2ad816` | [`DeployDojangPlayground`](broadcast/DeployDojangPlayground.s.sol/91342/run-latest.json) |

## Deploying verifiers

Deployment scripts are under [`script/`](script), with generated verifier sources under each circuit's `target/` directory. The generic helper accepts configured network names:

```bash
./scripts/deploy_verifier.sh coinbase-attestation base-sepolia
```

Environment-specific keys, RPC URLs, and explorer credentials are required.

## Trust model

Each CIP describes the trust assumptions of its circuit.

## License

MIT, preserving the repository's existing license intent. Vendored dependencies retain their respective licenses.
