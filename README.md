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
| CIP-5 | [Korean Mobile ID Selective Disclosure Profile](https://github.com/zkproofport/CIPs/blob/main/CIPS/cip-5.md) | [`mdl/kr-*`](mdl) | Experimental |

`coinbase-libs` is a shared implementation library. `coinbase-kyc` is an older reference-only circuit. `_archived-poc` and `zktls` are outside the current credential CIP mapping.

## Implemented circuits

### Coinbase KYC attestation — Reference

Proves control of an address named by a signed Coinbase `attestAccount(address)` transaction while keeping the address, transaction, and signatures private. The circuit verifies user ownership, EIP-1559 transaction structure and signature, signer membership in a public Merkle root, target calldata, and a signal- and scope-bound nullifier.

### Coinbase country predicate — Reference

Extends the Coinbase transaction profile with a private two-byte country code and a public inclusion or exclusion list of up to ten ISO 3166-1 alpha-2 values.

### OIDC domain attestation — Reference

Verifies a Google Workspace or Microsoft 365 OIDC JWT with RSA-2048 and proves that its private email ends in a public domain. It exposes a provider identifier and an email-derived scope-bound nullifier.

Provider key authorization, JWT freshness, issuer, audience, and nonce policy are not enforced by the current circuit and must be handled by an integration profile.

### GIWA attestation — PoC

GIWA Sepolia proof flow using a test `MockGiwaAttester`, mobile-compatible UltraHonk proof generation, and an EVM verifier. Production Dojang issuer and schema parameters remain unresolved.

### Korean Mobile ID predicates — Experimental

Three circuits under `mdl/` implement ownership/selective field commitment, year-based age threshold, and region-token predicates. They share `keccak256(keccak256(ci) || scope)` nullifiers.

The active circuits do not yet cryptographically authenticate claims against a canonical Mobile ID issuer trust anchor.

## Shared nullifier schemes

### Coinbase and GIWA transaction profiles

```text
user_secret = keccak256(user_address || signal_hash)
nullifier   = keccak256(user_secret || scope)
```

Duplicate-detection behavior depends on both `signal_hash` and `scope` remaining stable for the relevant action.

### OIDC domain profile

```text
nullifier = keccak256(keccak256(email) || scope)
```

### Korean Mobile ID experimental profile

```text
nullifier = keccak256(keccak256(ci) || scope)
```

Nullifier storage is application-specific. `NullifierRegistry` and `ZKProofportNullifierRegistry` are deprecated and are retained only as historical source references.

## Building

The current generated artifacts were built with:

- `nargo 1.0.0-beta.8`
- `bb v1.0.0-nightly.20250723`

```bash
./scripts/build.sh coinbase-attestation
./scripts/build.sh coinbase-country-attestation
./scripts/build.sh oidc-domain-attestation
./scripts/build.sh giwa-attestation
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

The tables below are synchronized with `broadcast/**/run-latest.json` at revision [`28bbc303e04b732eb612d419b44dfd39d8a38a9a`](https://github.com/zkproofport/circuits/commit/28bbc303e04b732eb612d419b44dfd39d8a38a9a).

### Ethereum Sepolia — chain ID 11155111

| Circuit | Verifier | Deployment record |
|---|---|---|
| Coinbase KYC | `0xcbc8e63ff92659e8b44cff117d33005bb669a018` | [`DeployCoinbaseAttestation`](broadcast/DeployCoinbaseAttestation.s.sol/11155111/run-latest.json) |
| Coinbase Country | `0x6646d970499bbed728636823a5a7e551e811b414` | [`DeployCoinbaseCountryAttestation`](broadcast/DeployCoinbaseCountryAttestation.s.sol/11155111/run-latest.json) |
| OIDC Domain | `0x07121eb50b2ebe1675e7cb96c84b580a3ff6589e` | [`DeployOidcDomainAttestation`](broadcast/DeployOidcDomainAttestation.s.sol/11155111/run-latest.json) |

### Base Sepolia — chain ID 84532

| Circuit | Verifier | Deployment record |
|---|---|---|
| Coinbase KYC | `0x0036b61dbfab8f3cfeef77dd5d45f7efbfe2035c` | [`DeployCoinbaseAttestation`](broadcast/DeployCoinbaseAttestation.s.sol/84532/run-latest.json) |
| Coinbase Country | `0xdee363585926c3c28327efd1edd01cf4559738cf` | [`DeployCoinbaseCountryAttestation`](broadcast/DeployCoinbaseCountryAttestation.s.sol/84532/run-latest.json) |
| OIDC Domain | `0x27afdea349f247cf698f97fdfab59e1bf8bd0550` | [`DeployOidcDomainAttestation`](broadcast/DeployOidcDomainAttestation.s.sol/84532/run-latest.json) |
| Mobile ID ownership | `0x7602d09d24e6e16eff5ab981646872886376763e` | [`DeployMdlKrOwnership`](broadcast/DeployMdlKrOwnership.s.sol/84532/run-latest.json) |
| Mobile ID age | `0xcff90ff8ceadc98f625300dc976ed85a3aa943ba` | [`DeployMdlKrAge`](broadcast/DeployMdlKrAge.s.sol/84532/run-latest.json) |
| Mobile ID region | `0x435f0448f02f5df9659d460181116bcaf37e518e` | [`DeployMdlKrRegion`](broadcast/DeployMdlKrRegion.s.sol/84532/run-latest.json) |

### Base Mainnet — chain ID 8453

| Circuit | Verifier | Deployment record |
|---|---|---|
| Coinbase KYC | `0xf7ded73e7a7fc8fb030c35c5a88d40abe6865382` | [`DeployCoinbaseAttestation`](broadcast/DeployCoinbaseAttestation.s.sol/8453/run-latest.json) |
| Coinbase Country | `0xf3d5a09d2c85b28c52ef2905c1be3a852b609d0c` | [`DeployCoinbaseCountryAttestation`](broadcast/DeployCoinbaseCountryAttestation.s.sol/8453/run-latest.json) |
| OIDC Domain | `0x9677ba46ad226ce8b3c4517d9c0143e4d458beae` | [`DeployOidcDomainAttestation`](broadcast/DeployOidcDomainAttestation.s.sol/8453/run-latest.json) |

### GIWA Sepolia — chain ID 91342

| Circuit | Verifier | Deployment record |
|---|---|---|
| GIWA attestation PoC | `0xeb9eb5452790cfe549ff83ceb3dbe1c432231492` | [`DeployGiwaAttestation`](broadcast/DeployGiwaAttestation.s.sol/91342/run-latest.json) |

## Deploying verifiers

Deployment scripts are under [`script/`](script), with generated verifier sources under each circuit's `target/` directory. The generic helper accepts configured network names:

```bash
./scripts/deploy_verifier.sh coinbase-attestation base-sepolia
```

Environment-specific keys, RPC URLs, and explorer credentials are required.

## Security status

No external security audit or formal verification is documented for the current circuits. Review each CIP's trust assumptions and known limitations before relying on a reference implementation or deployment.

## License

MIT, preserving the repository's existing license intent. Vendored dependencies retain their respective licenses.
