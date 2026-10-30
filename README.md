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

[`dojang-playground`](dojang-playground) is a GIWA Sepolia demo circuit outside the CIP mapping.

[`coinbase-attestation-v2`](coinbase-attestation-v2) is the next version of CIP-1's circuit: revocation bound by an Apple App Attest or AI-server statement, an optional EIP-712 action, and a wallet nullifier. Its README has the statement format and measurements.

[`coinbase-country-attestation-v2`](coinbase-country-attestation-v2) is the same next version of CIP-2's circuit: the statement also carries the country the signer saw on the unrevoked attestation, and the country list rule is unchanged. [`coinbase-country-attestation-v2-android`](coinbase-country-attestation-v2-android) and [`coinbase-country-attestation-v2-android-factory`](coinbase-country-attestation-v2-android-factory) are its Android signers; the shared checks are [`coinbase-country-v2-libs`](coinbase-country-v2-libs).

### Android signer packages

[`oidc-domain-attestation-android`](oidc-domain-attestation-android) and [`coinbase-attestation-v2-android`](coinbase-attestation-v2-android) serve the same circuit ids, public inputs, statements and nullifiers as `oidc-domain-attestation` and `coinbase-attestation-v2`; only the statement's signer differs. There it is an Android phone's hardware-backed key, proven in-circuit by Android key attestation ([`android-key-attestation`](android-key-attestation)): a Remote Key Provisioning chain under Google's Key Attestation CA1 root, valid at the statement's time, for a key generated in TEE or StrongBox by `com.masselabs.zkproofport` signed with its Play app signing certificate, on a device with a locked bootloader and verified boot. [`oidc-domain-attestation-android-factory`](oidc-domain-attestation-android-factory) and [`coinbase-attestation-v2-android-factory`](coinbase-attestation-v2-android-factory) serve the same ids for devices whose attestation keys were provisioned at the factory (launched with Android 12 or earlier): a chain under Google's RSA root plus a Google Play Integrity verdict for the same statement ([`play-integrity`](play-integrity)). Each package has its own verifier (2^21). The token and Coinbase checks are shared libraries ([`oidc-libs`](oidc-libs), [`coinbase-v2-libs`](coinbase-v2-libs)); [`statement-signer`](statement-signer) pins every trust anchor.

`coinbase-libs`, `coinbase-v2-libs`, `oidc-libs`, `app-attest-libs`, `android-key-attestation`, `play-integrity` and `statement-signer` are shared libraries. `coinbase-kyc` is an older reference-only circuit. `_archived-poc` and `zktls` are outside the current credential CIP mapping.

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

### Human Passport score — Beta

Proves that the signing wallet holds a Human Passport scoreV2 attestation whose EIP-712 request was signed by an issuer in a public Merkle root of (issuer, GitcoinVerifier domain, schema) leaves, with `score >= min_score` for a public scorer id and `now < expirationTime`. The wallet signs the request (an EIP-712 action, or the signal hash); the nullifier is the shared wallet + circuit-tag rule. Revocation is not checked. Design, measurements and limits in [`human-passport-score/README.md`](human-passport-score/README.md).

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

The tables below are generated by `scripts/readme-deployments.py` from `broadcast/**/run-latest.json` at revision [`78fe1127ddb5b9b92d47327758f3c4932cf0cd93`](https://github.com/zkproofport/circuits/commit/78fe1127ddb5b9b92d47327758f3c4932cf0cd93).

### Ethereum Sepolia — chain ID 11155111

| Circuit | Verifier | Deployment record |
|---|---|---|
| Coinbase KYC | `0x7fc2059a73cef2b572c8deee911c72963dcb4a8a` | [`DeployCoinbaseAttestation`](broadcast/DeployCoinbaseAttestation.s.sol/11155111/run-latest.json) |
| Coinbase Country | `0x0b3af3dfc67dc65e0145c37ee00230139d579f64` | [`DeployCoinbaseCountryAttestation`](broadcast/DeployCoinbaseCountryAttestation.s.sol/11155111/run-latest.json) |
| OIDC Domain | `0x8e8f481d98149f13fb756cab69376814fa854180` | [`DeployOidcDomainAttestation`](broadcast/DeployOidcDomainAttestation.s.sol/11155111/run-latest.json) |
| OIDC Domain (Android) | `0xbb430a01ad1e9550d983302963392c1d3d09e62f` | [`DeployOidcDomainAttestationAndroid`](broadcast/DeployOidcDomainAttestationAndroid.s.sol/11155111/run-latest.json) |
| Coinbase KYC v2 (Android) | `0x9432c87835c23d0a1dd88d1ba9f2b1996805b794` | [`DeployCoinbaseAttestationV2Android`](broadcast/DeployCoinbaseAttestationV2Android.s.sol/11155111/run-latest.json) |
| OIDC Domain (Android, factory keys) | `0x17ed7935981ee1aa78fd56f792fed5feed8b367a` | [`DeployOidcDomainAttestationAndroidFactory`](broadcast/DeployOidcDomainAttestationAndroidFactory.s.sol/11155111/run-latest.json) |
| Coinbase KYC v2 (Android, factory keys) | `0xeb1010791fe29b5f89ce1b9098ec4f4fafe04100` | [`DeployCoinbaseAttestationV2AndroidFactory`](broadcast/DeployCoinbaseAttestationV2AndroidFactory.s.sol/11155111/run-latest.json) |
| Coinbase Country v2 (pre-release) | `0x99489796751b4939879dcaf5db35eb4964c58f6c` | [`DeployCoinbaseCountryAttestationV2`](broadcast/DeployCoinbaseCountryAttestationV2.s.sol/11155111/run-latest.json) |
| Coinbase Country v2 (Android) | `0x00f5ab7c6450a6ea91d2db8a91409c1b7504f3cc` | [`DeployCoinbaseCountryAttestationV2Android`](broadcast/DeployCoinbaseCountryAttestationV2Android.s.sol/11155111/run-latest.json) |
| Coinbase Country v2 (Android, factory keys) | `0x81a7bb9c81d244d80f98ebeec455f252ee585911` | [`DeployCoinbaseCountryAttestationV2AndroidFactory`](broadcast/DeployCoinbaseCountryAttestationV2AndroidFactory.s.sol/11155111/run-latest.json) |
| Human Passport score | `0xc78585718fd27d428d7a90970d09a2121be36066` | [`DeployHumanPassportScore`](broadcast/DeployHumanPassportScore.s.sol/11155111/run-latest.json) |

### Base Sepolia — chain ID 84532

| Circuit | Verifier | Deployment record |
|---|---|---|
| Coinbase KYC | `0x42d165a48256ae184e1de4e7e6372e870e2bc883` | [`DeployCoinbaseAttestation`](broadcast/DeployCoinbaseAttestation.s.sol/84532/run-latest.json) |
| Coinbase KYC v2 (pre-release) | `0x1885aa2283db21ad0fc63a2df98efe92f31908e6` | [`DeployCoinbaseAttestationV2`](broadcast/DeployCoinbaseAttestationV2.s.sol/84532/run-latest.json) |
| Coinbase Country | `0x9deea2189ae694d7a36f65fb7d7dbe9f75abddce` | [`DeployCoinbaseCountryAttestation`](broadcast/DeployCoinbaseCountryAttestation.s.sol/84532/run-latest.json) |
| OIDC Domain | `0xea5933abc598401c89f63b3f13ae56a7e78984e8` | [`DeployOidcDomainAttestation`](broadcast/DeployOidcDomainAttestation.s.sol/84532/run-latest.json) |
| OIDC Domain (Android) | `0x64866bf6734ed43d34799c7949f5ecb35b7e7e44` | [`DeployOidcDomainAttestationAndroid`](broadcast/DeployOidcDomainAttestationAndroid.s.sol/84532/run-latest.json) |
| Coinbase KYC v2 (Android) | `0x395b3bcc27e7e405ec909a81374243fd0b44aacc` | [`DeployCoinbaseAttestationV2Android`](broadcast/DeployCoinbaseAttestationV2Android.s.sol/84532/run-latest.json) |
| OIDC Domain (Android, factory keys) | `0x9e47e3c2b30e840cfc4d6901ba3e28fc666b3135` | [`DeployOidcDomainAttestationAndroidFactory`](broadcast/DeployOidcDomainAttestationAndroidFactory.s.sol/84532/run-latest.json) |
| Coinbase KYC v2 (Android, factory keys) | `0xbfaf9390c36d14d596556e42eb52d984de040aa1` | [`DeployCoinbaseAttestationV2AndroidFactory`](broadcast/DeployCoinbaseAttestationV2AndroidFactory.s.sol/84532/run-latest.json) |
| Coinbase Country v2 (pre-release) | `0xc5363d7587bd580148373d0d8b7909be423242cb` | [`DeployCoinbaseCountryAttestationV2`](broadcast/DeployCoinbaseCountryAttestationV2.s.sol/84532/run-latest.json) |
| Coinbase Country v2 (Android) | `0x98013abb7ac83b6c985dcfbd5748ad2ae04c8c12` | [`DeployCoinbaseCountryAttestationV2Android`](broadcast/DeployCoinbaseCountryAttestationV2Android.s.sol/84532/run-latest.json) |
| Coinbase Country v2 (Android, factory keys) | `0xd7bfd6d7bcc6c627da12cfcdf39fca6f64fdc0b9` | [`DeployCoinbaseCountryAttestationV2AndroidFactory`](broadcast/DeployCoinbaseCountryAttestationV2AndroidFactory.s.sol/84532/run-latest.json) |
| Human Passport score | `0x39df92d9c603fe6d229c7b00272a1e874a628ace` | [`DeployHumanPassportScore`](broadcast/DeployHumanPassportScore.s.sol/84532/run-latest.json) |

### Base Mainnet — chain ID 8453

| Circuit | Verifier | Deployment record |
|---|---|---|
| Coinbase KYC | `0xf7ded73e7a7fc8fb030c35c5a88d40abe6865382` | [`DeployCoinbaseAttestation`](broadcast/DeployCoinbaseAttestation.s.sol/8453/run-latest.json) |
| Coinbase KYC v2 (pre-release) | `0x6fc22d3576fb70457d1529b3f70f711a3cba7a7f` | [`DeployCoinbaseAttestationV2`](broadcast/DeployCoinbaseAttestationV2.s.sol/8453/run-latest.json) |
| Coinbase Country | `0x8e89f11e65f219203f5be9d6a69a4da084630c56` | [`DeployCoinbaseCountryAttestation`](broadcast/DeployCoinbaseCountryAttestation.s.sol/8453/run-latest.json) |
| OIDC Domain | `0xf1aa88ad844bfd1dc552526a67f5980aad4e7f35` | [`DeployOidcDomainAttestation`](broadcast/DeployOidcDomainAttestation.s.sol/8453/run-latest.json) |
| OIDC Domain (Android) | `0x3d99a36b39231bc35f6e840f18ac443bf5d229de` | [`DeployOidcDomainAttestationAndroid`](broadcast/DeployOidcDomainAttestationAndroid.s.sol/8453/run-latest.json) |
| Coinbase KYC v2 (Android) | `0x836d8b0fd01bed4e34220ebcee6d63265951fbf9` | [`DeployCoinbaseAttestationV2Android`](broadcast/DeployCoinbaseAttestationV2Android.s.sol/8453/run-latest.json) |
| OIDC Domain (Android, factory keys) | `0x1b8e60db8b51015cdb1983f64c1210ac40d8f532` | [`DeployOidcDomainAttestationAndroidFactory`](broadcast/DeployOidcDomainAttestationAndroidFactory.s.sol/8453/run-latest.json) |
| Coinbase KYC v2 (Android, factory keys) | `0x87d9a66cacac95b2bc43bac8e610c59acb67c5e0` | [`DeployCoinbaseAttestationV2AndroidFactory`](broadcast/DeployCoinbaseAttestationV2AndroidFactory.s.sol/8453/run-latest.json) |
| Coinbase Country v2 (pre-release) | `0x509dee10cc1578361b450fed7475ea3bd69c6e8d` | [`DeployCoinbaseCountryAttestationV2`](broadcast/DeployCoinbaseCountryAttestationV2.s.sol/8453/run-latest.json) |
| Coinbase Country v2 (Android) | `0xb57182062141f59ddbb98da73764ec1676689832` | [`DeployCoinbaseCountryAttestationV2Android`](broadcast/DeployCoinbaseCountryAttestationV2Android.s.sol/8453/run-latest.json) |
| Coinbase Country v2 (Android, factory keys) | `0x1f2975abd0711cf6b98084829e04712ee105d8f7` | [`DeployCoinbaseCountryAttestationV2AndroidFactory`](broadcast/DeployCoinbaseCountryAttestationV2AndroidFactory.s.sol/8453/run-latest.json) |
| Human Passport score | `0x2d055c42a2b0c1024ac4aa83b4995fc8fd45662e` | [`DeployHumanPassportScore`](broadcast/DeployHumanPassportScore.s.sol/8453/run-latest.json) |

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
