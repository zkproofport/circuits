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

[`coinbase-attestation-v2`](coinbase-attestation-v2) is the next version of CIP-1's circuit: revocation bound by an Apple App Attest or AI-server statement, an optional EIP-712 action, and the OPRF nullifier. Its README has the statement format and measurements.

[`coinbase-country-attestation-v2`](coinbase-country-attestation-v2) is the same next version of CIP-2's circuit: the statement also carries the country the signer saw on the unrevoked attestation, and the country list rule is unchanged. [`coinbase-country-attestation-v2-android`](coinbase-country-attestation-v2-android) and [`coinbase-country-attestation-v2-android-factory`](coinbase-country-attestation-v2-android-factory) are its Android signers; the shared checks are [`coinbase-country-v2-libs`](coinbase-country-v2-libs).

### Android signer packages

[`oidc-domain-attestation-android`](oidc-domain-attestation-android) and [`coinbase-attestation-v2-android`](coinbase-attestation-v2-android) serve the same circuit ids, public inputs, statements and nullifiers as `oidc-domain-attestation` and `coinbase-attestation-v2`; only the statement's signer differs. There it is an Android phone's hardware-backed key, proven in-circuit by Android key attestation ([`android-key-attestation`](android-key-attestation)): a Remote Key Provisioning chain under Google's Key Attestation CA1 root, valid at the statement's time, for a key generated in TEE or StrongBox by `com.masselabs.zkproofport` signed with its Play app signing certificate, on a device with a locked bootloader and verified boot. [`oidc-domain-attestation-android-factory`](oidc-domain-attestation-android-factory) and [`coinbase-attestation-v2-android-factory`](coinbase-attestation-v2-android-factory) serve the same ids for devices whose attestation keys were provisioned at the factory (launched with Android 12 or earlier): a chain under Google's RSA root plus a Google Play Integrity verdict for the same statement ([`play-integrity`](play-integrity)). Each package has its own verifier (2^21). The token and Coinbase checks are shared libraries ([`oidc-libs`](oidc-libs), [`coinbase-v2-libs`](coinbase-v2-libs)); [`statement-signer`](statement-signer) pins every trust anchor.

`coinbase-libs`, `coinbase-v2-libs`, `oidc-libs`, `app-attest-libs`, `android-key-attestation`, `play-integrity`, `statement-signer` and `oprf-nullifier-libs` are shared libraries. `_archived-poc` (which holds the retired `coinbase-kyc` reference circuit) and `zktls` are outside the current credential CIP mapping.

## Implemented circuits

### Coinbase KYC attestation — Reference

Proves control of an address named by a signed Coinbase `attestAccount(address)` transaction while keeping the address, transaction, and signatures private. The circuit verifies user ownership, EIP-1559 transaction structure and signature, signer membership in a public Merkle root, target calldata, and the OPRF nullifier for that address.

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

Proves that the signing wallet holds a Human Passport scoreV2 attestation whose EIP-712 request was signed by an issuer in a public Merkle root of (issuer, GitcoinVerifier domain, schema) leaves, with `score >= min_score` for a public scorer id and `now < expirationTime`. The wallet signs the request (an EIP-712 action, or the signal hash); the nullifier is the OPRF nullifier. Revocation is not checked. Design, measurements and limits in [`human-passport-score/README.md`](human-passport-score/README.md).

## Shared nullifier schemes

### Wallet credentials: the OPRF nullifier

Every wallet credential circuit -- `coinbase-attestation`,
`coinbase-country-attestation`, the six `coinbase-*-attestation-v2*`
packages, `giwa-attestation`, `dojang-playground` and `human-passport-score`
-- publishes the nullifier of [`oprf-nullifier-libs`](oprf-nullifier-libs)
(TACEO's construction):

```text
query     = Poseidon2(DS_query, address, domain, scope)
nullifier = Poseidon2(DS_out, query, P.x, P.y)     P = k * encode_to_curve(query), unblinded
key hash  = Poseidon2(DS_key, D.x, D.y)            D = k * G, the OPRF public key
```

The circuit recomputes the blinded query, checks the OPRF nodes'
Chaum-Pedersen proof that their answer used the key behind `D`, and checks the
client's unblinding, for the address its credential checks proved. Public:
`oprf_key_hash`, `domain`, `scope` (each `keccak256(string) mod p` for a
string) and `nullifier`, where the circuit had `scope` and `nullifier` before.
Nobody without the OPRF key can compute a nullifier from an address. A
verifier pins `oprf_key_hash` to the key registered for the proof type (one key
per proof type) and compares `domain` and `scope` with the reduced values it
asked for. The construction, the checks and the tests are in
[`oprf-nullifier-libs/README.md`](oprf-nullifier-libs/README.md).

### OIDC domain profile

```text
nullifier = keccak256(keccak256(email) || scope)
```

Nullifier storage is application-specific. `NullifierRegistry` and `ZKProofportNullifierRegistry` are deprecated and are retained only as historical source references.

## Building

The current generated artifacts were built with:

- `nargo 1.0.0`
- `bb 6.0.0`

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

## Dependencies

Every Noir library is a local copy under `deps/`, one per library, pinned to an upstream release in `deps/MANIFEST.json`; no build fetches from git. A copy that differs from its release lists each change in its own `PATCHES.md`.

```bash
./scripts/check-deps.sh             # offline: git dependencies, duplicate copies, manifest hashes
./scripts/check-deps.sh --upstream  # compares every copy with its upstream release
```

## Reference deployments

The tables below are generated by `scripts/readme-deployments.py` from `broadcast/**/run-latest.json` at revision [`5a1f906f8a6f569eda0c88ac176d40cf3c6ba107`](https://github.com/zkproofport/circuits/commit/5a1f906f8a6f569eda0c88ac176d40cf3c6ba107).

### Ethereum Sepolia — chain ID 11155111

| Circuit | Verifier | Deployment record |
|---|---|---|
| Coinbase KYC | `0x7fc2059a73cef2b572c8deee911c72963dcb4a8a` | [`DeployCoinbaseAttestation`](broadcast/DeployCoinbaseAttestation.s.sol/11155111/run-latest.json) |
| Coinbase KYC v2 (pre-release) | `0x42972771718ef5096f884da45e53dd7fa54d4180` | [`DeployCoinbaseAttestationV2`](broadcast/DeployCoinbaseAttestationV2.s.sol/11155111/run-latest.json) |
| Coinbase Country | `0x0b3af3dfc67dc65e0145c37ee00230139d579f64` | [`DeployCoinbaseCountryAttestation`](broadcast/DeployCoinbaseCountryAttestation.s.sol/11155111/run-latest.json) |
| OIDC Domain | `0x4253eef617ee2d1fc4e551f448fbfdaaaeb9fc90` | [`DeployOidcDomainAttestation`](broadcast/DeployOidcDomainAttestation.s.sol/11155111/run-latest.json) |
| OIDC Domain (Android) | `0x87e6096c71c7e3b987b544b5f036cb2da1fb81ba` | [`DeployOidcDomainAttestationAndroid`](broadcast/DeployOidcDomainAttestationAndroid.s.sol/11155111/run-latest.json) |
| Coinbase KYC v2 (Android) | `0x6238395267684550b382291e9172470705a1a94a` | [`DeployCoinbaseAttestationV2Android`](broadcast/DeployCoinbaseAttestationV2Android.s.sol/11155111/run-latest.json) |
| OIDC Domain (Android, factory keys) | `0x481533c79a668af14ba6880b2c5c0040f2b4a390` | [`DeployOidcDomainAttestationAndroidFactory`](broadcast/DeployOidcDomainAttestationAndroidFactory.s.sol/11155111/run-latest.json) |
| Coinbase KYC v2 (Android, factory keys) | `0xeaf299f32dfb1c33fdde7cd4a13fd61306d25b26` | [`DeployCoinbaseAttestationV2AndroidFactory`](broadcast/DeployCoinbaseAttestationV2AndroidFactory.s.sol/11155111/run-latest.json) |
| Coinbase Country v2 (pre-release) | `0xbcc01efce38cda8f4ffed8eb5260810545ab0206` | [`DeployCoinbaseCountryAttestationV2`](broadcast/DeployCoinbaseCountryAttestationV2.s.sol/11155111/run-latest.json) |
| Coinbase Country v2 (Android) | `0x1e34e8057809e76639da74e432ca481f0622fcc0` | [`DeployCoinbaseCountryAttestationV2Android`](broadcast/DeployCoinbaseCountryAttestationV2Android.s.sol/11155111/run-latest.json) |
| Coinbase Country v2 (Android, factory keys) | `0x4857ca327be7ea2b6c34aef6fbf38d13273b81b8` | [`DeployCoinbaseCountryAttestationV2AndroidFactory`](broadcast/DeployCoinbaseCountryAttestationV2AndroidFactory.s.sol/11155111/run-latest.json) |
| Human Passport score | `0x9904a8d852ddeabf7d9c8cf7116609da8e39c2eb` | [`DeployHumanPassportScore`](broadcast/DeployHumanPassportScore.s.sol/11155111/run-latest.json) |

### Base Sepolia — chain ID 84532

| Circuit | Verifier | Deployment record |
|---|---|---|
| Coinbase KYC | `0x42d165a48256ae184e1de4e7e6372e870e2bc883` | [`DeployCoinbaseAttestation`](broadcast/DeployCoinbaseAttestation.s.sol/84532/run-latest.json) |
| Coinbase KYC v2 (pre-release) | `0xe78fcdc7562ce3afceadaf29f4b8b96dc997c01a` | [`DeployCoinbaseAttestationV2`](broadcast/DeployCoinbaseAttestationV2.s.sol/84532/run-latest.json) |
| Coinbase Country | `0x9deea2189ae694d7a36f65fb7d7dbe9f75abddce` | [`DeployCoinbaseCountryAttestation`](broadcast/DeployCoinbaseCountryAttestation.s.sol/84532/run-latest.json) |
| OIDC Domain | `0x14a2241b0a24679825befaaa562d4a204262d84f` | [`DeployOidcDomainAttestation`](broadcast/DeployOidcDomainAttestation.s.sol/84532/run-latest.json) |
| OIDC Domain (Android) | `0x31fea05b9fa197b591d66cff0fef5698e6a5d9c0` | [`DeployOidcDomainAttestationAndroid`](broadcast/DeployOidcDomainAttestationAndroid.s.sol/84532/run-latest.json) |
| Coinbase KYC v2 (Android) | `0x551af332b494658ece6124c1a5c48202c0580e28` | [`DeployCoinbaseAttestationV2Android`](broadcast/DeployCoinbaseAttestationV2Android.s.sol/84532/run-latest.json) |
| OIDC Domain (Android, factory keys) | `0xaef0af1b129035b6ceef40241fd75871d15a5f41` | [`DeployOidcDomainAttestationAndroidFactory`](broadcast/DeployOidcDomainAttestationAndroidFactory.s.sol/84532/run-latest.json) |
| Coinbase KYC v2 (Android, factory keys) | `0xe0982a6ecffc0ef1bd43d1d8bfe8c5089f3ff5bd` | [`DeployCoinbaseAttestationV2AndroidFactory`](broadcast/DeployCoinbaseAttestationV2AndroidFactory.s.sol/84532/run-latest.json) |
| Coinbase Country v2 (pre-release) | `0xe88033179576869c8730160ecbfaa7e5b2c1a4a9` | [`DeployCoinbaseCountryAttestationV2`](broadcast/DeployCoinbaseCountryAttestationV2.s.sol/84532/run-latest.json) |
| Coinbase Country v2 (Android) | `0x8e86cc23c908792ad4f2eb1df9a485a518eeea0e` | [`DeployCoinbaseCountryAttestationV2Android`](broadcast/DeployCoinbaseCountryAttestationV2Android.s.sol/84532/run-latest.json) |
| Coinbase Country v2 (Android, factory keys) | `0x26d4cfae6654c31d10d669c0ebc6428802adf9d0` | [`DeployCoinbaseCountryAttestationV2AndroidFactory`](broadcast/DeployCoinbaseCountryAttestationV2AndroidFactory.s.sol/84532/run-latest.json) |
| Human Passport score | `0x223e372553739678365486a3ded05310b5bcbc0c` | [`DeployHumanPassportScore`](broadcast/DeployHumanPassportScore.s.sol/84532/run-latest.json) |

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
| GIWA attestation | `0xa272056866453f0182426a29b9ca6382d6c6a060` | [`DeployGiwaAttestation`](broadcast/DeployGiwaAttestation.s.sol/91342/run-latest.json) |
| Dojang Playground | `0x400474e78a793289d091a5f556f78158956b5d01` | [`DeployDojangPlayground`](broadcast/DeployDojangPlayground.s.sol/91342/run-latest.json) |

## Deploying verifiers

Deployment scripts are under [`script/`](script), with generated verifier sources under each circuit's `target/` directory. The generic helper accepts configured network names:

```bash
./scripts/deploy_verifier.sh coinbase-attestation base-sepolia
```

Environment-specific keys, RPC URLs, and explorer credentials are required.

Checking a verifier:

```bash
# a local proof through the deployed contract; also each named proof field changed
TAMPER_FIELDS=default ./scripts/verify-onchain.sh human-passport-score base-sepolia
# the deployed runtime code against this checkout's build, and its linked libraries
python3 scripts/check-deployed-code.py 84532 HumanPassportScore
```

## Trust model

Each CIP describes the trust assumptions of its circuit.

## License

MIT, preserving the repository's existing license intent. Vendored dependencies retain their respective licenses.
