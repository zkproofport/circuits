# ZKProofport Circuit Library

## Overview

This repository contains the collection of Noir circuits used within the ZKProofport protocol. Each circuit is a standalone module designed to generate zero-knowledge proofs for specific on-chain or off-chain attestations.

ZKProofport is a privacy infrastructure enabling users to prove certain qualifications (e.g., KYC completion, email domain ownership) to dApps without revealing their personal information. This repository houses the core cryptographic logic—the Noir circuits—required to generate these proofs.

## Available Circuits

This library is designed to be extensible. Our first and most complex circuit serves as the technical foundation for future development.

  * **`coinbase-kyc/`**: (Complete) An advanced circuit for generating ZK proofs of Coinbase on-chain KYC attestations. This circuit securely verifies the RLP-encoded EIP-1559 transaction, validates the Coinbase attester's signature using a high-performance hybrid (off-chain/on-chain) method, and confirms signer validity against a flexible Merkle root.

  * **`coinbase-attestation/`**: Refactored from `coinbase-kyc` for mobile app integration. Shared utilities extracted into `coinbase-libs` for maintainability. Proves Coinbase KYC attestation without revealing the user's identity.

  * **`coinbase-country-attestation/`**: Built on the refactored `coinbase-libs` shared library. Proves Coinbase country attestation without revealing the country.

  * **`coinbase-libs/`**: Shared Noir library (`type = "lib"`) extracted from common code. Provides RLP parser, Merkle proof verification, EIP-1559 transaction parser, and Ethereum helpers. Used by both `coinbase-attestation` and `coinbase-country-attestation`.

  * **`[Future Circuit Dirs]/`**: New circuits for various on-chain state proofs (e.g., Proof of NFT Ownership) or other off-chain data (e.g., Proof of GitHub Contribution) will be added here.

## Building Circuits

```bash
# Full build (compile + VK + witness + proof + verify + Solidity verifier)
./scripts/build.sh coinbase-attestation
./scripts/build.sh coinbase-country-attestation
```

## Deploying Verifiers

Deploy Solidity verifier contracts to EVM networks using Foundry.

**Prerequisites**: `.env.development` or `.env.production` with `PRIVATE_KEY`, RPC URLs, API keys. Install Foundry dependencies with `forge install`.

**Deployment order**:
1. Deploy ZKTranscriptLib (shared on-chain library, once per network):
   ```bash
   ./scripts/deploy_verifier.sh lib base-sepolia
   ```
2. Deploy verifier contracts:
   ```bash
   ./scripts/deploy_verifier.sh coinbase-attestation base-sepolia
   ./scripts/deploy_verifier.sh coinbase-country-attestation base-sepolia
   ```

**Supported networks**: base-sepolia, sepolia, base, mainnet

### Current Deployments (Base Sepolia - Chain 84532)

| Contract | Address |
|----------|---------|
| ZKTranscriptLib | `0xD4A84AcCA4d9A94ec194a10226eC600fFF0939E7` |
| CoinbaseAttestation HonkVerifier | `0x07121eb50b2Ebe1675E7Cb96c84B580A3fF6589e` |
| CoinbaseCountryAttestation HonkVerifier | `0xaaC5F16CD40D8AF76508ae7dbD6A8FbE60f780B4` |

## Security & Disclaimer

The circuits in this repository, including the completed `coinbase-kyc` circuit, are experimental and have not yet undergone a formal, independent security audit. They are provided as-is for research, testing, and community feedback.

We strongly advise caution when integrating these circuits into systems where tangible assets are at stake. Bug reports and feature suggestions are always welcome via GitHub Issues. For security vulnerabilities, please contact us privately.

## License

[MIT](https://www.google.com/search?q=LICENSE)