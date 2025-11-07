# ZKProofport Circuit Library

## Overview

This repository contains the collection of Noir circuits used within the ZKProofport protocol. Each circuit is a standalone module designed to generate zero-knowledge proofs for specific on-chain or off-chain attestations.

ZKProofport is a privacy infrastructure enabling users to prove certain qualifications (e.g., KYC completion, email domain ownership) to dApps without revealing their personal information. This repository houses the core cryptographic logic—the Noir circuits—required to generate these proofs.

## Available Circuits

This library is designed to be extensible. Our first and most complex circuit serves as the technical foundation for future development.

  * **`coinbase-kyc/`**: (Complete) An advanced circuit for generating ZK proofs of Coinbase on-chain KYC attestations. This circuit securely verifies the RLP-encoded EIP-1559 transaction, validates the Coinbase attester's signature using a high-performance hybrid (off-chain/on-chain) method, and confirms signer validity against a flexible Merkle root.

  * **`[Future Circuit Dirs]/`**: New circuits for various on-chain state proofs (e.g., Proof of NFT Ownership) or other off-chain data (e.g., Proof of GitHub Contribution) will be added here.

## Security & Disclaimer

The circuits in this repository, including the completed `coinbase-kyc` circuit, are experimental and have not yet undergone a formal, independent security audit. They are provided as-is for research, testing, and community feedback.

We strongly advise caution when integrating these circuits into systems where tangible assets are at stake. Bug reports and feature suggestions are always welcome via GitHub Issues. For security vulnerabilities, please contact us privately.

## License

[MIT](https://www.google.com/search?q=LICENSE)