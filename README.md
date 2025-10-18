# ZKProofport Circuit Library

This repository contains a collection of Noir circuits used within the ZKProofport protocol. Each circuit is designed to generate proofs for specific types of private attestations.

## Overview

ZKProofport is a privacy infrastructure enabling users to prove certain qualifications (e.g., KYC completion, membership in a group) to dApps without revealing their personal information. This repository houses the core cryptographic logic—the Noir circuits—required to generate these proofs.

## Directory Structure

* **`coinbase-kyc/`**: Contains the circuit for ZK proofs based on Coinbase on-chain KYC attestations (EAS). (Currently under development)
* **`utils/`** (Example): May contain utility functions or libraries (e.g., Keccak256, Merkle Tree implementations) shared across multiple circuits.
* **`[Future Circuit Dirs]/`**: Will house circuits for other types of attestations planned for future support (e.g., `twitter-followers/`, `github-contributions/`).

## Security & Contribution

The circuits currently under development have not undergone production-level security audits. Use with caution.

Bug reports and feature suggestions are always welcome via GitHub Issues. For security vulnerabilities, please contact us privately.

## License

[MIT](https://www.google.com/search?q=LICENSE)



