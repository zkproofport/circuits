# ZKProofport Circuit Library

## Overview

Noir ZK circuits for the ProofPort protocol. Each circuit generates zero-knowledge proofs for specific on-chain attestations without revealing user identity.

## Available Circuits

### coinbase-attestation (Active)
Proves Coinbase KYC attestation using hybrid verification:
- Off-chain: JavaScript `ecrecover` derives signer public key
- On-chain: Noir verifies ECDSA signature via `std::ecdsa_secp256k1::verify_signature`
- Includes nullifier generation for sybil resistance

### coinbase-country-attestation (Active)
Proves Coinbase country attestation without revealing the country. Built on shared `coinbase-libs`.

### coinbase-libs (Shared Library)
Shared Noir library providing nullifier generation, RLP parser, Merkle proof verification, and Ethereum helpers.

### coinbase-kyc (Reference Only)
Original circuit implementation. Kept as reference, not actively developed.

## Public Inputs

All active circuits share these public inputs:

| Input | Description |
|-------|-------------|
| `signal_hash` | Anti-replay challenge from dApp |
| `signer_list_merkle_root` | Merkle root of authorized Coinbase signers |
| `scope` | Nullifier scope identifier |
| `nullifier` | Sybil resistance identifier |

## Nullifier Scheme

```
scope = keccak256(scope_string)
user_secret = keccak256(user_address ++ signal_hash)
nullifier = keccak256(user_secret ++ scope)
```

Same user + same scope = same nullifier (duplicate detected).

## Building

```bash
# Full build pipeline (compile + VK + Solidity verifier)
./scripts/build.sh coinbase-attestation
./scripts/build.sh coinbase-country-attestation
```

Required tools (exact versions):
- nargo 1.0.0-beta.8
- bb v1.0.0-nightly.20250723

## Deploying Verifiers

Prerequisites: `.env.development` or `.env.production` with `PRIVATE_KEY`, RPC URLs, `ETHERSCAN_API_KEY`.

```bash
# 1. Deploy shared library (once per network)
./scripts/deploy_verifier.sh lib base-sepolia

# 2. Deploy verifier contracts
./scripts/deploy_verifier.sh coinbase-attestation base-sepolia
./scripts/deploy_verifier.sh coinbase-country-attestation base-sepolia
```

Supported networks: base-sepolia, sepolia, base, mainnet

## Current Deployments

### Base Sepolia (Chain ID: 84532)

| Contract | Address |
|----------|---------|
| ZKTranscriptLib | `0xD4A84AcCA4d9A94ec194a10226eC600fFF0939E7` |
| CoinbaseAttestation | `0xEb9eb5452790Cfe549fF83CEB3Dbe1C432231492` |
| CoinbaseCountryAttestation | `0xD0F3eE648386B59B484157332E736388Fcc41F47` |
| NullifierRegistry | `0x5Da234546874304F8c51BBEed00fC632938211c1` |

### Base Mainnet (Chain ID: 8453)

Not yet deployed.

## Smart Contracts

### Verifier Contracts
Generated Solidity contracts that verify UltraHonk proofs on-chain. Each circuit has its own verifier.

### NullifierRegistry
Multi-circuit nullifier registry that prevents duplicate proofs within the same scope. Deployed via `script/DeployNullifierRegistry.s.sol`.

## Constants

| Constant | Value |
|----------|-------|
| Coinbase Attester | `0x357458739F90461b99789350868CD7CF330Dd7EE` |
| Function Selector | `0x56feed5e` (attestAccount) |

## Security

These circuits are experimental and have not undergone a formal security audit. Use with caution in production.

## License

MIT