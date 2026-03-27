# ZKProofport Circuit Library

## Overview

Noir ZK circuits for the Proofport protocol. Each circuit generates zero-knowledge proofs for specific on-chain attestations without revealing user identity.

## Available Circuits

### coinbase-attestation (Active)
Proves Coinbase KYC attestation using hybrid verification:
- Off-chain: JavaScript `ecrecover` derives signer public key
- On-chain: Noir verifies ECDSA signature via `std::ecdsa_secp256k1::verify_signature`
- Includes nullifier generation for sybil resistance

### coinbase-country-attestation (Active)
Proves Coinbase country attestation without revealing the country. Built on shared `coinbase-libs`.

### oidc-domain-attestation (Active)
Proves email domain affiliation via OIDC JWT (Google, Microsoft) without revealing the full email address.
- RSA-2048 signature verification of JWT
- Domain extraction from email claim
- Nullifier generation from email + scope (Sybil-resistant)
- Provider support: Google (email_verified), Microsoft 365 (xms_edov)
- 148 public inputs: pubkey_modulus_limbs[18] + domain BoundedVec<u8,64> + scope[32] + nullifier[32] + provider[1]

### coinbase-libs (Shared Library)
Shared Noir library providing nullifier generation, RLP parser, Merkle proof verification, and Ethereum helpers.

### coinbase-kyc (Reference Only)
Original circuit implementation. Kept as reference, not actively developed.

## Public Inputs

### Coinbase Circuits

Coinbase attestation circuits share these public inputs:

| Input | Description |
|-------|-------------|
| `signal_hash` | Anti-replay challenge from dApp |
| `signer_list_merkle_root` | Merkle root of authorized Coinbase signers |
| `scope` | Nullifier scope identifier |
| `nullifier` | Sybil resistance identifier |

### OIDC Domain Attestation Circuit

The OIDC circuit has a distinct layout with 148 public inputs:

| Input | Count | Description |
|-------|-------|-------------|
| `pubkey_modulus_limbs` | 18 | RSA-2048 public key modulus (18 x 120-bit limbs) |
| `domain` | 65 | BoundedVec\<u8,64\>: length prefix + domain bytes |
| `scope` | 32 | Nullifier scope identifier (32 bytes) |
| `nullifier` | 32 | Sybil resistance identifier (32 bytes) |
| `provider` | 1 | OIDC provider (0 = Google, 1 = Microsoft) |

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
./scripts/build.sh oidc-domain-attestation
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
./scripts/deploy_verifier.sh oidc-domain-attestation base-sepolia
```

> **Note:** OIDC domain attestation is verified both on-chain (via deployed verifier contracts) and off-chain (via `bb verify` in the AI server).

Supported networks: base-sepolia, sepolia, base, mainnet

## Current Deployments

### Base Sepolia (Chain ID: 84532)

| Contract | Address |
|----------|---------|
| ZKTranscriptLib | `0xD4A84AcCA4d9A94ec194a10226eC600fFF0939E7` |
| CoinbaseAttestation | `0xEb9eb5452790Cfe549fF83CEB3Dbe1C432231492` |
| CoinbaseCountryAttestation | `0xD0F3eE648386B59B484157332E736388Fcc41F47` |
| OidcDomainAttestation | `0x27afdea349f247cf698f97fdfab59e1bf8bd0550` |
| ~~ZKProofportNullifierRegistry~~ | ~~`0xC6a8dC34B1872a883aFCc808C90c31c038764d9a`~~ (DEPRECATED) |

### Base Mainnet (Chain ID: 8453)

| Contract | Address |
|----------|---------|
| ZKTranscriptLib | `0x5A74865E3027FEeaE68cb1F07970442F2cbE00B1` |
| CoinbaseAttestation | `0xF7dED73E7a7fc8fb030c35c5A88D40ABe6865382` |
| CoinbaseCountryAttestation | `0xF3D5A09d2C85B28C52EF2905c1BE3a852b609D0C` |
| OidcDomainAttestation | `0x9677ba46ad226ce8b3c4517d9c0143e4d458beae` |

## Smart Contracts

### Verifier Contracts
Generated Solidity contracts that verify UltraHonk proofs on-chain. Each circuit has its own verifier.

### NullifierRegistry (DEPRECATED)
Multi-circuit nullifier registry. **Deprecated** — nullifier management is handled off-chain. Source code kept for reference only.

## Constants

| Constant | Value |
|----------|-------|
| Coinbase Attester | `0x357458739F90461b99789350868CD7CF330Dd7EE` |
| Function Selector | `0x56feed5e` (attestAccount) |

## Security

These circuits are experimental and have not undergone a formal security audit. Use with caution in production.

## License

MIT