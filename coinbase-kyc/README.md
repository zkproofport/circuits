# Coinbase KYC Circuit (v0.1 - Under Development)

This circuit generates a ZK proof allowing a user to prove they have completed Coinbase's on-chain KYC attestation (EAS) without revealing their Ethereum address.

## Purpose

To enable dApps to comply with KYC regulations without compromising user on-chain privacy.

## How it Works (Conceptual)

The circuit performs the following checks (refer to `src/main.nr` for details):

1.  **Attestor Verification:** Confirms the attesting address matches the official Coinbase address. (Currently hardcoded, planned to change to Merkle Tree).
2.  **Ownership & Signature Verification:** Verifies the user's signature against the provided `calldata` and ensures the address recovered from the signature matches both the address within the `calldata` and the claimed user address.

## Current Status & Limitations (v0.1)

* **PoC Stage:** This circuit is not ready for production use.
* **External Digest Trust:** Relies on a pre-computed `keccak256` digest provided as a private input, which is a security vulnerability.
* **Core Anchors Missing:** Implementation of `merkle_root`, `nullifier_hash`, and `signal_hash` is required.

## Future Direction

1.  **Internal Keccak256:** Implement digest calculation *inside* the circuit using the raw `calldata` for trustlessness.
2.  **Implement Core Anchors:** Add logic for Merkle Tree verification, Nullifier generation/check, and Signal Hash validation to achieve production-level security and functionality.
3.  **Optimization:** Reduce circuit constraints to decrease proof generation time.