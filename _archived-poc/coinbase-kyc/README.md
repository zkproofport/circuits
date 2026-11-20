# Coinbase KYC Attestation Circuit

## Overview

This is an advanced Noir circuit that allows a user to prove they have successfully completed a Coinbase KYC attestation, without revealing their identity, wallet address, or the specific transaction details.

Current on-chain attestations from Coinbase create a public link between a user's KYC status and their wallet address, exposing their entire on-chain history. This circuit breaks that link. It allows a dApp to verify a user's compliance status (e.g., for AML/KYC) without forcing the user to give up their on-chain privacy.

## Key Features

This circuit is designed for robust security, performance, and maintainability:

* **Complete Privacy:** The user's wallet address (`user_address`) is a private input and is never revealed in the final proof.
* **Anti-Replay Security:** A unique, dApp-provided `signal_hash` is used as a public input. This ensures that a proof generated for one dApp or one session cannot be reused elsewhere.
* **High Performance (Hybrid Verification):** Instead of performing a costly `ecrecover` operation entirely within the circuit, we use a hybrid model. The client (JavaScript) calculates the Coinbase attester's public key from the signature off-chain. The circuit then only needs to run the much cheaper `std::ecdsa_secp256k1::verify_signature` function using this public key as a private input.
* **Flexible Signer Management:** Instead of hardcoding a single Coinbase signer address, the circuit accepts a `signer_list_merkle_root` as a public input. This allows the dApp to maintain a flexible list of authorized Coinbase signers. If Coinbase rotates its keys, the dApp only needs to update its Merkle root, with no changes to the circuit required.

## Circuit Verification Logic

The `main` function executes a three-part verification to ensure the proof is valid:

1.  **Part 1: User Ownership Verification**
    * It cryptographically verifies that the prover (the person generating the proof) is the true owner of the private `user_address`.
    * It verifies that the user has consented to this specific proof request by checking their `user_signature` against the public `signal_hash`.

2.  **Part 2: On-Chain Fact Verification**
    * This is a critical security check to prove the `raw_transaction` is authentic.
    * First, it verifies that the provided `coinbase_attester_pubkey` (a private input) matches the signature on the `raw_transaction` using `verify_signature`. This proves the key *did* sign the transaction.
    * Second, it verifies that this *same* public key is a valid and authorized signer by checking its `coinbase_signer_merkle_proof` against the public `signer_list_merkle_root`.
    * This two-step process (verifying the signature, then verifying the signer) prevents an attacker from submitting a fake public key.
    * This verification relies on the constrained `eip1559_tx_parser` module to safely parse the EIP-1559 transaction.

3.  **Part 3: The Logical Link**
    * This part connects the verified user (Part 1) with the verified transaction (Part 2).
    * It checks the `to` address from the parsed transaction to ensure it was sent to the correct `COINBASE_ATTESTER_CONTRACT`.
    * It checks the `calldata` to ensure the correct function (`ATTEST_ACCOUNT_SELECTOR`) was called.
    * Finally, it asserts that the address *inside* the `calldata` is identical to the private `user_address` from Part 1.

## Inputs

### Public Inputs

* `signal_hash`: A unique anti-replay challenge hash provided by the dApp.
* `signer_list_merkle_root`: The Merkle root of the dApp's trusted list of Coinbase signer addresses.

### Private Inputs

* `user_address`: The prover's KYC'd wallet address.
* `user_signature`: The prover's signature (r, s) over the `signal_hash`.
* `user_pubkey_x`, `user_pubkey_y`: The prover's public key.
* `raw_transaction`, `tx_length`: The original, RLP-encoded EIP-1559 attestation transaction.
* `coinbase_attester_pubkey_x`, `coinbase_attester_pubkey_y`: The Coinbase signer's public key, pre-calculated via `ecrecover` in the client.
* `coinbase_signer_merkle_proof`, `coinbase_signer_leaf_index`, `merkle_proof_depth`: The Merkle proof path required to validate the Coinbase signer against the public root.