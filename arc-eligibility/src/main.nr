// ZKProofport: a Coinbase-KYC proof that authorizes ONE named action.
//
// This is `coinbase_attestation` with ONE thing changed: what the user signs.
// The nullifier, the attester check, the Merkle set, the RLP parse and the
// calldata link are byte-for-byte the same logic, deliberately, because they
// are already deployed and exercised.
//
// WHAT CHANGED, AND WHY
//
// `coinbase_attestation` has the user sign `signal_hash`, which is
// keccak256(address, scopeString, circuitName). Two consequences follow from
// that value being the same for a given wallet and scope no matter what the
// proof is later used for:
//
//   - It commits to no contract, amount, caller, ordering or deadline. A proof
//     produced for one vault verifies just as well at another.
//   - The wallet has nothing to display. `personal_sign` over 32 opaque bytes
//     shows the person a hex string, so they approve without seeing what they
//     approve. That is tolerable while a proof only says "this wallet is
//     KYC'd". It is not tolerable once an agent moves money with it.
//
// Here the user signs an EIP-712 typed structure instead. The wallet renders
// the named fields, and the digest binds the verifying contract and chain id
// through the domain separator.
//
// The circuit does NOT parse the structure and does not know what the action
// is -- a deposit, a grant of authority, an agreement in prose. It proves the
// KYC'd key signed this domain and this struct hash. Whoever defined them
// recomputes the same two values and compares. That keeps the circuit generic:
// nothing about vaults or USDC is baked in here.
//
// `signal_hash` stays a public input even though nobody signs it any more,
// because the nullifier derives from it. Deriving the nullifier from the
// signed action instead would give a different nullifier per action and
// destroy the one-per-person property it exists for.

use dep::std;
use dep::keccak256::keccak256;
use dep::coinbase_libs::eip1559_tx_parser;
use dep::coinbase_libs::merkle;
use dep::coinbase_libs::ethereum::{
    COINBASE_ATTESTER_CONTRACT,
    derive_address_from_pubkey,
    create_eip712_digest,
};

// Function selector for "attestAccount(address)" -- 0x56feed5e
global ATTEST_ACCOUNT_SELECTOR: [u8; 4] = [0x56, 0xfe, 0xed, 0x5e];

fn main(
    // ============ Public Inputs ============

    // keccak256(address, scopeString, circuitName). Nobody signs this; the
    // nullifier is derived from it, exactly as on Base.
    signal_hash: pub [u8; 32],

    // EIP-712 domain: hashStruct of name, version, chainId, verifyingContract.
    // The verifier recomputes its own and refuses a mismatch, which is what
    // stops a signature made for one contract reaching another.
    domain_separator: pub [u8; 32],

    // The action, as EIP-712's hashStruct of the signed structure.
    // Opaque here on purpose: whoever defined the structure recomputes this
    // and compares. The circuit never learns whether it is a deposit, a grant
    // of authority or an agreement in prose.
    action_hash: pub [u8; 32],

    // Root of the dApp's current list of accepted Coinbase attester addresses.
    signer_list_merkle_root: pub [u8; 32],

    // Sybil domain. One nullifier per (person, scope).
    scope: pub [u8; 32],

    // keccak256(keccak256(user_address ++ signal_hash) ++ scope)
    nullifier: pub [u8; 32],

    // ============ Private Inputs ============

    user_address: [u8; 20],
    user_signature: [u8; 64],  // r ++ s, no v
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],

    raw_transaction: [u8; 300],
    tx_length: u32,
    coinbase_attester_pubkey_x: [u8; 32],
    coinbase_attester_pubkey_y: [u8; 32],
    coinbase_signer_merkle_proof: [[u8; 32]; 8],
    coinbase_signer_leaf_index: u32,
    merkle_proof_depth: u32,
) {
    // ===================================================================
    // PART 1: the KYC'd key authorized THIS action, on THIS contract
    // ===================================================================

    let derived_user_address = derive_address_from_pubkey(user_pubkey_x, user_pubkey_y);
    assert(derived_user_address == user_address, "User pubkey does not match address");

    let message_hash = create_eip712_digest(domain_separator, action_hash);
    let valid_user_sig = std::ecdsa_secp256k1::verify_signature(
        user_pubkey_x,
        user_pubkey_y,
        user_signature,
        message_hash
    );
    assert(valid_user_sig, "Invalid user signature on typed action");

    // ===================================================================
    // PART 2: the attestation transaction is real, and signed by an
    //         attester the dApp accepts
    // ===================================================================

    let unsigned_tx_hash = eip1559_tx_parser::create_unsigned_tx_hash(raw_transaction, tx_length);
    let tx_signature = eip1559_tx_parser::extract_signature_from_tx(raw_transaction);

    let mut coinbase_signature: [u8; 64] = [0; 64];
    for i in 0..64 {
        coinbase_signature[i] = tx_signature[i];
    }

    let valid_coinbase_sig = std::ecdsa_secp256k1::verify_signature(
        coinbase_attester_pubkey_x,
        coinbase_attester_pubkey_y,
        coinbase_signature,
        unsigned_tx_hash
    );
    assert(valid_coinbase_sig, "Invalid TX signature");

    // The attester pubkey is supplied by the prover, so on its own it proves
    // nothing. It becomes trustworthy only because the signature above
    // verifies against it AND the address it derives to is in the approved set.
    let derived_signer_address = derive_address_from_pubkey(
        coinbase_attester_pubkey_x,
        coinbase_attester_pubkey_y
    );
    let leaf_hash = keccak256(derived_signer_address, 20);
    let calculated_root = merkle::verify_merkle_proof(
        leaf_hash,
        coinbase_signer_leaf_index,
        coinbase_signer_merkle_proof,
        merkle_proof_depth
    );
    assert(calculated_root == signer_list_merkle_root, "Signer not in valid list");

    // ===================================================================
    // PART 3: that transaction is about THIS user
    // ===================================================================

    let to_address = eip1559_tx_parser::extract_to_address(raw_transaction);
    assert(to_address == COINBASE_ATTESTER_CONTRACT, "TX sent to wrong contract");

    let calldata = eip1559_tx_parser::extract_calldata(raw_transaction);
    let mut selector: [u8; 4] = [0; 4];
    for i in 0..4 {
        selector[i] = calldata[i];
    }
    assert(selector == ATTEST_ACCOUNT_SELECTOR, "Invalid function selector");

    let calldata_address = eip1559_tx_parser::extract_address_from_calldata(calldata);
    assert(calldata_address == user_address, "Calldata address does not match user_address");

    // ===================================================================
    // PART 4: one action per person per scope -- identical to Base
    // ===================================================================

    coinbase_libs::nullifier::verify_nullifier(user_address, signal_hash, scope, nullifier);
}
