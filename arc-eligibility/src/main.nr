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
// AN ACTION IS OPTIONAL, AND THE CIRCUIT IS WHAT MAKES IT SO
//
// This circuit used to require one: it computed the EIP-712 digest and nothing
// else, so a request without an action built a vector 64 bytes short and the
// prover died with a message naming none of it. The app's signing helper had
// always been shaped for both, which is what made the requirement look like a
// choice somebody had made rather than one nobody had.
//
// Now the mode is chosen from the inputs, by the same rule `giwa_attestation`
// uses -- one definition, in coinbase_libs::signed_message. With an action the
// wallet signs the typed data and `signal_hash` must be empty; without one it
// personal_signs `signal_hash` and the EIP-712 pair must be empty.
//
// THE NULLIFIER NO LONGER COMES FROM signal_hash
//
// It could not survive the branch. `signal_hash` is zero in action mode, so a
// nullifier derived from it would differ between the two modes -- the same
// wallet, the same scope, two identities, which is the exact property the
// nullifier exists to provide.
//
// It should not have survived anyway: nothing constrains `signal_hash`, and
// in action mode nobody even signs it, so a prover wanting a second identity
// only had to pass different bytes. The secret is now the address and a
// constant compiled in below.

use dep::std;
use dep::keccak256::keccak256;
use dep::coinbase_libs::eip1559_tx_parser;
use dep::coinbase_libs::merkle;
use dep::coinbase_libs::ethereum::{
    COINBASE_ATTESTER_CONTRACT,
    derive_address_from_pubkey,
};
use dep::coinbase_libs::nullifier::verify_wallet_nullifier;
use dep::coinbase_libs::signed_message::signed_digest;

/// keccak256("arc_eligibility"). Compiled in, never supplied: this is the half
/// of the nullifier's secret preimage that used to be a free public input.
global CIRCUIT_TAG: [u8; 32] = [
    0x73, 0xf6, 0xd0, 0xaa, 0x36, 0xcd, 0xc2, 0x56,
    0xe0, 0xda, 0x6a, 0xca, 0xda, 0x12, 0xb1, 0x54,
    0x19, 0xb4, 0x23, 0xb3, 0x03, 0xac, 0x05, 0x25,
    0x4c, 0xc7, 0x6d, 0x2c, 0xd8, 0x9d, 0x85, 0x1b,
];

// Function selector for "attestAccount(address)" -- 0x56feed5e
global ATTEST_ACCOUNT_SELECTOR: [u8; 4] = [0x56, 0xfe, 0xed, 0x5e];

fn main(
    // ============ Public Inputs ============

    // The dApp's challenge, signed with personal_sign when no action is
    // bound. All zeros in action mode. NOT part of the nullifier.
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

    // keccak(keccak(user_address ++ CIRCUIT_TAG) ++ scope)
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
    // PART 1: the KYC'd key signed THIS message -- an action, or the challenge
    // ===================================================================

    let derived_user_address = derive_address_from_pubkey(user_pubkey_x, user_pubkey_y);
    assert(derived_user_address == user_address, "User pubkey does not match address");

    let message_hash = signed_digest(signal_hash, domain_separator, action_hash);
    let valid_user_sig = std::ecdsa_secp256k1::verify_signature(
        user_pubkey_x,
        user_pubkey_y,
        user_signature,
        message_hash
    );
    assert(valid_user_sig, "Invalid user signature on the signed message");

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
    // PART 4: one nullifier per wallet per scope, with nothing to choose
    // ===================================================================

    verify_wallet_nullifier(user_address, CIRCUIT_TAG, scope, nullifier);
}
