// ZKProofport: a GIWA attestation proof that authorizes ONE named action.
//
// Forked from coinbase_attestation, like the previous GIWA circuit, and then
// changed in the two places that were wrong.
//
// WHAT THE USER SIGNS
//
// An EIP-712 typed structure, not a 32-byte opaque hash. `personal_sign` over
// `signal_hash` shows the person a hex string, so they approve without seeing
// what they approve -- tolerable while a proof only says "this wallet is
// attested", not tolerable once the proof authorizes money moving. The wallet
// renders the named fields here, and the digest binds the verifying contract
// and the chain id through the domain separator.
//
// The circuit does NOT parse the structure and does not learn what the action
// is. It proves the attested key signed THIS domain and THIS struct hash.
// Whoever defined them recomputes the same two values and compares.
//
// TWO MODES, AND WHY THE CIRCUIT HAS TO KNOW ABOUT BOTH
//
// A request may or may not carry an action. The app has always been shaped
// that way -- one signing path that produces typed data when an action is
// present and a personal_sign over signal_hash when it is not -- and the
// circuit is what makes that real. `arc_eligibility` did NOT branch: it always
// requires the EIP-712 signature, so a request without an action builds a
// vector 64 bytes short and the prover dies with a message naming none of it.
//
// There is no null in a circuit. Every public input is always present, so an
// absent action is 32 zero bytes, and the two modes are made MUTUALLY
// EXCLUSIVE here: with an action, signal_hash must be empty; without one, the
// domain and action hashes must be. A verifier reading the public inputs can
// therefore tell which mode it was handed, instead of guessing -- and a proof
// made without an action cannot be presented as one that authorized something.
//
// WHAT signal_hash IS NOT ANY MORE
//
// It is not part of the nullifier. In `arc_eligibility` it is, which is the
// defect this circuit does not copy: nobody signs it there and nothing
// constrains it, so a prover wanting a second identity for the same wallet and
// scope only had to pass different bytes. Here it is a dApp challenge and
// nothing else. Replay protection for an action belongs in the signed
// structure -- a nonce and an expiry the wallet displays and the verifying
// contract records.
//
// THE NULLIFIER
//
// keccak(keccak(user_address ++ CIRCUIT_TAG) ++ scope), with CIRCUIT_TAG
// compiled in. One wallet in one scope has exactly one nullifier and there is
// no input to vary. The tag is this circuit's name, so the same wallet proving
// something else elsewhere is not linkable to this proof.

use dep::std;
use dep::keccak256::keccak256;
use dep::coinbase_libs::eip1559_tx_parser;
use dep::coinbase_libs::merkle;
use dep::coinbase_libs::nullifier::verify_wallet_nullifier;
use dep::coinbase_libs::signed_message::signed_digest;
use dep::coinbase_libs::ethereum::derive_address_from_pubkey;

/// MockGiwaAttester address on GIWA Sepolia (the 'to' address of the attest tx).
/// 0x6646d970499BBeD728636823A5A7e551E811b414
global GIWA_ATTESTER_CONTRACT: [u8; 20] = [
    0x66, 0x46, 0xd9, 0x70, 0x49, 0x9B, 0xBe, 0xD7,
    0x28, 0x63, 0x68, 0x23, 0xA5, 0xA7, 0xe5, 0x51,
    0xE8, 0x11, 0xb4, 0x14
];

/// Function selector for "attestAccount(address)" -- 0x56feed5e
global ATTEST_ACCOUNT_SELECTOR: [u8; 4] = [0x56, 0xfe, 0xed, 0x5e];

/// keccak256("giwa_attestation"). Compiled in, never supplied: this is the
/// half of the nullifier's secret preimage that used to be a free input.
global CIRCUIT_TAG: [u8; 32] = [
    0xbb, 0xe9, 0xbf, 0x6a, 0x49, 0x13, 0xc0, 0xc3,
    0x02, 0xcb, 0x2a, 0x16, 0x28, 0x8d, 0xcc, 0x91,
    0x73, 0x08, 0xee, 0x9a, 0x2a, 0xc3, 0x7b, 0xb6,
    0xc8, 0x23, 0xb8, 0x60, 0xe1, 0x5c, 0x79, 0x13,
];

fn main(
    // ============ Public Inputs ============

    // The dApp's challenge, signed with personal_sign when no action is bound.
    // All zeros in action mode. NOT part of the nullifier, in either mode.
    signal_hash: pub [u8; 32],

    // EIP-712 domain: hashStruct of name, version, chainId, verifyingContract.
    // The verifying contract recomputes its own and refuses a mismatch, which
    // is what stops a signature made for one contract reaching another.
    // All zeros when no action is bound.
    domain_separator: pub [u8; 32],

    // The action, as EIP-712's hashStruct of the signed structure. Opaque
    // here on purpose -- whoever defined the structure recomputes this.
    // All zeros when no action is bound.
    action_hash: pub [u8; 32],

    // Root of the dApp's current list of accepted GIWA attester addresses.
    signer_list_merkle_root: pub [u8; 32],

    // Sybil domain. One nullifier per (wallet, scope).
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
    // PART 1: this wallet signed THIS message, and the signature is real
    // ===================================================================

    // The public key is the prover's claim; the address is what the rest of
    // the circuit reasons about. Without this they can be two different
    // people.
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

    let mut attester_signature: [u8; 64] = [0; 64];
    for i in 0..64 {
        attester_signature[i] = tx_signature[i];
    }

    let valid_attester_sig = std::ecdsa_secp256k1::verify_signature(
        coinbase_attester_pubkey_x,
        coinbase_attester_pubkey_y,
        attester_signature,
        unsigned_tx_hash
    );
    assert(valid_attester_sig, "Invalid TX signature");

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
    assert(to_address == GIWA_ATTESTER_CONTRACT, "TX sent to wrong contract");

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
