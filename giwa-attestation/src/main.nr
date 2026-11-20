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
// circuit is what makes that real. A circuit that does NOT branch -- one that
// always requires the EIP-712 signature -- turns a request without an action
// into a vector 64 bytes short, and the prover dies with a message naming none
// of it.
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
// It is not part of the nullifier. Deriving the nullifier from it is a defect
// this circuit deliberately avoids: in action mode nobody signs signal_hash and
// nothing constrains it, so a prover wanting a second identity for the same
// wallet and scope would only have to pass different bytes. Here it is a dApp challenge and
// nothing else. Replay protection for an action belongs in the signed
// structure -- a nonce and an expiry the wallet displays and the verifying
// contract records.
//
// THE NULLIFIER
//
// The OPRF nullifier (../oprf-nullifier-libs): Poseidon2 of the query
// (address, domain, scope) and the OPRF nodes' answer, whose Chaum-Pedersen
// proof the circuit checks. One wallet in one (domain, scope) has exactly one
// nullifier under the key, there is no input to vary, and nobody without the
// key can compute it from an address -- the keccak nullifier this circuit had
// before could be recomputed for every attested address. The key is this proof
// type's own (its hash is public), so the same wallet proving something else
// elsewhere is not linkable to this proof.

use oprf_nullifier_libs::{OprfAnswer, verify_oprf_nullifier};
use std;
use keccak256::keccak256;
use coinbase_libs::eip1559_tx_parser;
use coinbase_libs::merkle;
use coinbase_libs::signed_message::signed_digest;
use coinbase_libs::ethereum::derive_address_from_pubkey;

/// MockGiwaAttester address on GIWA Sepolia (the 'to' address of the attest tx).
/// 0x6646d970499BBeD728636823A5A7e551E811b414
global GIWA_ATTESTER_CONTRACT: [u8; 20] = [
    0x66, 0x46, 0xd9, 0x70, 0x49, 0x9B, 0xBe, 0xD7,
    0x28, 0x63, 0x68, 0x23, 0xA5, 0xA7, 0xe5, 0x51,
    0xE8, 0x11, 0xb4, 0x14
];

/// Function selector for "attestAccount(address)" -- 0x56feed5e
global ATTEST_ACCOUNT_SELECTOR: [u8; 4] = [0x56, 0xfe, 0xed, 0x5e];

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

    // The OPRF nullifier (../oprf-nullifier-libs): the hash of the OPRF key the
    // verifier pins for this proof type, the nullifier's domain and scope
    // (keccak256(string) mod p each), and the nullifier -- one per wallet per
    // (domain, scope) under that key, which nobody without the key can compute
    // from an address.
    oprf_key_hash: pub Field,
    domain: pub Field,
    scope: pub Field,
    nullifier: pub Field,

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
    // The OPRF nodes' answer for this wallet's query, and the blinding factor
    // (private; ../oprf-nullifier-libs checks them).
    oprf_public_key_x: Field,
    oprf_public_key_y: Field,
    oprf_beta: Field,
    oprf_dlog_e: Field,
    oprf_dlog_s: Field,
    oprf_response_x: Field,
    oprf_response_y: Field,
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
    // PART 4: one nullifier per wallet per (domain, scope), from the OPRF
    // ===================================================================

    verify_oprf_nullifier(
        user_address,
        domain,
        scope,
        oprf_key_hash,
        nullifier,
        OprfAnswer {
            public_key_x: oprf_public_key_x,
            public_key_y: oprf_public_key_y,
            beta: oprf_beta,
            dlog_e: oprf_dlog_e,
            dlog_s: oprf_dlog_s,
            response_x: oprf_response_x,
            response_y: oprf_response_y,
        },
    );
}
