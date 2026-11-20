// ZKProofport: Dojang Playground.
//
// Shows the GIWA Dojang flow -- QR, app, wallet signature, proof, dApp
// verify -- using the attestation anyone can issue to themselves from the
// GIWA Playground. It is a demonstration of the flow, not a credential.
//
// WHAT IT PROVES
//
// 1. The wallet signed this request (a signal hash, or an EIP-712 action --
//    the same two modes as giwa_attestation, mutually exclusive).
// 2. The SAME key signed a GIWA Sepolia transaction calling
//    `payAndIssueEAS()` on the Playground faucet, which is the call that
//    issues the Dojang "Verified Address" attestation to its sender.
// 3. One nullifier per wallet per (domain, scope): the OPRF nullifier
//    (../oprf-nullifier-libs).
//
// WHAT IT DOES NOT PROVE, AND WHY THAT WAS CHOSEN
//
// The faucet transaction is signed by the user, not by an issuer. In
// giwa_attestation the issuer's signature is what carries trust; here a
// signature by the user only shows the user could have sent it. Proving the
// attestation actually exists would need a storage proof against a GIWA block
// (EAS slot, account and storage MPT proofs; see circuits-dev.md), several
// times this circuit's size. Decided 2026-10-14 to keep this to the flow
// and not build that. So there is no issuer list, no signer Merkle root, and
// no check that the transaction was included or succeeded -- whoever builds
// the inputs looks the transaction up on chain, and that lookup is outside
// the proof.

use oprf_nullifier_libs::{OprfAnswer, verify_oprf_nullifier};
use std;
use coinbase_libs::signed_message::signed_digest;
use coinbase_libs::ethereum::derive_address_from_pubkey;
use coinbase_libs::signed_tx::{parse_signed_tx, MAX_TX_LEN};

/// GIWA Sepolia.
global GIWA_SEPOLIA_CHAIN_ID: u64 = 91342;

/// GIWAFaucetExtension, the Playground issuing contract on GIWA Sepolia.
/// 0x63CCe2b569A7bC35895ee24306c1512fefc06121
global PLAYGROUND_FAUCET: [u8; 20] = [
    0x63, 0xCC, 0xe2, 0xb5, 0x69, 0xA7, 0xbC, 0x35,
    0x89, 0x5e, 0xe2, 0x43, 0x06, 0xc1, 0x51, 0x2f,
    0xef, 0xc0, 0x61, 0x21
];

/// payAndIssueEAS() -- 0xb19e5904. Takes no arguments: the recipient is the sender.
global PAY_AND_ISSUE_SELECTOR: [u8; 4] = [0xb1, 0x9e, 0x59, 0x04];

fn main(
    // ============ Public Inputs ============

    // The dApp's challenge, personal_signed when no action is bound; zero otherwise.
    signal_hash: pub [u8; 32],
    // EIP-712 domain separator; zero when no action is bound.
    domain_separator: pub [u8; 32],
    // EIP-712 hashStruct of the action; zero when no action is bound.
    action_hash: pub [u8; 32],
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
    user_signature: [u8; 64], // r ++ s
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],

    // The faucet transaction, legacy or EIP-1559, zero-padded.
    raw_transaction: [u8; MAX_TX_LEN],
    tx_length: u32,
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
    // PART 1: this wallet signed this request
    let derived_user_address = derive_address_from_pubkey(user_pubkey_x, user_pubkey_y);
    assert(derived_user_address == user_address, "User pubkey does not match address");

    let message_hash = signed_digest(signal_hash, domain_separator, action_hash);
    let valid_user_sig = std::ecdsa_secp256k1::verify_signature(
        user_pubkey_x,
        user_pubkey_y,
        user_signature,
        message_hash,
    );
    assert(valid_user_sig, "Invalid user signature on the signed message");

    // PART 2: the same key signed the Playground issuance on GIWA Sepolia
    let tx = parse_signed_tx(raw_transaction, tx_length, GIWA_SEPOLIA_CHAIN_ID);
    let valid_tx_sig = std::ecdsa_secp256k1::verify_signature(
        user_pubkey_x,
        user_pubkey_y,
        tx.signature,
        tx.unsigned_hash,
    );
    assert(valid_tx_sig, "Issuance transaction was not signed by this wallet");

    assert(tx.to == PLAYGROUND_FAUCET, "Transaction is not to the Playground faucet");
    assert(tx.data_length == 4, "Calldata is not a bare payAndIssueEAS() call");
    assert(tx.selector == PAY_AND_ISSUE_SELECTOR, "Transaction does not call payAndIssueEAS()");

    // PART 3: one nullifier per wallet per (domain, scope), from the OPRF
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
