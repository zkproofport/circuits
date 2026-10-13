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
// 3. One nullifier per wallet per scope.
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

use dep::std;
use dep::coinbase_libs::nullifier::verify_wallet_nullifier;
use dep::coinbase_libs::signed_message::signed_digest;
use dep::coinbase_libs::ethereum::derive_address_from_pubkey;
use dep::coinbase_libs::signed_tx::{parse_signed_tx, MAX_TX_LEN};

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

/// keccak256("dojang_playground"), compiled in so no input can move the nullifier.
global CIRCUIT_TAG: [u8; 32] = [
    0x3e, 0x28, 0x69, 0xcc, 0xf9, 0x1d, 0x1b, 0xce,
    0x22, 0xfb, 0x34, 0xa3, 0x24, 0xb4, 0x35, 0xf3,
    0x7e, 0xd3, 0x12, 0xbf, 0x71, 0x23, 0x47, 0x67,
    0x82, 0x43, 0xe9, 0x98, 0xe3, 0x3f, 0xab, 0xfe,
];

fn main(
    // ============ Public Inputs ============

    // The dApp's challenge, personal_signed when no action is bound; zero otherwise.
    signal_hash: pub [u8; 32],
    // EIP-712 domain separator; zero when no action is bound.
    domain_separator: pub [u8; 32],
    // EIP-712 hashStruct of the action; zero when no action is bound.
    action_hash: pub [u8; 32],
    // Sybil domain. One nullifier per (wallet, scope).
    scope: pub [u8; 32],
    // keccak(keccak(user_address ++ CIRCUIT_TAG) ++ scope)
    nullifier: pub [u8; 32],

    // ============ Private Inputs ============

    user_address: [u8; 20],
    user_signature: [u8; 64], // r ++ s
    user_pubkey_x: [u8; 32],
    user_pubkey_y: [u8; 32],

    // The faucet transaction, legacy or EIP-1559, zero-padded.
    raw_transaction: [u8; MAX_TX_LEN],
    tx_length: u32,
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

    // PART 3: one nullifier per wallet per scope
    verify_wallet_nullifier(user_address, CIRCUIT_TAG, scope, nullifier);
}
