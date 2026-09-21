use dep::keccak256::keccak256;

/// Verify that the nullifier is correctly derived from user_address, signal_hash, and scope.
/// Formula:
///   user_secret = keccak256(user_address[20] ++ signal_hash[32])
///   expected_nullifier = keccak256(user_secret[32] ++ scope[32])
///   assert(nullifier == expected_nullifier)
pub fn verify_nullifier(
    user_address: [u8; 20],
    signal_hash: [u8; 32],
    scope: [u8; 32],
    nullifier: [u8; 32],
) {
    // Compute user_secret = keccak256(user_address ++ signal_hash)
    let mut secret_preimage: [u8; 52] = [0; 52];
    for i in 0..20 {
        secret_preimage[i] = user_address[i];
    }
    for i in 0..32 {
        secret_preimage[20 + i] = signal_hash[i];
    }
    let user_secret: [u8; 32] = keccak256(secret_preimage, 52);

    // Compute expected_nullifier = keccak256(user_secret ++ scope)
    let mut nullifier_preimage: [u8; 64] = [0; 64];
    for i in 0..32 {
        nullifier_preimage[i] = user_secret[i];
    }
    for i in 0..32 {
        nullifier_preimage[32 + i] = scope[i];
    }
    let expected_nullifier: [u8; 32] = keccak256(nullifier_preimage, 64);

    // Assert the provided nullifier matches
    assert(nullifier == expected_nullifier, "Nullifier mismatch");
}


/// Verify a nullifier whose secret material is the wallet address and a
/// COMPILE-TIME circuit tag -- nothing the prover supplies.
///
/// WHY THIS EXISTS, next to the function above.
///
/// `verify_nullifier` takes `signal_hash` as the second half of the secret
/// preimage. Off-circuit, every caller computes that value as
/// keccak(address ++ scope_string ++ circuit_name), so one wallet in one scope
/// maps to one nullifier -- but NOTHING ENFORCES IT. The circuit does not
/// recompute it, and a verifier cannot: the address is a private input, so
/// there is nothing to recompute it from. A prover who wants a second identity
/// for the same wallet and the same scope just passes different bytes.
///
/// In `coinbase_attestation` the wallet at least signs `signal_hash`, which is
/// no barrier -- the signer is the prover -- but it is a constraint. In
/// `arc_eligibility` the signature moved to the EIP-712 action and the value
/// became a free public input that still decides the nullifier.
///
/// Here the second half is a constant compiled into the circuit. There is no
/// input to choose, so the one-per-(wallet, scope) property holds by
/// construction rather than by everyone agreeing to compute the same hash.
///
/// The tag differs per circuit on purpose: the same wallet proving two
/// different things produces two unrelated nullifiers, and neither can be used
/// to link the person across circuits.
///
/// Formula:
///   user_secret = keccak256(user_address[20] ++ circuit_tag[32])
///   nullifier   = keccak256(user_secret[32] ++ scope[32])
pub fn verify_wallet_nullifier(
    user_address: [u8; 20],
    circuit_tag: [u8; 32],
    scope: [u8; 32],
    nullifier: [u8; 32],
) {
    let mut secret_preimage: [u8; 52] = [0; 52];
    for i in 0..20 {
        secret_preimage[i] = user_address[i];
    }
    for i in 0..32 {
        secret_preimage[20 + i] = circuit_tag[i];
    }
    let user_secret: [u8; 32] = keccak256(secret_preimage, 52);

    let mut nullifier_preimage: [u8; 64] = [0; 64];
    for i in 0..32 {
        nullifier_preimage[i] = user_secret[i];
    }
    for i in 0..32 {
        nullifier_preimage[32 + i] = scope[i];
    }
    let expected: [u8; 32] = keccak256(nullifier_preimage, 64);

    assert(nullifier == expected, "Nullifier mismatch");
}
