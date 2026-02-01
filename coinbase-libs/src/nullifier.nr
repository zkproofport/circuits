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
