// Merkle Tree Proof Verification
//
// Provides keccak256-based Merkle proof verification for Ethereum compatibility.
// This is used to verify that a Coinbase signer address is in the authorized list.

use dep::keccak256::keccak256;

/// Verifies a Merkle proof using keccak256 hashing
///
/// # Arguments
/// * `leaf` - The leaf hash to verify (32 bytes)
/// * `leaf_index` - The index of the leaf in the tree
/// * `proof` - Array of sibling hashes for the proof path
/// * `depth` - The actual depth of the proof (number of levels to verify)
///
/// # Returns
/// The calculated Merkle root (32 bytes)
///
/// # Merkle Tree Structure
/// ```
///        root
///       /    \
///      h1    h2
///     / \    / \
///    l0 l1  l2 l3
/// ```
///
/// For leaf at index 1 (l1), proof = [l0, h2]
/// - Level 0: hash(l0 || l1) = h1
/// - Level 1: hash(h1 || h2) = root
///
/// # Implementation Notes
/// - Uses keccak256 for Ethereum compatibility
/// - Supports variable depth (up to max array size)
/// - Left/right sibling determined by index bit
pub fn verify_merkle_proof(
    leaf: [u8; 32],
    leaf_index: u32,
    proof: [[u8; 32]; 8],  // Max depth 8 (256 leaves)
    depth: u32
) -> [u8; 32] {
    let mut current_hash = leaf;
    let mut current_index = leaf_index;

    // Traverse up the tree, combining with siblings
    for i in 0..8 {
        if i < depth {
            let is_left = (current_index % 2) == 0;

            // Combine current hash with sibling
            let mut combined: [u8; 64] = [0; 64];

            if is_left {
                // Current is left child: current || sibling
                for j in 0..32 {
                    combined[j] = current_hash[j];
                    combined[32 + j] = proof[i][j];
                }
            } else {
                // Current is right child: sibling || current
                for j in 0..32 {
                    combined[j] = proof[i][j];
                    combined[32 + j] = current_hash[j];
                }
            }

            // Hash the combined value
            current_hash = keccak256(combined, 64);

            // Move to parent node
            current_index = current_index / 2;
        }
    }

    current_hash
}

/// Helper function to create a leaf hash from an address
/// This matches the format used by JavaScript Merkle tree libraries
///
/// # Arguments
/// * `address` - Ethereum address (20 bytes)
///
/// # Returns
/// Keccak256 hash of the address (32 bytes)
pub fn create_leaf_hash(address: [u8; 20]) -> [u8; 32] {
    keccak256(address, 20)
}

#[test]
fn test_merkle_proof_verification() {
    // Test case: Verify a simple 2-leaf tree
    // Leaves: [leaf0, leaf1]
    // Tree:
    //       root
    //      /    \
    //   leaf0  leaf1

    let leaf0: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ];

    let leaf1: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    ];

    // Proof for leaf0 (index 0): sibling is leaf1
    let mut proof: [[u8; 32]; 8] = [[0; 32]; 8];
    proof[0] = leaf1;

    let calculated_root = verify_merkle_proof(leaf0, 0, proof, 1);

    // Expected root = keccak256(leaf0 || leaf1)
    let mut combined: [u8; 64] = [0; 64];
    for i in 0..32 {
        combined[i] = leaf0[i];
        combined[32 + i] = leaf1[i];
    }
    let expected_root = keccak256(combined, 64);

    assert(calculated_root == expected_root);
}
