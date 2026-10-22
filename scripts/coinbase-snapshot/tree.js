/**
 * The snapshot tree, shared by the builder, the fixture generator and anyone
 * re-deriving a published root. Nothing here reads the network.
 *
 *   leaf  = Poseidon1(address as a field element)
 *   node  = Poseidon2(left, right)
 *   empty = 0 at the leaves, and Poseidon2(empty, empty) one level up
 *
 * Addresses are sorted ascending as 160-bit integers and placed left to right
 * from index 0. Poseidon is the circom BN254 instance (poseidon-lite), which is
 * what circuits/deps/poseidon's bn254 hash_1/hash_2 compute.
 */
const { poseidon1, poseidon2 } = require('poseidon-lite');

function sortAddresses(addresses) {
  const unique = [...new Set(addresses.map(a => a.toLowerCase()))];
  return unique.map(a => BigInt(a)).sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
}

function zeroHashes(depth) {
  const z = [0n];
  for (let i = 0; i < depth; i++) z.push(poseidon2([z[i], z[i]]));
  return z;
}

/** Every level of the tree, bottom first; levels hold only the non-empty prefix. */
function buildLevels(sortedAddresses, depth) {
  if (sortedAddresses.length > 2 ** depth) {
    throw new Error(`${sortedAddresses.length} addresses do not fit a depth-${depth} tree`);
  }
  const zeros = zeroHashes(depth);
  const levels = [sortedAddresses.map(a => poseidon1([a]))];
  for (let d = 0; d < depth; d++) {
    const below = levels[d];
    const up = [];
    for (let i = 0; i < below.length; i += 2) {
      up.push(poseidon2([below[i], i + 1 < below.length ? below[i + 1] : zeros[d]]));
    }
    levels.push(up);
  }
  const root = levels[depth].length ? levels[depth][0] : zeros[depth];
  return { levels, zeros, root };
}

/** Siblings bottom-up, and the index bits (bit d = 1 when the node is a right child). */
function pathOf(tree, index, depth) {
  const siblings = [];
  const bits = [];
  let i = index;
  for (let d = 0; d < depth; d++) {
    const level = tree.levels[d];
    const sib = i ^ 1;
    siblings.push(sib < level.length ? level[sib] : tree.zeros[d]);
    bits.push(i & 1);
    i >>= 1;
  }
  return { siblings, bits };
}

module.exports = { sortAddresses, buildLevels, pathOf, zeroHashes };
