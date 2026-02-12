//! Merkle tree operations for commitment membership proofs.
//!
//! Uses Rescue Prime (Rp64_256) for internal hashing, matching the zk-STARK
//! circuit. This ensures the Merkle paths verified on-chain are the same ones
//! proven inside the STARK proof.
//!
//! The commitment tree has a canonical depth of MERKLE_DEPTH (20), supporting
//! up to ~1M commitments. Trees with fewer leaves are padded with zero-subtree
//! hashes so that all Merkle paths have uniform depth.

use serde::{Deserialize, Serialize};

use crate::crypto::stark::convert::{felts_to_hash, hash_to_felts, Felt};
use crate::crypto::stark::rescue;
use crate::crypto::stark::spend_air::MERKLE_DEPTH;
use crate::Hash;

/// A node in a Merkle authentication path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleNode {
    pub hash: Hash,
    /// True if this sibling is on the left (current node is right child).
    pub is_left: bool,
}

/// Compute a Merkle root from a leaf and authentication path using Rescue Prime.
pub fn compute_merkle_root(leaf: &Hash, path: &[MerkleNode]) -> Hash {
    let mut current = hash_to_felts(leaf);
    for node in path {
        let sibling = hash_to_felts(&node.hash);
        current = if node.is_left {
            rescue::hash_merge(&sibling, &current)
        } else {
            rescue::hash_merge(&current, &sibling)
        };
    }
    felts_to_hash(&current)
}

/// Build a Merkle tree from leaf hashes and return (root, paths).
///
/// The tree is padded to the next power of 2 with zero leaves.
/// All hashing uses Rescue Prime for STARK compatibility.
pub fn build_merkle_tree(leaves: &[Hash]) -> (Hash, Vec<Vec<MerkleNode>>) {
    if leaves.is_empty() {
        return ([0u8; 32], vec![]);
    }
    if leaves.len() == 1 {
        return (leaves[0], vec![vec![]]);
    }

    // Pad to next power of 2
    let n = leaves.len().next_power_of_two();
    let mut layer: Vec<Hash> = leaves.to_vec();
    layer.resize(n, [0u8; 32]);

    let mut all_layers = vec![layer.clone()];

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks(2) {
            let left = hash_to_felts(&chunk[0]);
            let right = hash_to_felts(&chunk[1]);
            let merged = rescue::hash_merge(&left, &right);
            next.push(felts_to_hash(&merged));
        }
        all_layers.push(next.clone());
        layer = next;
    }

    let root = layer[0];

    // Build authentication paths for each original leaf
    let mut paths = Vec::with_capacity(leaves.len());
    for i in 0..leaves.len() {
        let mut path = Vec::new();
        let mut idx = i;
        for layer in &all_layers[..all_layers.len() - 1] {
            let sibling_idx = idx ^ 1;
            if sibling_idx < layer.len() {
                path.push(MerkleNode {
                    hash: layer[sibling_idx],
                    is_left: idx % 2 == 1,
                });
            }
            idx /= 2;
        }
        paths.push(path);
    }

    (root, paths)
}

/// Precomputed zero-subtree hashes for each level.
///
/// `zero_subtree[0]` = hash of empty leaf = [0; 32]
/// `zero_subtree[n]` = merge(zero_subtree[n-1], zero_subtree[n-1])
fn zero_subtree_hashes() -> Vec<Hash> {
    let mut hashes = Vec::with_capacity(MERKLE_DEPTH + 1);
    hashes.push([0u8; 32]); // Level 0: empty leaf
    for _ in 1..=MERKLE_DEPTH {
        let prev = hash_to_felts(hashes.last().unwrap());
        let merged = rescue::hash_merge(&prev, &prev);
        hashes.push(felts_to_hash(&merged));
    }
    hashes
}

/// Pad a Merkle path to the canonical depth (MERKLE_DEPTH = 20).
///
/// Extends the path with zero-subtree siblings on the right side.
/// This produces a depth-20 canonical root from any shallower tree.
pub fn pad_merkle_path(path: &[MerkleNode], target_depth: usize) -> Vec<MerkleNode> {
    let mut padded = path.to_vec();
    let zero_hashes = zero_subtree_hashes();
    let current_depth = padded.len();
    for zero_hash in &zero_hashes[current_depth..target_depth] {
        padded.push(MerkleNode {
            hash: *zero_hash,
            is_left: false, // zero subtree is on the right, current on the left
        });
    }
    padded
}

/// Compute the canonical depth-20 Merkle root from a shallower root.
///
/// Extends the root hash through padding levels with zero-subtree hashes.
pub fn canonical_root(root: &Hash, tree_depth: usize) -> Hash {
    let zero_hashes = zero_subtree_hashes();
    let mut current = hash_to_felts(root);
    for zero_hash in &zero_hashes[tree_depth..MERKLE_DEPTH] {
        let zero = hash_to_felts(zero_hash);
        current = rescue::hash_merge(&current, &zero);
    }
    felts_to_hash(&current)
}

/// Convert a MerkleNode path to STARK witness format: Vec<([Felt; 4], bool)>.
///
/// `is_left` in MerkleNode (sibling on left) maps to `is_right` in STARK witness
/// (current on right). They represent the same boolean.
pub fn path_to_stark_witness(path: &[MerkleNode]) -> Vec<([Felt; 4], bool)> {
    path.iter()
        .map(|node| {
            let felts = hash_to_felts(&node.hash);
            (felts, node.is_left) // is_left == is_right for current hash
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::commitment::{BlindingFactor, Commitment};

    #[test]
    fn merkle_tree_single_leaf() {
        let c = Commitment::commit(100, &BlindingFactor::random());
        let (root, paths) = build_merkle_tree(&[c.0]);
        assert_eq!(root, c.0);
        assert_eq!(paths.len(), 1);
        assert!(paths[0].is_empty());
    }

    #[test]
    fn merkle_tree_two_leaves() {
        let c0 = Commitment::commit(100, &BlindingFactor::random());
        let c1 = Commitment::commit(200, &BlindingFactor::random());
        let (root, paths) = build_merkle_tree(&[c0.0, c1.0]);

        assert_eq!(compute_merkle_root(&c0.0, &paths[0]), root);
        assert_eq!(compute_merkle_root(&c1.0, &paths[1]), root);
    }

    #[test]
    fn merkle_tree_many_leaves() {
        let leaves: Vec<Hash> = (0..8u64)
            .map(|i| Commitment::commit(i * 100, &BlindingFactor::from_bytes([i as u8; 32])).0)
            .collect();
        let (root, paths) = build_merkle_tree(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            assert_eq!(compute_merkle_root(leaf, &paths[i]), root);
        }
    }

    #[test]
    fn pad_merkle_path_extends_correctly() {
        let c = Commitment::commit(500, &BlindingFactor::random());
        let (root, paths) = build_merkle_tree(&[c.0, [0u8; 32]]);

        // Tree has depth 1
        assert_eq!(paths[0].len(), 1);

        // Pad to depth 20
        let padded = pad_merkle_path(&paths[0], MERKLE_DEPTH);
        assert_eq!(padded.len(), MERKLE_DEPTH);

        // The padded root should match canonical_root
        let padded_root = compute_merkle_root(&c.0, &padded);
        let canon_root = canonical_root(&root, 1);
        assert_eq!(padded_root, canon_root);
    }

    #[test]
    fn canonical_root_single_leaf() {
        let c = Commitment::commit(42, &BlindingFactor::random());
        // Single leaf tree has depth 0 (root = leaf)
        let canon = canonical_root(&c.0, 0);
        assert_ne!(canon, c.0); // Should be different due to padding
    }

    #[test]
    fn path_to_stark_witness_conversion() {
        let c0 = Commitment::commit(100, &BlindingFactor::random());
        let c1 = Commitment::commit(200, &BlindingFactor::random());
        let (_, paths) = build_merkle_tree(&[c0.0, c1.0]);

        let stark_path = path_to_stark_witness(&paths[0]);
        assert_eq!(stark_path.len(), paths[0].len());
        for (stark_node, merkle_node) in stark_path.iter().zip(paths[0].iter()) {
            assert_eq!(felts_to_hash(&stark_node.0), merkle_node.hash);
            assert_eq!(stark_node.1, merkle_node.is_left);
        }
    }
}
