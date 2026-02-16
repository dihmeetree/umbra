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

/// Precomputed zero-subtree hashes for each level (cached on first call).
///
/// `zero_subtree[0]` = hash of empty leaf = [0; 32]
/// `zero_subtree[n]` = merge(zero_subtree[n-1], zero_subtree[n-1])
///
/// Cached via `OnceLock` to avoid recomputing on every call.
fn zero_subtree_hashes() -> &'static Vec<Hash> {
    static CACHE: std::sync::OnceLock<Vec<Hash>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let mut hashes = Vec::with_capacity(MERKLE_DEPTH + 1);
        hashes.push([0u8; 32]); // Level 0: empty leaf
        for _ in 1..=MERKLE_DEPTH {
            let prev = hash_to_felts(hashes.last().unwrap());
            let merged = rescue::hash_merge(&prev, &prev);
            hashes.push(felts_to_hash(&merged));
        }
        hashes
    })
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
    if tree_depth >= MERKLE_DEPTH {
        return *root;
    }
    let zero_hashes = zero_subtree_hashes();
    let mut current = hash_to_felts(root);
    for zero_hash in &zero_hashes[tree_depth..MERKLE_DEPTH] {
        let zero = hash_to_felts(zero_hash);
        current = rescue::hash_merge(&current, &zero);
    }
    felts_to_hash(&current)
}

/// An append-only Merkle tree with fixed canonical depth (MERKLE_DEPTH = 20).
///
/// Supports O(MERKLE_DEPTH) append and O(MERKLE_DEPTH) path queries, compared
/// to the O(n) full-rebuild approach. Uses Rescue Prime hashing for STARK
/// compatibility.
///
/// Internally stores nodes at each level in `Vec`s that grow as leaves are
/// appended. Unoccupied positions implicitly hold precomputed zero-subtree
/// hashes, so the root and paths are always canonical depth-20 values.
pub struct IncrementalMerkleTree {
    /// Number of leaves appended so far.
    num_leaves: usize,
    /// Nodes at each level: `levels[0]` = leaves, `levels[MERKLE_DEPTH]` = root.
    levels: Vec<Vec<Hash>>,
    /// Precomputed zero-subtree hashes for each level (0..=MERKLE_DEPTH).
    zero_hashes: Vec<Hash>,
}

impl IncrementalMerkleTree {
    /// Create a new empty tree.
    pub fn new() -> Self {
        let zero_hashes = zero_subtree_hashes().clone();
        let levels = (0..=MERKLE_DEPTH).map(|_| Vec::new()).collect();
        IncrementalMerkleTree {
            num_leaves: 0,
            levels,
            zero_hashes,
        }
    }

    /// Maximum number of leaves the tree can hold: 2^MERKLE_DEPTH.
    pub const MAX_LEAVES: usize = 1 << MERKLE_DEPTH;

    /// Append a leaf hash, updating all affected internal nodes.
    ///
    /// Runs in O(MERKLE_DEPTH) time (20 hash operations).
    ///
    /// # Panics
    ///
    /// Panics if the tree already has `MAX_LEAVES` (2^20 = 1,048,576) entries.
    /// In production, callers should check `num_leaves() < MAX_LEAVES` before
    /// appending and reject transactions that would overflow the tree.
    pub fn append(&mut self, leaf: Hash) -> Result<(), String> {
        if self.num_leaves >= Self::MAX_LEAVES {
            return Err(format!(
                "commitment tree full: {} leaves (max {})",
                self.num_leaves,
                Self::MAX_LEAVES,
            ));
        }
        let leaf_index = self.num_leaves;
        self.set_node(0, leaf_index, leaf);

        let mut idx = leaf_index;
        for level in 1..=MERKLE_DEPTH {
            let parent_idx = idx / 2;
            let left = self.get_node(level - 1, parent_idx * 2);
            let right = self.get_node(level - 1, parent_idx * 2 + 1);
            let merged = rescue::hash_merge(&hash_to_felts(&left), &hash_to_felts(&right));
            self.set_node(level, parent_idx, felts_to_hash(&merged));
            idx = parent_idx;
        }

        self.num_leaves += 1;
        Ok(())
    }

    /// Get the canonical depth-20 Merkle root.
    pub fn root(&self) -> Hash {
        self.get_node(MERKLE_DEPTH, 0)
    }

    /// Get the depth-20 authentication path for a leaf by index.
    ///
    /// Returns `None` if the index is out of bounds.
    pub fn path(&self, leaf_index: usize) -> Option<Vec<MerkleNode>> {
        if leaf_index >= self.num_leaves {
            return None;
        }
        let mut path = Vec::with_capacity(MERKLE_DEPTH);
        let mut idx = leaf_index;
        for level in 0..MERKLE_DEPTH {
            let sibling_idx = idx ^ 1;
            path.push(MerkleNode {
                hash: self.get_node(level, sibling_idx),
                is_left: idx % 2 == 1,
            });
            idx >>= 1;
        }
        Some(path)
    }

    /// Get the number of leaves in the tree.
    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    /// Truncate the tree back to `new_leaf_count` leaves.
    ///
    /// Used for rollback on partial vertex application failure.
    /// Truncates each level's Vec and recomputes affected parent nodes.
    pub fn truncate(&mut self, new_leaf_count: usize) {
        if new_leaf_count >= self.num_leaves {
            return;
        }
        // Truncate leaves
        self.levels[0].truncate(new_leaf_count);
        self.num_leaves = new_leaf_count;
        // Recompute parent levels
        let mut count = new_leaf_count;
        for level in 1..=MERKLE_DEPTH {
            let parent_count = count.div_ceil(2);
            self.levels[level].truncate(parent_count);
            // Recompute parents whose children may have changed due to truncation
            if count > 0 {
                // Only the last parent at this level might need recomputation
                // (its right child may now be a zero hash instead of a real node)
                let last_parent = parent_count - 1;
                let left = self.get_node(level - 1, last_parent * 2);
                let right = self.get_node(level - 1, last_parent * 2 + 1);
                let merged = rescue::hash_merge(&hash_to_felts(&left), &hash_to_felts(&right));
                self.set_node(level, last_parent, felts_to_hash(&merged));
            }
            count = parent_count;
        }
    }

    /// Restore a tree from stored level data and leaf count.
    ///
    /// The `loader` function is called with `(level, index)` and should return
    /// the stored hash for that node, or `None` if not stored (will use zero hash).
    pub fn restore(num_leaves: usize, loader: impl Fn(usize, usize) -> Option<Hash>) -> Self {
        let zero_hashes = zero_subtree_hashes().clone();
        let mut levels: Vec<Vec<Hash>> = (0..=MERKLE_DEPTH).map(|_| Vec::new()).collect();

        // For each level, determine how many nodes should exist
        let mut count_at_level = num_leaves;
        for level in 0..=MERKLE_DEPTH {
            if count_at_level == 0 {
                break;
            }
            let mut level_vec = Vec::with_capacity(count_at_level);
            for idx in 0..count_at_level {
                let hash = loader(level, idx).unwrap_or(zero_hashes[level]);
                level_vec.push(hash);
            }
            levels[level] = level_vec;
            count_at_level = count_at_level.div_ceil(2);
        }

        IncrementalMerkleTree {
            num_leaves,
            levels,
            zero_hashes,
        }
    }

    /// Get a node hash (public accessor for persistence).
    pub fn get_node_public(&self, level: usize, index: usize) -> Hash {
        self.get_node(level, index)
    }

    /// Get the number of stored nodes at a level.
    pub fn level_len(&self, level: usize) -> usize {
        if level < self.levels.len() {
            self.levels[level].len()
        } else {
            0
        }
    }

    /// Return the path of nodes modified by the most recent append.
    ///
    /// Returns `(level, index, hash)` for each node on the append path.
    /// Used for incremental persistence (only 21 writes per append).
    pub fn last_appended_path(&self) -> Vec<(usize, usize, Hash)> {
        if self.num_leaves == 0 {
            return vec![];
        }
        let leaf_index = self.num_leaves - 1;
        let mut result = Vec::with_capacity(MERKLE_DEPTH + 1);
        result.push((0, leaf_index, self.get_node(0, leaf_index)));
        let mut idx = leaf_index;
        for level in 1..=MERKLE_DEPTH {
            let parent_idx = idx / 2;
            result.push((level, parent_idx, self.get_node(level, parent_idx)));
            idx = parent_idx;
        }
        result
    }

    /// Get a node, defaulting to the zero-subtree hash for that level.
    fn get_node(&self, level: usize, index: usize) -> Hash {
        if index < self.levels[level].len() {
            self.levels[level][index]
        } else {
            self.zero_hashes[level]
        }
    }

    /// Set a node, extending the level's Vec with zero hashes if needed.
    fn set_node(&mut self, level: usize, index: usize, hash: Hash) {
        let zero = self.zero_hashes[level];
        let level_vec = &mut self.levels[level];
        if index >= level_vec.len() {
            level_vec.resize(index + 1, zero);
        }
        level_vec[index] = hash;
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
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
    fn incremental_tree_matches_batch() {
        // Verify that the incremental tree produces the same canonical root
        // and paths as build_merkle_tree + canonical_root + pad_merkle_path.
        let leaves: Vec<Hash> = (0..5u64)
            .map(|i| Commitment::commit(i * 100 + 1, &BlindingFactor::from_bytes([i as u8; 32])).0)
            .collect();

        // Batch approach
        let (batch_root, batch_paths) = build_merkle_tree(&leaves);
        let batch_canon_root = canonical_root(&batch_root, batch_paths[0].len());

        // Incremental approach
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf).unwrap();
        }

        assert_eq!(tree.root(), batch_canon_root);
        assert_eq!(tree.num_leaves(), leaves.len());

        for (i, leaf) in leaves.iter().enumerate() {
            let inc_path = tree.path(i).unwrap();
            let batch_padded = pad_merkle_path(&batch_paths[i], MERKLE_DEPTH);
            assert_eq!(inc_path.len(), MERKLE_DEPTH);
            assert_eq!(compute_merkle_root(leaf, &inc_path), tree.root());
            // Each sibling hash and direction must match
            for (inc_node, batch_node) in inc_path.iter().zip(batch_padded.iter()) {
                assert_eq!(inc_node.hash, batch_node.hash);
                assert_eq!(inc_node.is_left, batch_node.is_left);
            }
        }
    }

    #[test]
    fn incremental_tree_empty() {
        let tree = IncrementalMerkleTree::new();
        assert_eq!(tree.num_leaves(), 0);
        assert!(tree.path(0).is_none());
        // Empty root should match canonical_root of an empty tree
        assert_eq!(tree.root(), canonical_root(&[0u8; 32], 0));
    }

    #[test]
    fn incremental_tree_single_leaf() {
        let c = Commitment::commit(42, &BlindingFactor::random());
        let mut tree = IncrementalMerkleTree::new();
        tree.append(c.0).unwrap();

        let path = tree.path(0).unwrap();
        assert_eq!(path.len(), MERKLE_DEPTH);
        assert_eq!(compute_merkle_root(&c.0, &path), tree.root());
        assert_eq!(tree.root(), canonical_root(&c.0, 0));
    }

    #[test]
    fn incremental_tree_restore() {
        // Build a tree with several leaves
        let leaves: Vec<Hash> = (0..7u64)
            .map(|i| Commitment::commit(i * 100 + 1, &BlindingFactor::from_bytes([i as u8; 32])).0)
            .collect();

        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf).unwrap();
        }
        let original_root = tree.root();

        // Save all nodes
        let mut saved: std::collections::HashMap<(usize, usize), Hash> =
            std::collections::HashMap::new();
        for level in 0..=MERKLE_DEPTH {
            for idx in 0..tree.level_len(level) {
                saved.insert((level, idx), tree.get_node_public(level, idx));
            }
        }

        // Restore from saved data
        let restored = IncrementalMerkleTree::restore(leaves.len(), |level, idx| {
            saved.get(&(level, idx)).copied()
        });
        assert_eq!(restored.root(), original_root);
        assert_eq!(restored.num_leaves(), leaves.len());

        // Paths should still work
        for (i, leaf) in leaves.iter().enumerate() {
            let path = restored.path(i).unwrap();
            assert_eq!(compute_merkle_root(leaf, &path), original_root);
        }

        // Appending after restore should work
        let mut restored = restored;
        let new_leaf = Commitment::commit(999, &BlindingFactor::from_bytes([99u8; 32])).0;
        tree.append(new_leaf).unwrap();
        restored.append(new_leaf).unwrap();
        assert_eq!(restored.root(), tree.root());
    }

    #[test]
    fn last_appended_path_covers_all_levels() {
        let mut tree = IncrementalMerkleTree::new();
        let leaf = Commitment::commit(42, &BlindingFactor::random()).0;
        tree.append(leaf).unwrap();

        let path = tree.last_appended_path();
        assert_eq!(path.len(), MERKLE_DEPTH + 1); // levels 0..=20
        assert_eq!(path[0], (0, 0, leaf)); // leaf level
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

    #[test]
    fn incremental_tree_truncate_to_zero() {
        let mut tree = IncrementalMerkleTree::new();
        let empty_root = tree.root();

        let c = Commitment::commit(42, &BlindingFactor::random());
        tree.append(c.0).unwrap();
        assert_eq!(tree.num_leaves(), 1);
        assert_ne!(tree.root(), empty_root);

        tree.truncate(0);
        assert_eq!(tree.num_leaves(), 0);
        assert_eq!(tree.root(), empty_root);
    }

    #[test]
    fn incremental_tree_truncate_partial() {
        let leaves: Vec<Hash> = (0..5u64)
            .map(|i| Commitment::commit(i * 100 + 1, &BlindingFactor::from_bytes([i as u8; 32])).0)
            .collect();

        // Build tree with 5 leaves, capture root at 3
        let mut tree3 = IncrementalMerkleTree::new();
        for leaf in &leaves[..3] {
            tree3.append(*leaf).unwrap();
        }
        let root_at_3 = tree3.root();

        // Build tree with 5 leaves
        let mut tree5 = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree5.append(*leaf).unwrap();
        }
        assert_eq!(tree5.num_leaves(), 5);

        // Truncate back to 3
        tree5.truncate(3);
        assert_eq!(tree5.num_leaves(), 3);
        assert_eq!(tree5.root(), root_at_3);

        // Paths should still work
        for (i, leaf) in leaves[..3].iter().enumerate() {
            let path = tree5.path(i).unwrap();
            assert_eq!(compute_merkle_root(leaf, &path), tree5.root());
        }
    }

    #[test]
    fn incremental_tree_truncate_noop_when_larger() {
        let mut tree = IncrementalMerkleTree::new();
        let c = Commitment::commit(42, &BlindingFactor::random());
        tree.append(c.0).unwrap();
        let root_before = tree.root();

        // Truncate to a larger count should be a no-op
        tree.truncate(5);
        assert_eq!(tree.num_leaves(), 1);
        assert_eq!(tree.root(), root_before);
    }

    #[test]
    fn incremental_tree_truncate_then_reappend() {
        let leaves: Vec<Hash> = (0..4u64)
            .map(|i| Commitment::commit(i * 100, &BlindingFactor::from_bytes([i as u8; 32])).0)
            .collect();

        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf).unwrap();
        }

        // Truncate to 2 then re-append same leaves
        tree.truncate(2);
        tree.append(leaves[2]).unwrap();
        tree.append(leaves[3]).unwrap();

        // Should match a fresh tree with same 4 leaves
        let mut fresh = IncrementalMerkleTree::new();
        for leaf in &leaves {
            fresh.append(*leaf).unwrap();
        }
        assert_eq!(tree.root(), fresh.root());
    }

    #[test]
    fn build_merkle_tree_empty() {
        let (root, paths) = build_merkle_tree(&[]);
        assert_eq!(root, [0u8; 32]);
        assert!(paths.is_empty());
    }

    #[test]
    fn incremental_tree_level_len() {
        let mut tree = IncrementalMerkleTree::new();
        assert_eq!(tree.level_len(0), 0);

        let c = Commitment::commit(42, &BlindingFactor::random());
        tree.append(c.0).unwrap();
        assert_eq!(tree.level_len(0), 1); // 1 leaf
        assert!(tree.level_len(MERKLE_DEPTH) > 0); // root level populated

        // Out-of-range level returns 0
        assert_eq!(tree.level_len(MERKLE_DEPTH + 5), 0);
    }

    #[test]
    fn incremental_tree_path_out_of_bounds() {
        let mut tree = IncrementalMerkleTree::new();
        let c = Commitment::commit(42, &BlindingFactor::random());
        tree.append(c.0).unwrap();
        assert!(tree.path(0).is_some());
        assert!(tree.path(1).is_none());
        assert!(tree.path(100).is_none());
    }

    #[test]
    fn incremental_tree_many_leaves_root_consistency() {
        let leaves: Vec<Hash> = (0..100u64)
            .map(|i| {
                Commitment::commit(i * 10, &BlindingFactor::from_bytes([(i & 0xFF) as u8; 32])).0
            })
            .collect();

        // Build via incremental tree
        let mut tree = IncrementalMerkleTree::new();
        for leaf in &leaves {
            tree.append(*leaf).unwrap();
        }

        // Build via batch tree and canonicalize
        let (batch_root, batch_paths) = build_merkle_tree(&leaves);
        let batch_canon_root = canonical_root(&batch_root, batch_paths[0].len());

        assert_eq!(tree.root(), batch_canon_root);
    }

    #[test]
    fn canonical_root_at_max_depth() {
        let c = Commitment::commit(42, &BlindingFactor::random());
        // When tree_depth == MERKLE_DEPTH, canonical_root should return the root unchanged
        let result = canonical_root(&c.0, MERKLE_DEPTH);
        assert_eq!(result, c.0);
    }

    #[test]
    fn zero_subtree_cache_consistent() {
        let first = zero_subtree_hashes();
        let second = zero_subtree_hashes();
        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn incremental_tree_single_leaf_nonzero_root() {
        let mut tree = IncrementalMerkleTree::new();
        let c = Commitment::commit(42, &BlindingFactor::random());
        tree.append(c.0).unwrap();
        assert_eq!(tree.num_leaves(), 1);
        assert!(tree.path(0).is_some());
        // Root should not be zero
        assert_ne!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn build_merkle_tree_single_leaf_nonzero_root() {
        let leaf = Commitment::commit(100, &BlindingFactor::random()).0;
        let (root, paths) = build_merkle_tree(&[leaf]);
        assert_ne!(root, [0u8; 32]);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn merkle_proof_valid_four_leaves() {
        let leaves: Vec<Hash> = (0..4u64)
            .map(|i| Commitment::commit(i * 100, &BlindingFactor::from_bytes([i as u8; 32])).0)
            .collect();
        let (root, paths) = build_merkle_tree(&leaves);
        // All proofs should verify via compute_merkle_root
        for (i, leaf) in leaves.iter().enumerate() {
            assert_eq!(
                compute_merkle_root(leaf, &paths[i]),
                root,
                "proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn merkle_proof_rejects_fake_leaf() {
        let leaves: Vec<Hash> = (0..2u64)
            .map(|i| Commitment::commit(i * 100, &BlindingFactor::from_bytes([i as u8; 32])).0)
            .collect();
        let (root, paths) = build_merkle_tree(&leaves);
        let fake_leaf = [0xFFu8; 32];
        assert_ne!(compute_merkle_root(&fake_leaf, &paths[0]), root);
    }

    #[test]
    fn incremental_tree_empty_last_appended_path() {
        let tree = IncrementalMerkleTree::new();
        assert!(tree.last_appended_path().is_empty());
        assert_eq!(tree.num_leaves(), 0);
    }

    #[test]
    fn incremental_tree_restore_empty() {
        let tree = IncrementalMerkleTree::restore(0, |_, _| None);
        assert_eq!(tree.num_leaves(), 0);
        assert_eq!(tree.root(), IncrementalMerkleTree::new().root());
    }

    #[test]
    fn incremental_tree_restore_with_data() {
        // Build a tree normally
        let mut original = IncrementalMerkleTree::new();
        let leaves: Vec<Hash> = (0..3u64)
            .map(|i| Commitment::commit(i * 100, &BlindingFactor::from_bytes([i as u8; 32])).0)
            .collect();
        for l in &leaves {
            original.append(*l).unwrap();
        }

        // Capture all nodes
        let mut stored: std::collections::HashMap<(usize, usize), Hash> =
            std::collections::HashMap::new();
        for level in 0..=MERKLE_DEPTH {
            for idx in 0..original.level_len(level) {
                stored.insert((level, idx), original.get_node_public(level, idx));
            }
        }

        // Restore from stored data
        let restored =
            IncrementalMerkleTree::restore(3, |level, idx| stored.get(&(level, idx)).copied());
        assert_eq!(restored.root(), original.root());
        assert_eq!(restored.num_leaves(), 3);
    }

    #[test]
    fn compute_merkle_root_empty_path() {
        let leaf = [42u8; 32];
        let root = compute_merkle_root(&leaf, &[]);
        // With empty path, root should equal the leaf itself
        assert_eq!(root, leaf);
    }

    #[test]
    fn path_to_stark_witness_length_matches_depth() {
        let mut tree = IncrementalMerkleTree::new();
        let c = Commitment::commit(1, &BlindingFactor::random());
        tree.append(c.0).unwrap();
        let path = tree.path(0).unwrap();
        let witness = path_to_stark_witness(&path);
        assert_eq!(witness.len(), MERKLE_DEPTH);
    }

    #[test]
    fn canonical_root_below_max_depth_differs() {
        let hash = [42u8; 32];
        let padded = canonical_root(&hash, 0);
        assert_ne!(padded, hash); // padding should change the root
    }

    #[test]
    fn incremental_tree_restore_sparse_loader() {
        // Restore with a loader that returns None for all nodes
        let tree = IncrementalMerkleTree::restore(5, |_, _| None);
        assert_eq!(tree.num_leaves(), 5);
        // Root should be non-zero (zero-hashes fill missing nodes)
        assert_ne!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn incremental_tree_default_matches_new() {
        let from_new = IncrementalMerkleTree::new();
        let from_default = IncrementalMerkleTree::default();
        assert_eq!(from_new.root(), from_default.root());
        assert_eq!(from_new.num_leaves(), from_default.num_leaves());
    }

    #[test]
    fn pad_merkle_path_at_depth_is_noop() {
        let path: Vec<MerkleNode> = (0..MERKLE_DEPTH)
            .map(|_| MerkleNode {
                hash: [0u8; 32],
                is_left: false,
            })
            .collect();
        let padded = pad_merkle_path(&path, MERKLE_DEPTH);
        assert_eq!(padded.len(), MERKLE_DEPTH);
    }
}
