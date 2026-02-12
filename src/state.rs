//! Blockchain state management.
//!
//! Tracks:
//! - The set of all output commitments (Merkle tree with Rescue Prime hashing)
//! - The set of all revealed nullifiers (prevents double-spending)
//! - Validator registry
//! - Current epoch state
//!
//! The commitment Merkle tree uses a canonical depth of 20, matching the
//! zk-STARK spend proof circuit. Shallower trees are extended to depth 20
//! using precomputed zero-subtree hashes.

use std::collections::HashMap;

use crate::consensus::bft::Validator;
use crate::consensus::dag::{Vertex, VertexId};
use crate::crypto::commitment::Commitment;
use crate::crypto::nullifier::{Nullifier, NullifierSet};
use crate::crypto::proof::{build_merkle_tree, canonical_root, pad_merkle_path, MerkleNode};
use crate::crypto::stark::convert::hash_to_felts;
use crate::crypto::stark::spend_air::MERKLE_DEPTH;
use crate::crypto::stark::types::SpendPublicInputs;
use crate::transaction::Transaction;
use crate::Hash;

/// The full blockchain state.
pub struct ChainState {
    /// Chain identifier for replay protection
    chain_id: Hash,
    /// All output commitments ever created
    commitments: Vec<Commitment>,
    /// Merkle tree root of all commitments (actual depth, NOT canonical)
    raw_commitment_root: Hash,
    /// Actual depth of the Merkle tree (log2 of padded leaf count)
    tree_depth: usize,
    /// Canonical depth-20 root (padded from raw root)
    commitment_root: Hash,
    /// Merkle paths for each commitment (actual depth, pre-padding)
    commitment_paths: Vec<Vec<MerkleNode>>,
    /// Set of revealed nullifiers (spent outputs)
    nullifiers: NullifierSet,
    /// Incremental hash accumulator over nullifiers (for state root)
    nullifier_hash: Hash,
    /// Registered validators
    validators: HashMap<Hash, Validator>,
    /// Total fees collected in the current epoch
    epoch_fees: u64,
    /// Current epoch number
    epoch: u64,
    /// ID of the last finalized vertex
    last_finalized: Option<VertexId>,
}

/// The full ledger coordinating DAG, BFT, and chain state.
pub struct Ledger {
    /// The DAG data structure
    pub dag: crate::consensus::dag::Dag,
    /// The chain state (commitments, nullifiers)
    pub state: ChainState,
}

impl ChainState {
    /// Create a new chain state with genesis conditions.
    pub fn new() -> Self {
        ChainState {
            chain_id: crate::constants::chain_id(),
            commitments: Vec::new(),
            raw_commitment_root: [0u8; 32],
            tree_depth: 0,
            commitment_root: canonical_root(&[0u8; 32], 0),
            commitment_paths: Vec::new(),
            nullifiers: NullifierSet::new(),
            nullifier_hash: [0u8; 32],
            validators: HashMap::new(),
            epoch_fees: 0,
            epoch: 0,
            last_finalized: None,
        }
    }

    /// Apply a finalized vertex to the state.
    pub fn apply_vertex(&mut self, vertex: &Vertex) -> Result<(), StateError> {
        for tx in &vertex.transactions {
            self.apply_transaction(tx)?;
        }
        self.last_finalized = Some(vertex.id);
        Ok(())
    }

    /// Apply a transaction to the state.
    ///
    /// Performs full validation (structure, balance proof, spend proofs, expiry)
    /// before applying state changes.
    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), StateError> {
        // Verify chain_id matches (defense-in-depth; also bound via balance proof)
        if !crate::constant_time_eq(&tx.chain_id, &self.chain_id) {
            return Err(StateError::WrongChainId);
        }

        // Full structural validation including balance proof, spend proofs, binding, and expiry
        tx.validate_structure(self.epoch)
            .map_err(StateError::InvalidTransaction)?;

        // Check all nullifiers are fresh
        for input in &tx.inputs {
            if self.nullifiers.contains(&input.nullifier) {
                return Err(StateError::DoubleSpend(input.nullifier));
            }
        }

        // Check spend proof Merkle roots against current canonical commitment root.
        // Spend proofs were already cryptographically verified by validate_structure();
        // here we only need to deserialize the public inputs to check the Merkle root.
        for input in &tx.inputs {
            let spend_pub = SpendPublicInputs::from_bytes(&input.spend_proof.public_inputs_bytes)
                .ok_or(StateError::InvalidSpendProof)?;

            let root_felts = hash_to_felts(&self.commitment_root);
            if spend_pub.merkle_root != root_felts {
                return Err(StateError::InvalidSpendProof);
            }
        }

        // All checks passed — apply state changes

        // Record nullifiers (with incremental hash update)
        for input in &tx.inputs {
            self.record_nullifier(input.nullifier);
        }

        // Add new output commitments
        for output in &tx.outputs {
            self.commitments.push(output.commitment);
        }

        // Rebuild Merkle tree
        self.rebuild_commitment_tree();

        // Collect fee with overflow check
        self.epoch_fees = self
            .epoch_fees
            .checked_add(tx.fee)
            .ok_or(StateError::FeeOverflow)?;

        Ok(())
    }

    /// Record a nullifier as spent, updating the incremental hash accumulator.
    fn record_nullifier(&mut self, nullifier: Nullifier) {
        if self.nullifiers.insert(nullifier) {
            // Update incremental hash: new = H(old || nullifier)
            self.nullifier_hash =
                crate::hash_concat(&[b"spectra.nullifier_acc", &self.nullifier_hash, &nullifier.0]);
        }
    }

    /// Rebuild the commitment Merkle tree after adding new commitments.
    fn rebuild_commitment_tree(&mut self) {
        if self.commitments.is_empty() {
            self.raw_commitment_root = [0u8; 32];
            self.tree_depth = 0;
            self.commitment_root = canonical_root(&[0u8; 32], 0);
            self.commitment_paths.clear();
            return;
        }

        let leaves: Vec<Hash> = self.commitments.iter().map(|c| c.0).collect();
        let (root, paths) = build_merkle_tree(&leaves);

        // Compute actual tree depth
        let depth = if paths.is_empty() || paths[0].is_empty() {
            if leaves.len() <= 1 {
                0
            } else {
                1
            }
        } else {
            paths[0].len()
        };

        self.raw_commitment_root = root;
        self.tree_depth = depth;
        self.commitment_root = canonical_root(&root, depth);
        self.commitment_paths = paths;
    }

    /// Add a single commitment and rebuild the Merkle tree.
    pub fn add_commitment(&mut self, commitment: Commitment) {
        self.commitments.push(commitment);
        self.rebuild_commitment_tree();
    }

    /// Record a nullifier as spent (public API).
    pub fn mark_nullifier(&mut self, nullifier: Nullifier) {
        self.record_nullifier(nullifier);
    }

    /// Get the current canonical (depth-20) commitment Merkle root.
    pub fn commitment_root(&self) -> Hash {
        self.commitment_root
    }

    /// Get the Merkle path for a commitment by index, padded to depth 20.
    pub fn commitment_path(&self, index: usize) -> Option<Vec<MerkleNode>> {
        self.commitment_paths
            .get(index)
            .map(|path| pad_merkle_path(path, MERKLE_DEPTH))
    }

    /// Get the index of a commitment in the tree, if it exists.
    pub fn find_commitment(&self, commitment: &Commitment) -> Option<usize> {
        self.commitments.iter().position(|c| c == commitment)
    }

    /// Check if a nullifier has been used.
    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Register a validator.
    pub fn register_validator(&mut self, validator: Validator) {
        self.validators.insert(validator.id, validator);
    }

    /// Get all active validators.
    pub fn active_validators(&self) -> Vec<&Validator> {
        self.validators.values().filter(|v| v.active).collect()
    }

    /// Get a validator by ID.
    pub fn get_validator(&self, id: &Hash) -> Option<&Validator> {
        self.validators.get(id)
    }

    /// Get the total number of output commitments.
    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }

    /// Get the total number of spent nullifiers.
    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }

    /// Get accumulated fees for the current epoch.
    pub fn epoch_fees(&self) -> u64 {
        self.epoch_fees
    }

    /// Advance to the next epoch, returning collected fees.
    pub fn advance_epoch(&mut self) -> u64 {
        let fees = self.epoch_fees;
        self.epoch_fees = 0;
        self.epoch += 1;
        fees
    }

    /// Compute the state root (hash of all state components).
    pub fn state_root(&self) -> Hash {
        crate::hash_concat(&[
            b"spectra.state_root",
            &self.commitment_root,
            &self.nullifier_hash,
            &self.epoch.to_le_bytes(),
            &self.epoch_fees.to_le_bytes(),
        ])
    }

    /// Get the last finalized vertex ID.
    pub fn last_finalized(&self) -> Option<&VertexId> {
        self.last_finalized.as_ref()
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

impl Ledger {
    /// Create a new ledger with genesis.
    pub fn new() -> Self {
        let genesis = crate::consensus::dag::Dag::genesis_vertex();
        let dag = crate::consensus::dag::Dag::new(genesis);
        Ledger {
            dag,
            state: ChainState::new(),
        }
    }

    /// Apply a finalized vertex: insert into DAG, finalize, and update state.
    ///
    /// Validates vertex structure including proposer signature.
    pub fn apply_finalized_vertex(
        &mut self,
        vertex: crate::consensus::dag::Vertex,
    ) -> Result<(), StateError> {
        let id = vertex.id;
        // Use insert() which validates structure + signature
        self.dag.insert(vertex).map_err(StateError::InvalidVertex)?;
        self.dag.finalize(&id);
        if let Some(v) = self.dag.get(&id) {
            let v = v.clone();
            self.state.apply_vertex(&v)?;
        }
        Ok(())
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

/// State application errors.
#[derive(Clone, Debug, thiserror::Error)]
pub enum StateError {
    #[error("transaction chain_id does not match this chain")]
    WrongChainId,
    #[error("double spend: nullifier {0:?} already revealed")]
    DoubleSpend(Nullifier),
    #[error("invalid spend proof")]
    InvalidSpendProof,
    #[error("invalid transaction: {0}")]
    InvalidTransaction(crate::transaction::TxValidationError),
    #[error("invalid vertex: {0}")]
    InvalidVertex(#[from] crate::consensus::dag::VertexError),
    #[error("validator not found")]
    ValidatorNotFound,
    #[error("fee accumulation overflow")]
    FeeOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::commitment::{BlindingFactor, Commitment};
    use crate::crypto::nullifier::Nullifier;

    #[test]
    fn state_commitment_tree() {
        let mut state = ChainState::new();
        let blind = BlindingFactor::random();
        let c = Commitment::commit(100, &blind);

        state.commitments.push(c);
        state.rebuild_commitment_tree();

        assert_ne!(state.commitment_root(), [0u8; 32]);
        assert_eq!(state.commitment_count(), 1);
        assert_eq!(state.find_commitment(&c), Some(0));
    }

    #[test]
    fn state_nullifier_tracking() {
        let mut state = ChainState::new();
        let n = Nullifier::derive(&[1u8; 32], &[2u8; 32]);

        assert!(!state.is_spent(&n));
        state.mark_nullifier(n);
        assert!(state.is_spent(&n));
    }

    #[test]
    fn state_root_changes() {
        let mut state = ChainState::new();
        let root1 = state.state_root();

        let blind = BlindingFactor::random();
        state.commitments.push(Commitment::commit(100, &blind));
        state.rebuild_commitment_tree();

        let root2 = state.state_root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn state_root_commits_to_nullifiers() {
        let mut state1 = ChainState::new();
        let mut state2 = ChainState::new();

        let n = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        state1.mark_nullifier(n);

        assert_ne!(state1.state_root(), state2.state_root());

        state2.mark_nullifier(n);
        assert_eq!(state1.state_root(), state2.state_root());
    }

    #[test]
    fn canonical_root_consistency() {
        let mut state = ChainState::new();
        let blind = BlindingFactor::random();
        let c = Commitment::commit(100, &blind);
        state.add_commitment(c);

        // The padded path should produce the same canonical root
        let padded_path = state.commitment_path(0).unwrap();
        assert_eq!(padded_path.len(), MERKLE_DEPTH);
        let root_from_path = crate::crypto::proof::compute_merkle_root(&c.0, &padded_path);
        assert_eq!(root_from_path, state.commitment_root());
    }
}
