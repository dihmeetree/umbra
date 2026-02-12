//! Blockchain state management.
//!
//! Tracks:
//! - The set of all output commitments (Merkle tree with Rescue Prime hashing)
//! - The set of all revealed nullifiers (prevents double-spending)
//! - Validator registry
//! - Current epoch state
//!
//! The commitment Merkle tree is an incremental append-only structure at
//! canonical depth 20, matching the zk-STARK spend proof circuit. Appending
//! a commitment is O(MERKLE_DEPTH) instead of rebuilding the full tree.

use std::collections::{HashMap, HashSet};

use crate::consensus::bft::Validator;
use crate::consensus::dag::{Vertex, VertexId};
use crate::crypto::commitment::Commitment;
use crate::crypto::nullifier::{Nullifier, NullifierSet};
use crate::crypto::proof::{IncrementalMerkleTree, MerkleNode};
use crate::crypto::stark::convert::hash_to_felts;
use crate::crypto::stark::types::SpendPublicInputs;
use crate::crypto::vrf::EpochSeed;
use crate::transaction::{deregister_sign_data, Transaction, TxType};
use crate::Hash;

/// The full blockchain state.
///
/// # State growth (M8)
///
/// The commitment tree and nullifier set grow monotonically. At depth 20 the
/// commitment tree supports up to 2^20 ≈ 1M outputs. After that, a tree
/// rotation or depth increase would be required. The nullifier `HashSet`
/// grows linearly with spends; production deployments should consider a
/// disk-backed set (e.g., via sled) and periodic compaction.
///
/// # Persistence (M4)
///
/// State restoration from storage is not yet implemented. On startup the
/// chain state is rebuilt from genesis. A production node should persist
/// `ChainStateMeta` and the commitment tree levels to storage, and restore
/// them on startup to avoid full replay.
pub struct ChainState {
    /// Chain identifier for replay protection
    chain_id: Hash,
    /// All output commitments ever created (for lookup by index/value)
    commitments: Vec<Commitment>,
    /// Incremental depth-20 Merkle tree over commitments (Rescue Prime)
    commitment_tree: IncrementalMerkleTree,
    /// Set of revealed nullifiers (spent outputs)
    nullifiers: NullifierSet,
    /// Incremental hash accumulator over nullifiers (for state root)
    nullifier_hash: Hash,
    /// Registered validators
    validators: HashMap<Hash, Validator>,
    /// Escrowed validator bonds (validator_id -> bond amount)
    validator_bonds: HashMap<Hash, u64>,
    /// Permanently slashed validators
    slashed_validators: HashSet<Hash>,
    /// Current epoch's VRF seed
    epoch_seed: EpochSeed,
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
            commitment_tree: IncrementalMerkleTree::new(),
            nullifiers: NullifierSet::new(),
            nullifier_hash: [0u8; 32],
            validators: HashMap::new(),
            validator_bonds: HashMap::new(),
            slashed_validators: HashSet::new(),
            epoch_seed: EpochSeed::genesis(),
            epoch_fees: 0,
            epoch: 0,
            last_finalized: None,
        }
    }

    /// Apply a finalized vertex to the state.
    ///
    /// Uses two-pass validation: first validates all transactions without
    /// mutating state, then applies them. This prevents partial state
    /// corruption if a later transaction in the vertex is invalid.
    pub fn apply_vertex(&mut self, vertex: &Vertex) -> Result<(), StateError> {
        // H9: Pass 1 — validate all transactions without applying
        for tx in &vertex.transactions {
            self.validate_transaction(tx)?;
        }
        // Pass 2 — apply all transactions (cannot fail after validation)
        for tx in &vertex.transactions {
            self.apply_transaction_unchecked(tx);
        }
        self.last_finalized = Some(vertex.id);
        Ok(())
    }

    /// Validate a transaction against the current state (without applying).
    ///
    /// Performs full validation (structure, balance proof, spend proofs, expiry,
    /// state checks) but does NOT mutate state.
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<(), StateError> {
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
        let root_felts = hash_to_felts(&self.commitment_tree.root());
        for input in &tx.inputs {
            let spend_pub = SpendPublicInputs::from_bytes(&input.spend_proof.public_inputs_bytes)
                .ok_or(StateError::InvalidSpendProof)?;

            if spend_pub.merkle_root != root_felts {
                return Err(StateError::InvalidSpendProof);
            }
        }

        // Validate transaction-type-specific state constraints
        match &tx.tx_type {
            TxType::Transfer => {}
            TxType::ValidatorRegister { signing_key } => {
                let vid = signing_key.fingerprint();
                if self.validators.contains_key(&vid) {
                    return Err(StateError::ValidatorAlreadyRegistered);
                }
                if self.slashed_validators.contains(&vid) {
                    return Err(StateError::ValidatorSlashed);
                }
            }
            TxType::ValidatorDeregister {
                validator_id,
                auth_signature,
                bond_return_output,
                bond_blinding,
            } => {
                let validator = self
                    .validators
                    .get(validator_id)
                    .ok_or(StateError::ValidatorNotFound)?;
                if !validator.active {
                    return Err(StateError::ValidatorNotActive);
                }
                if self.slashed_validators.contains(validator_id) {
                    return Err(StateError::ValidatorSlashed);
                }
                let tx_content_hash = tx.tx_content_hash();
                let sign_data =
                    deregister_sign_data(&self.chain_id, validator_id, &tx_content_hash);
                if !validator.public_key.verify(&sign_data, auth_signature) {
                    return Err(StateError::InvalidDeregisterAuth);
                }
                // C4: Verify that the bond return commitment opens to exactly VALIDATOR_BOND
                let bond = self
                    .validator_bonds
                    .get(validator_id)
                    .copied()
                    .ok_or(StateError::InsufficientBond)?;
                let blinding =
                    crate::crypto::commitment::BlindingFactor::from_bytes(*bond_blinding);
                if !bond_return_output.commitment.verify(bond, &blinding) {
                    return Err(StateError::InvalidBondReturn);
                }
            }
        }

        Ok(())
    }

    /// Apply a transaction to the state (full validate + apply).
    ///
    /// Performs full validation then applies state changes.
    /// For batch application (vertices), prefer `validate_transaction` + `apply_transaction_unchecked`.
    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), StateError> {
        self.validate_transaction(tx)?;
        self.apply_transaction_unchecked(tx);
        Ok(())
    }

    /// Apply a pre-validated transaction to the state (no validation).
    ///
    /// SAFETY: The caller MUST have called `validate_transaction` first.
    fn apply_transaction_unchecked(&mut self, tx: &Transaction) {
        // Record nullifiers (with incremental hash update)
        for input in &tx.inputs {
            self.record_nullifier(input.nullifier);
        }

        // Add new output commitments (incremental tree update, O(log n) each)
        for output in &tx.outputs {
            self.add_commitment(output.commitment);
        }

        // Handle transaction type
        match &tx.tx_type {
            TxType::Transfer => {
                // Standard fee collection
                self.epoch_fees = self.epoch_fees.saturating_add(tx.fee);
            }
            TxType::ValidatorRegister { signing_key } => {
                let validator = Validator::new(signing_key.clone());
                let vid = validator.id;

                // Escrow bond, remainder goes to epoch fees
                let bond = crate::constants::VALIDATOR_BOND;
                let actual_fee = tx.fee.saturating_sub(bond);
                self.epoch_fees = self.epoch_fees.saturating_add(actual_fee);

                self.validator_bonds.insert(vid, bond);
                self.register_validator(validator);
            }
            TxType::ValidatorDeregister {
                validator_id,
                bond_return_output,
                ..
            } => {
                // Return bond as output commitment (already verified in validate_transaction)
                self.add_commitment(bond_return_output.commitment);

                // Mark inactive and remove bond
                if let Some(v) = self.validators.get_mut(validator_id) {
                    v.active = false;
                }
                self.validator_bonds.remove(validator_id);

                // Collect fee
                self.epoch_fees = self.epoch_fees.saturating_add(tx.fee);
            }
        }
    }

    /// Record a nullifier as spent, updating the incremental hash accumulator.
    fn record_nullifier(&mut self, nullifier: Nullifier) {
        if self.nullifiers.insert(nullifier) {
            // Update incremental hash: new = H(old || nullifier)
            self.nullifier_hash =
                crate::hash_concat(&[b"spectra.nullifier_acc", &self.nullifier_hash, &nullifier.0]);
        }
    }

    /// Add a single commitment to the incremental Merkle tree.
    pub fn add_commitment(&mut self, commitment: Commitment) {
        self.commitment_tree.append(commitment.0);
        self.commitments.push(commitment);
    }

    /// Record a nullifier as spent (public API).
    pub fn mark_nullifier(&mut self, nullifier: Nullifier) {
        self.record_nullifier(nullifier);
    }

    /// Get the current canonical (depth-20) commitment Merkle root.
    pub fn commitment_root(&self) -> Hash {
        self.commitment_tree.root()
    }

    /// Get the depth-20 Merkle path for a commitment by index.
    pub fn commitment_path(&self, index: usize) -> Option<Vec<MerkleNode>> {
        self.commitment_tree.path(index)
    }

    /// Get the index of a commitment in the tree, if it exists.
    pub fn find_commitment(&self, commitment: &Commitment) -> Option<usize> {
        self.commitments.iter().position(|c| c == commitment)
    }

    /// Check if a nullifier has been used.
    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Register a validator (internal — use apply_transaction for public API).
    fn register_validator(&mut self, validator: Validator) {
        self.validators.insert(validator.id, validator);
    }

    /// Register a genesis validator (bond escrowed without requiring a funding tx).
    pub fn register_genesis_validator(&mut self, validator: Validator) {
        let id = validator.id;
        self.validator_bonds
            .insert(id, crate::constants::VALIDATOR_BOND);
        self.validators.insert(id, validator);
    }

    /// Get all active validators.
    pub fn active_validators(&self) -> Vec<&Validator> {
        self.validators.values().filter(|v| v.active).collect()
    }

    /// Get all validators (active and inactive).
    pub fn all_validators(&self) -> Vec<&Validator> {
        self.validators.values().collect()
    }

    /// Get a validator by ID.
    pub fn get_validator(&self, id: &Hash) -> Option<&Validator> {
        self.validators.get(id)
    }

    /// Check if a validator is registered and active.
    pub fn is_active_validator(&self, id: &Hash) -> bool {
        self.validators.get(id).map(|v| v.active).unwrap_or(false)
    }

    /// Get the bond escrowed for a validator.
    pub fn validator_bond(&self, id: &Hash) -> Option<u64> {
        self.validator_bonds.get(id).copied()
    }

    /// Count of active validators.
    pub fn total_validators(&self) -> usize {
        // L7: Count directly instead of allocating a Vec
        self.validators.values().filter(|v| v.active).count()
    }

    /// Slash a validator: forfeit bond and mark as permanently slashed.
    pub fn slash_validator(&mut self, validator_id: &Hash) -> Result<(), StateError> {
        let validator = self
            .validators
            .get_mut(validator_id)
            .ok_or(StateError::ValidatorNotFound)?;
        validator.active = false;

        // Forfeit bond to epoch fees
        if let Some(bond) = self.validator_bonds.remove(validator_id) {
            self.epoch_fees = self
                .epoch_fees
                .checked_add(bond)
                .ok_or(StateError::FeeOverflow)?;
        }

        self.slashed_validators.insert(*validator_id);
        Ok(())
    }

    /// Check if a validator has been slashed.
    pub fn is_slashed(&self, id: &Hash) -> bool {
        self.slashed_validators.contains(id)
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

    /// Advance to the next epoch, returning collected fees and the new epoch seed.
    pub fn advance_epoch(&mut self) -> (u64, EpochSeed) {
        let fees = self.epoch_fees;
        self.epoch_fees = 0;
        self.epoch += 1;
        let state_root = self.state_root();
        self.epoch_seed = self.epoch_seed.next(&state_root);
        (fees, self.epoch_seed.clone())
    }

    /// Compute the state root (hash of all state components).
    pub fn state_root(&self) -> Hash {
        let root = self.commitment_tree.root();
        // M14: Include validator registry in state root
        let validator_count = self.total_validators() as u64;
        let total_bonds: u64 = self.validator_bonds.values().sum();
        crate::hash_concat(&[
            b"spectra.state_root",
            &root,
            &self.nullifier_hash,
            &self.epoch.to_le_bytes(),
            &self.epoch_fees.to_le_bytes(),
            &validator_count.to_le_bytes(),
            &total_bonds.to_le_bytes(),
        ])
    }

    /// Get the last finalized vertex ID.
    pub fn last_finalized(&self) -> Option<&VertexId> {
        self.last_finalized.as_ref()
    }

    /// Get the current epoch number.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Get the chain ID.
    pub fn chain_id(&self) -> &Hash {
        &self.chain_id
    }

    /// Get the nullifier hash accumulator (for state snapshots).
    pub fn nullifier_hash(&self) -> &Hash {
        &self.nullifier_hash
    }

    /// Get the current epoch seed for VRF evaluation.
    pub fn epoch_seed(&self) -> &EpochSeed {
        &self.epoch_seed
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

    /// Insert a vertex into the DAG (validated but not yet finalized).
    ///
    /// Validates vertex structure including proposer signature, but does NOT
    /// apply transactions to state. Call `finalize_vertex()` after BFT
    /// certification to apply.
    pub fn insert_vertex(&mut self, vertex: Vertex) -> Result<(), StateError> {
        self.dag.insert(vertex).map_err(StateError::InvalidVertex)?;
        Ok(())
    }

    /// Finalize a vertex: mark as final in DAG and apply transactions to state.
    ///
    /// Call after BFT certification. The vertex must already be in the DAG
    /// (via `insert_vertex()`).
    pub fn finalize_vertex(&mut self, vertex_id: &VertexId) -> Result<(), StateError> {
        self.dag.finalize(vertex_id);
        if let Some(v) = self.dag.get(vertex_id) {
            let v = v.clone();
            self.state.apply_vertex(&v)?;
        }
        Ok(())
    }

    /// Apply a finalized vertex: insert into DAG, finalize, and update state.
    ///
    /// Convenience method that calls `insert_vertex()` then `finalize_vertex()`.
    /// Validates vertex structure including proposer signature.
    pub fn apply_finalized_vertex(&mut self, vertex: Vertex) -> Result<(), StateError> {
        let id = vertex.id;
        self.insert_vertex(vertex)?;
        self.finalize_vertex(&id)?;
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
    #[error("validator already registered")]
    ValidatorAlreadyRegistered,
    #[error("validator not active")]
    ValidatorNotActive,
    #[error("validator has been slashed")]
    ValidatorSlashed,
    #[error("insufficient bond deposit")]
    InsufficientBond,
    #[error("invalid deregistration auth signature")]
    InvalidDeregisterAuth,
    #[error("bond return commitment does not open to the escrowed bond amount")]
    InvalidBondReturn,
    #[error("fee accumulation overflow")]
    FeeOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::commitment::{BlindingFactor, Commitment};
    use crate::crypto::nullifier::Nullifier;
    use crate::crypto::stark::spend_air::MERKLE_DEPTH;

    #[test]
    fn state_commitment_tree() {
        let mut state = ChainState::new();
        let blind = BlindingFactor::random();
        let c = Commitment::commit(100, &blind);

        state.add_commitment(c);

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
        state.add_commitment(Commitment::commit(100, &blind));

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

        // The path should produce the same root
        let path = state.commitment_path(0).unwrap();
        assert_eq!(path.len(), MERKLE_DEPTH);
        let root_from_path = crate::crypto::proof::compute_merkle_root(&c.0, &path);
        assert_eq!(root_from_path, state.commitment_root());
    }
}
