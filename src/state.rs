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
use crate::crypto::commitment::{BlindingFactor, Commitment};
use crate::crypto::encryption::EncryptedPayload;
use crate::crypto::nullifier::{Nullifier, NullifierSet};
use crate::crypto::proof::{IncrementalMerkleTree, MerkleNode};
use crate::crypto::stark::convert::hash_to_felts;
use crate::crypto::stark::types::SpendPublicInputs;
use crate::crypto::stealth::StealthAddress;
use crate::crypto::vrf::EpochSeed;
use crate::node::storage::{ChainStateMeta, Storage, ValidatorRecord};
use crate::transaction::{deregister_sign_data, Transaction, TxOutput, TxType};
use crate::Hash;

/// Complete state snapshot for fast node bootstrap.
///
/// Contains all data needed to reconstruct `ChainState` without replaying
/// finalized vertices. The receiver writes this data to local storage and
/// calls `Ledger::restore_from_storage()`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SnapshotData {
    /// Compact metadata (epoch, roots, counts, hashes).
    pub meta: ChainStateMeta,
    /// All registered validators with bond and slashed status.
    pub validators: Vec<ValidatorRecord>,
    /// Full commitment Merkle tree nodes: (level, index, hash).
    pub commitment_levels: Vec<(usize, usize, Hash)>,
    /// All revealed nullifier hashes.
    pub nullifiers: Vec<Hash>,
}

/// Import a `SnapshotData` into local storage for `Ledger::restore_from_storage()`.
///
/// Clears existing state data, writes snapshot components, and returns the
/// `ChainStateMeta` needed to restore the ledger.
///
/// # Verification
///
/// `Ledger::restore_from_storage()` will verify:
/// - Commitment tree root matches `meta.commitment_root`
/// - Nullifier count matches `meta.nullifier_count`
///
/// The caller should additionally verify `state_root()` after restore.
pub fn import_snapshot_to_storage(
    storage: &dyn Storage,
    snapshot: &SnapshotData,
) -> Result<ChainStateMeta, StateError> {
    // 1. Clear existing state data
    storage
        .clear_for_snapshot_import()
        .map_err(|e| StateError::StorageError(e.to_string()))?;

    // 2. Write commitment levels
    for &(level, index, ref hash) in &snapshot.commitment_levels {
        storage
            .put_commitment_level(level, index, hash)
            .map_err(|e| StateError::StorageError(e.to_string()))?;
    }

    // 3. Write nullifiers
    for hash in &snapshot.nullifiers {
        storage
            .put_nullifier(&Nullifier(*hash))
            .map_err(|e| StateError::StorageError(e.to_string()))?;
    }

    // 4. Write validators
    for record in &snapshot.validators {
        storage
            .put_validator(&record.validator, record.bond, record.slashed)
            .map_err(|e| StateError::StorageError(e.to_string()))?;
    }

    // 5. Write chain state meta
    storage
        .put_chain_state_meta(&snapshot.meta)
        .map_err(|e| StateError::StorageError(e.to_string()))?;

    // 6. Flush to disk
    storage
        .flush()
        .map_err(|e| StateError::StorageError(e.to_string()))?;

    Ok(snapshot.meta.clone())
}

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
/// # Persistence
///
/// State can be persisted via `to_chain_state_meta()` (snapshot) and the
/// commitment tree's `last_appended_path()` (incremental level writes).
/// Use `restore_from_storage()` on startup to rebuild state from storage
/// without replaying all finalized vertices from genesis.
pub struct ChainState {
    /// Chain identifier for replay protection
    chain_id: Hash,
    /// All output commitments ever created (for lookup by index/value)
    commitments: Vec<Commitment>,
    /// Incremental depth-20 Merkle tree over commitments (Rescue Prime)
    commitment_tree: IncrementalMerkleTree,
    /// Set of revealed nullifiers (spent outputs) — in-memory cache
    nullifiers: NullifierSet,
    /// Optional sled-backed nullifier storage for scalability (F12).
    /// When present, new nullifiers are written to both memory and sled,
    /// and `is_spent()` falls back to sled for lookups.
    nullifier_storage: Option<sled::Tree>,
    /// Number of nullifiers migrated to sled-only storage (no longer in `nullifiers` set).
    /// Used so `nullifier_count()` returns the true total even after migration.
    migrated_nullifier_count: usize,
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
    /// Total coins ever minted via coinbase rewards
    total_minted: u64,
    /// O(1) commitment lookup index (commitment -> position in commitments vec)
    commitment_index: HashMap<Commitment, usize>,
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
            nullifier_storage: None,
            migrated_nullifier_count: 0,
            nullifier_hash: [0u8; 32],
            validators: HashMap::new(),
            validator_bonds: HashMap::new(),
            slashed_validators: HashSet::new(),
            epoch_seed: EpochSeed::genesis(),
            epoch_fees: 0,
            epoch: 0,
            last_finalized: None,
            total_minted: 0,
            commitment_index: HashMap::new(),
        }
    }

    /// Apply a finalized vertex to the state.
    ///
    /// Uses two-pass validation: first validates all transactions in parallel
    /// using rayon (F14), then applies them sequentially. Creates a coinbase
    /// output for the vertex proposer containing the block reward plus
    /// transaction fees.
    ///
    /// Returns the coinbase `TxOutput` if one was created (requires the
    /// proposer to be a registered validator with a KEM public key).
    pub fn apply_vertex(&mut self, vertex: &Vertex) -> Result<Option<TxOutput>, StateError> {
        if vertex.transactions.len() > crate::constants::MAX_TXS_PER_VERTEX {
            return Err(StateError::TooManyTransactions);
        }

        // Validate vertex epoch matches the current chain epoch.
        // A malicious proposer could set a fake epoch to manipulate block rewards
        // or bypass expiry checks. Genesis (epoch=0, round=0) is exempt.
        if vertex.round > 0 && vertex.epoch != self.epoch {
            return Err(StateError::EpochMismatch {
                expected: self.epoch,
                got: vertex.epoch,
            });
        }

        // Check for intra-vertex nullifier duplicates (cross-tx double-spend within a single vertex)
        {
            let mut seen_nullifiers = HashSet::new();
            for tx in &vertex.transactions {
                for input in &tx.inputs {
                    if !seen_nullifiers.insert(input.nullifier) {
                        return Err(StateError::DoubleSpend(input.nullifier));
                    }
                }
            }
        }

        // Check for duplicate validator operations within vertex
        {
            let mut registering = HashSet::new();
            let mut deregistering = HashSet::new();
            for tx in &vertex.transactions {
                match &tx.tx_type {
                    TxType::ValidatorRegister { signing_key, .. } => {
                        let vid = signing_key.fingerprint();
                        if !registering.insert(vid) {
                            return Err(StateError::ValidatorAlreadyRegistered);
                        }
                    }
                    TxType::ValidatorDeregister { validator_id, .. } => {
                        if !deregistering.insert(*validator_id) {
                            return Err(StateError::ValidatorNotFound);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Pass 1 — validate all transactions without applying.
        // Use rayon parallel iteration for independent tx validation.
        if vertex.transactions.len() > 1 {
            use rayon::prelude::*;
            let results: Vec<Result<(), StateError>> = vertex
                .transactions
                .par_iter()
                .map(|tx| self.validate_transaction(tx))
                .collect();
            for r in results {
                r?;
            }
        } else {
            for tx in &vertex.transactions {
                self.validate_transaction(tx)?;
            }
        }

        // Record fees before applying transactions
        let fees_before = self.epoch_fees;

        // Snapshot state for rollback if a transaction fails mid-loop.
        // Pass 1 validated everything, so failures here are rare (sled I/O
        // errors or commitment tree overflow) but we must not leave state
        // partially modified.
        let nullifier_hash_before = self.nullifier_hash;
        let commitment_count_before = self.commitments.len();
        let tree_leaves_before = self.commitment_tree.num_leaves();
        let mut applied_nullifiers: Vec<Nullifier> = Vec::new();
        let mut registered_validators: Vec<(Hash, bool, u64)> = Vec::new(); // (id, was_reregistration, old_bond)
        let mut deregistered_validators: Vec<(Hash, u64)> = Vec::new(); // (id, bond)

        // Pass 2 — apply all transactions sequentially.
        // May fail if sled nullifier persistence fails (S5 fix).
        for tx in &vertex.transactions {
            let tx_nullifiers: Vec<Nullifier> = tx.inputs.iter().map(|i| i.nullifier).collect();
            // Snapshot validator state before applying (for rollback)
            let pre_apply_info = match &tx.tx_type {
                TxType::ValidatorRegister { signing_key, .. } => {
                    let vid = signing_key.fingerprint();
                    let is_reregistration = self.validators.contains_key(&vid);
                    // Capture old bond for re-registrations so it can be restored on rollback
                    let old_bond = self.validator_bonds.get(&vid).copied().unwrap_or(0);
                    Some((true, vid, old_bond, is_reregistration))
                }
                TxType::ValidatorDeregister { validator_id, .. } => {
                    let bond = self.validator_bonds.get(validator_id).copied().unwrap_or(0);
                    Some((false, *validator_id, bond, false))
                }
                _ => None,
            };
            match self.apply_transaction_unchecked(tx) {
                Ok(()) => {
                    applied_nullifiers.extend(tx_nullifiers);
                    if let Some((is_register, vid, old_bond, is_rereg)) = pre_apply_info {
                        if is_register {
                            registered_validators.push((vid, is_rereg, old_bond));
                        } else {
                            deregistered_validators.push((vid, old_bond));
                        }
                    }
                }
                Err(e) => {
                    // Rollback: restore state to pre-Pass-2 condition
                    self.epoch_fees = fees_before;
                    self.nullifier_hash = nullifier_hash_before;
                    // Complete the full rollback loop before returning, but
                    // track sled failures. If any sled removal fails, the nullifier
                    // remains as "spent" in persistent storage (fail-closed: safe
                    // against double-spend, but locks the UTXO permanently).
                    let mut rollback_err: Option<String> = None;
                    for n in &applied_nullifiers {
                        self.nullifiers.remove(n);
                        if let Some(ref tree) = self.nullifier_storage {
                            if let Err(sled_err) = tree.remove(n.0) {
                                tracing::error!(
                                    error = %sled_err,
                                    "Failed to roll back nullifier from sled during vertex rollback"
                                );
                                if rollback_err.is_none() {
                                    rollback_err = Some(sled_err.to_string());
                                }
                            }
                        }
                    }
                    for c in self.commitments.drain(commitment_count_before..) {
                        self.commitment_index.remove(&c);
                    }
                    self.commitment_tree.truncate(tree_leaves_before);
                    // Undo validator registrations
                    for (vid, is_rereg, old_bond) in &registered_validators {
                        if *is_rereg {
                            // Undo re-registration: set back to inactive and restore old bond
                            if let Some(v) = self.validators.get_mut(vid) {
                                v.active = false;
                            }
                            if *old_bond > 0 {
                                self.validator_bonds.insert(*vid, *old_bond);
                            } else {
                                self.validator_bonds.remove(vid);
                            }
                        } else {
                            // Undo new registration: remove entirely
                            self.validators.remove(vid);
                            self.validator_bonds.remove(vid);
                        }
                    }
                    // Undo validator deregistrations (re-activate and restore bond)
                    for (vid, bond) in &deregistered_validators {
                        if let Some(v) = self.validators.get_mut(vid) {
                            v.active = true;
                        }
                        self.validator_bonds.insert(*vid, *bond);
                    }
                    // If sled rollback failed, return a storage error instead
                    // of the original error to surface the persistence issue.
                    if let Some(sled_msg) = rollback_err {
                        return Err(StateError::StoragePersistenceFailed(format!(
                            "nullifier rollback failed (sled): {}",
                            sled_msg
                        )));
                    }
                    return Err(e);
                }
            }
        }

        // Compute vertex fees for the proposer's coinbase reward.
        // Don't reset epoch_fees — fees accumulate for epoch-level accounting
        // (advance_epoch returns and resets the total). The proposer receives
        // vertex_fees via coinbase output as an additional reward.
        let vertex_fees = self.epoch_fees.saturating_sub(fees_before);

        // Compute total coinbase amount.
        // Use self.epoch (canonical chain epoch) instead of vertex.epoch to prevent
        // a malicious proposer from claiming a higher reward by setting a fake epoch.
        let block_reward = crate::constants::block_reward_for_epoch(self.epoch);
        let total_coinbase = block_reward.saturating_add(vertex_fees);

        // Create coinbase output for the proposer
        let coinbase = if total_coinbase > 0 {
            let output = self.create_coinbase_output(&vertex.id, &vertex.proposer, total_coinbase);
            if output.is_none() {
                // Log when coinbase creation fails despite non-zero reward.
                // This typically means the proposer has no KEM public key registered,
                // so the reward is effectively burned.
                tracing::warn!(
                    vertex_id = hex::encode(&vertex.id.0[..8]),
                    total_coinbase,
                    "coinbase output creation returned None for non-zero reward; \
                     proposer may lack a registered KEM public key"
                );
            }
            output
        } else {
            None
        };

        self.last_finalized = Some(vertex.id);
        Ok(coinbase)
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
            if self.is_spent(&input.nullifier) {
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
            TxType::ValidatorRegister { signing_key, .. } => {
                let vid = signing_key.fingerprint();
                // Allow re-registration if the validator was previously deregistered
                // (inactive). Only reject if already active or slashed.
                if let Some(existing) = self.validators.get(&vid) {
                    if existing.active {
                        return Err(StateError::ValidatorAlreadyRegistered);
                    }
                }
                if self.slashed_validators.contains(&vid) {
                    return Err(StateError::ValidatorSlashed);
                }
                // Dynamic bond check: the required bond scales with active validator count
                let required_bond =
                    crate::constants::required_validator_bond(self.total_validators());
                let min_fee = required_bond.saturating_add(crate::constants::MIN_TX_FEE);
                if tx.fee < min_fee {
                    return Err(StateError::InsufficientBond);
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
                // Verify that the bond return commitment opens to the escrowed bond amount
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
        self.apply_transaction_unchecked(tx)?;
        Ok(())
    }

    /// Apply a pre-validated transaction to the state (no validation).
    ///
    /// SAFETY: The caller MUST have called `validate_transaction` first.
    /// Returns an error if nullifier persistence to sled storage fails.
    fn apply_transaction_unchecked(&mut self, tx: &Transaction) -> Result<(), StateError> {
        // Record nullifiers (with incremental hash update)
        for input in &tx.inputs {
            self.record_nullifier(input.nullifier)?;
        }

        // Add new output commitments (incremental tree update, O(log n) each)
        for output in &tx.outputs {
            self.add_commitment(output.commitment)?;
        }

        // Handle transaction type
        match &tx.tx_type {
            TxType::Transfer => {
                // Standard fee collection
                self.epoch_fees = self.epoch_fees.saturating_add(tx.fee);
            }
            TxType::ValidatorRegister {
                signing_key,
                kem_public_key,
            } => {
                let vid = signing_key.fingerprint();

                // Re-check bond requirement at application time to prevent
                // TOCTOU if total_validators() changed since validation.
                let bond = crate::constants::required_validator_bond(self.total_validators());
                let min_fee = bond.saturating_add(crate::constants::MIN_TX_FEE);
                if tx.fee < min_fee {
                    return Err(StateError::InsufficientBond);
                }

                // Escrow bond (scaled by current active validator count), remainder
                // goes to epoch fees. Compute BEFORE updating active status.
                let actual_fee = tx.fee.saturating_sub(bond);
                self.epoch_fees = self.epoch_fees.saturating_add(actual_fee);

                if let Some(existing) = self.validators.get_mut(&vid) {
                    // Re-registration of a previously deregistered validator
                    existing.active = true;
                    existing.activation_epoch = self.epoch + 1;
                    existing.kem_public_key = Some(kem_public_key.clone());
                } else {
                    // New registration
                    let mut validator =
                        Validator::with_kem(signing_key.clone(), kem_public_key.clone());
                    validator.activation_epoch = self.epoch + 1;
                    self.register_validator(validator);
                }

                self.validator_bonds.insert(vid, bond);
            }
            TxType::ValidatorDeregister {
                validator_id,
                bond_return_output,
                ..
            } => {
                // Return bond as output commitment (already verified in validate_transaction)
                self.add_commitment(bond_return_output.commitment)?;

                // Mark inactive and remove bond
                if let Some(v) = self.validators.get_mut(validator_id) {
                    v.active = false;
                }
                self.validator_bonds.remove(validator_id);

                // Collect fee
                self.epoch_fees = self.epoch_fees.saturating_add(tx.fee);
            }
        }
        Ok(())
    }

    /// Record a nullifier as spent, updating the incremental hash accumulator.
    ///
    /// Returns an error if sled persistence fails, so the caller can abort the
    /// vertex/transaction application instead of silently allowing a nullifier
    /// that won't survive a restart.
    fn record_nullifier(&mut self, nullifier: Nullifier) -> Result<(), StateError> {
        if self.nullifiers.contains(&nullifier) {
            return Ok(()); // already recorded
        }
        // Persist to sled FIRST — if it fails, in-memory state is unchanged,
        // so on restart the nullifier won't be in memory either (consistent).
        if let Some(ref tree) = self.nullifier_storage {
            if let Err(e) = tree.insert(nullifier.0, &[1u8]) {
                return Err(StateError::StoragePersistenceFailed(format!(
                    "failed to persist nullifier to sled: {}",
                    e
                )));
            }
        }
        self.nullifiers.insert(nullifier);
        // Update incremental hash: new = H(old || nullifier)
        self.nullifier_hash =
            crate::hash_concat(&[b"umbra.nullifier_acc", &self.nullifier_hash, &nullifier.0]);
        Ok(())
    }

    /// Add a single commitment to the incremental Merkle tree.
    pub fn add_commitment(&mut self, commitment: Commitment) -> Result<(), StateError> {
        self.commitment_tree
            .append(commitment.0)
            .map_err(StateError::CommitmentTreeFull)?;
        self.commitments.push(commitment);
        self.commitment_index
            .insert(commitment, self.commitments.len() - 1);
        Ok(())
    }

    /// Record a nullifier as spent (public API).
    ///
    /// Returns an error if sled-backed nullifier persistence fails.
    pub fn mark_nullifier(&mut self, nullifier: Nullifier) -> Result<(), StateError> {
        self.record_nullifier(nullifier)
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
        self.commitment_index.get(commitment).copied()
    }

    /// Check if a nullifier has been used.
    ///
    /// Checks in-memory set first, then falls back to sled storage if present.
    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        if self.nullifiers.contains(nullifier) {
            return true;
        }
        // Fall back to sled storage if available
        if let Some(ref tree) = self.nullifier_storage {
            return match tree.contains_key(nullifier.0) {
                Ok(found) => found,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "Sled I/O error during nullifier lookup; treating as spent (fail-closed)"
                    );
                    true // fail-closed: treat I/O errors as spent to prevent double-spend
                }
            };
        }
        false
    }

    /// Register a validator (internal — use apply_transaction for public API).
    fn register_validator(&mut self, validator: Validator) {
        self.validators.insert(validator.id, validator);
    }

    /// Register a genesis validator (bond escrowed without requiring a funding tx).
    pub fn register_genesis_validator(&mut self, validator: Validator) {
        let id = validator.id;
        self.validator_bonds
            .insert(id, crate::constants::VALIDATOR_BASE_BOND);
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

    /// Get validators eligible for committee selection in the given epoch.
    ///
    /// A validator is eligible if it is active and its activation_epoch <= epoch.
    pub fn eligible_validators(&self, epoch: u64) -> Vec<&Validator> {
        self.validators
            .values()
            .filter(|v| v.active && v.activation_epoch <= epoch)
            .collect()
    }

    /// Count of active validators.
    pub fn total_validators(&self) -> usize {
        // Count directly instead of allocating a Vec
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

    /// Get the total number of spent nullifiers (in-memory + migrated to sled).
    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len() + self.migrated_nullifier_count
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
    ///
    /// Includes a deterministic hash over the full validator set (sorted by ID)
    /// so that two nodes with different validator registries will compute
    /// different state roots, preventing silent state divergence.
    pub fn state_root(&self) -> Hash {
        let root = self.commitment_tree.root();
        let validator_hash = self.validator_set_hash();
        crate::hash_concat(&[
            b"umbra.state_root",
            &root,
            &self.nullifier_hash,
            &self.epoch.to_le_bytes(),
            &self.epoch_fees.to_le_bytes(),
            &validator_hash,
            &self.total_minted.to_le_bytes(),
        ])
    }

    /// Compute a deterministic hash over the full validator set.
    ///
    /// Validators are sorted by ID to ensure deterministic ordering regardless
    /// of HashMap iteration order. Each validator's ID, active status, bond,
    /// and slashed status are included in the hash.
    fn validator_set_hash(&self) -> Hash {
        let mut sorted_ids: Vec<&Hash> = self.validators.keys().collect();
        sorted_ids.sort();

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"umbra.validator_set");
        hasher.update(&(sorted_ids.len() as u64).to_le_bytes());
        for vid in sorted_ids {
            hasher.update(vid);
            let active = self.validators.get(vid).map(|v| v.active).unwrap_or(false);
            hasher.update(&[active as u8]);
            let bond = self.validator_bonds.get(vid).copied().unwrap_or(0);
            hasher.update(&bond.to_le_bytes());
            let slashed = self.slashed_validators.contains(vid) as u8;
            hasher.update(&[slashed]);
        }
        *hasher.finalize().as_bytes()
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

    /// Attach sled-backed nullifier storage for scalability.
    ///
    /// After calling this, new nullifiers are written to both memory and sled,
    /// and `is_spent()` falls back to sled for lookups not in memory.
    pub fn set_nullifier_storage(&mut self, tree: sled::Tree) {
        self.nullifier_storage = Some(tree);
    }

    /// Migrate in-memory nullifiers to sled storage.
    ///
    /// Writes all current in-memory nullifiers to the sled tree, then clears
    /// the in-memory set to free RAM. After migration, `is_spent()` reads from
    /// sled and new nullifiers are written to both sled and a fresh in-memory set.
    pub fn migrate_nullifiers_to_storage(&mut self, tree: sled::Tree) -> Result<usize, String> {
        let count = self.nullifiers.len();
        for nullifier in self.nullifiers.iter() {
            tree.insert(nullifier.0, &[1u8])
                .map_err(|e| format!("sled write failed during migration: {}", e))?;
        }
        self.migrated_nullifier_count += count;
        self.nullifiers = NullifierSet::new();
        self.nullifier_storage = Some(tree);
        Ok(count)
    }

    /// Get the current epoch seed for VRF evaluation.
    pub fn epoch_seed(&self) -> &EpochSeed {
        &self.epoch_seed
    }

    // ── Persistence / Restoration ──────────────────────────────────────

    /// Create a `ChainStateMeta` snapshot for storage persistence.
    pub fn to_chain_state_meta(&self, finalized_count: u64) -> ChainStateMeta {
        ChainStateMeta {
            epoch: self.epoch,
            last_finalized: self.last_finalized,
            state_root: self.state_root(),
            commitment_root: self.commitment_root(),
            commitment_count: self.commitments.len() as u64,
            nullifier_count: self.nullifier_count() as u64,
            nullifier_hash: self.nullifier_hash,
            epoch_fees: self.epoch_fees,
            validator_count: self.validators.values().filter(|v| v.active).count() as u64,
            epoch_seed: self.epoch_seed.seed,
            finalized_count,
            total_minted: self.total_minted,
        }
    }

    /// Create a full state snapshot for transfer to a bootstrapping node.
    ///
    /// Collects all state components (metadata, validators, commitment tree
    /// nodes, nullifiers) into a single serializable structure.
    pub fn to_snapshot_data(
        &self,
        storage: &dyn Storage,
        finalized_count: u64,
    ) -> Result<SnapshotData, StateError> {
        let meta = self.to_chain_state_meta(finalized_count);

        let validators = storage
            .get_all_validators()
            .map_err(|e| StateError::StorageError(e.to_string()))?;

        let commitment_levels = storage
            .get_all_commitment_levels()
            .map_err(|e| StateError::StorageError(e.to_string()))?;

        let nullifiers: Vec<Hash> = storage
            .get_all_nullifiers()
            .map_err(|e| StateError::StorageError(e.to_string()))?
            .into_iter()
            .map(|n| n.0)
            .collect();

        Ok(SnapshotData {
            meta,
            validators,
            commitment_levels,
            nullifiers,
        })
    }

    /// Get a commitment tree node hash (for incremental persistence).
    pub fn commitment_tree_node(&self, level: usize, index: usize) -> Hash {
        self.commitment_tree.get_node_public(level, index)
    }

    /// Get the number of stored nodes at a commitment tree level.
    pub fn commitment_tree_level_len(&self, level: usize) -> usize {
        self.commitment_tree.level_len(level)
    }

    /// Return the path of nodes modified by the most recent commitment append.
    pub fn commitment_tree_last_path(&self) -> Vec<(usize, usize, Hash)> {
        self.commitment_tree.last_appended_path()
    }

    /// Get the total coins ever minted via coinbase rewards.
    pub fn total_minted(&self) -> u64 {
        self.total_minted
    }

    // ── Coinbase Output Creation ──────────────────────────────────────

    /// Derive a deterministic blinding factor for a coinbase output.
    ///
    /// Uses the vertex ID and epoch as input so the blinding is publicly
    /// verifiable (coinbase amounts are public anyway).
    fn coinbase_blinding(vertex_id: &VertexId, epoch: u64) -> BlindingFactor {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&vertex_id.0);
        data.extend_from_slice(&epoch.to_le_bytes());
        let hash = crate::hash_domain(b"umbra.coinbase.blinding", &data);
        BlindingFactor::from_bytes(hash)
    }

    /// Encode coinbase note data (same 40-byte format as transaction builder).
    fn encode_coinbase_note(value: u64, blinding: &BlindingFactor) -> Vec<u8> {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&value.to_le_bytes());
        data.extend_from_slice(&blinding.0);
        data
    }

    /// Create a coinbase output for the vertex proposer.
    ///
    /// Looks up the proposer's KEM public key from the validator registry,
    /// generates a stealth address, encrypts the note, and adds the
    /// commitment to the Merkle tree. Returns `None` if the proposer is
    /// not a registered validator or lacks a KEM public key.
    fn create_coinbase_output(
        &mut self,
        vertex_id: &VertexId,
        proposer: &crate::crypto::keys::SigningPublicKey,
        amount: u64,
    ) -> Option<TxOutput> {
        // Look up proposer's validator record
        let vid = proposer.fingerprint();
        let kem_pk = self.validators.get(&vid)?.kem_public_key.as_ref()?.clone();

        // Deterministic blinding factor (coinbase amounts are public)
        let blinding = Self::coinbase_blinding(vertex_id, self.epoch);
        let commitment = Commitment::commit(amount, &blinding);

        // Generate stealth address (output index 0 — coinbase has a single output)
        let stealth_result = StealthAddress::generate(&kem_pk, 0)?;
        let stealth_address = stealth_result.address;

        // Encrypt note data reusing the stealth KEM shared secret
        let note_data = Self::encode_coinbase_note(amount, &blinding);
        let encrypted_note = EncryptedPayload::encrypt_with_shared_secret(
            &stealth_result.shared_secret,
            stealth_address.kem_ciphertext.clone(),
            &note_data,
        )?;

        // Add commitment to the Merkle tree
        if let Err(e) = self.add_commitment(commitment) {
            tracing::error!(error = %e, "Failed to add coinbase commitment to Merkle tree");
            return None;
        }

        // Track total minted with supply cap enforcement
        self.total_minted = self
            .total_minted
            .checked_add(amount)
            .filter(|&total| total <= crate::constants::MAX_TOTAL_SUPPLY)?;

        let blake3_binding = crate::crypto::commitment::blake3_512_binding(amount, &blinding);
        Some(TxOutput {
            commitment,
            stealth_address,
            encrypted_note,
            blake3_binding,
        })
    }

    /// Create a genesis coinbase output for the initial coin distribution.
    ///
    /// Called once at network bootstrap to mint `GENESIS_MINT` coins to the
    /// genesis validator. Uses a deterministic blinding factor derived from
    /// the genesis domain so the amount is publicly verifiable.
    pub fn create_genesis_coinbase(
        &mut self,
        kem_pk: &crate::crypto::keys::KemPublicKey,
    ) -> Option<TxOutput> {
        let amount = crate::constants::GENESIS_MINT;

        // Deterministic blinding for genesis (no vertex ID, use a fixed domain)
        let hash = crate::hash_domain(b"umbra.genesis.blinding", b"genesis-coinbase");
        let blinding = BlindingFactor::from_bytes(hash);
        let commitment = Commitment::commit(amount, &blinding);

        // Generate stealth address (output index 0)
        let stealth_result = StealthAddress::generate(kem_pk, 0)?;
        let stealth_address = stealth_result.address;

        // Encrypt note data
        let note_data = Self::encode_coinbase_note(amount, &blinding);
        let encrypted_note = EncryptedPayload::encrypt_with_shared_secret(
            &stealth_result.shared_secret,
            stealth_address.kem_ciphertext.clone(),
            &note_data,
        )?;

        // Add commitment to the Merkle tree
        if let Err(e) = self.add_commitment(commitment) {
            tracing::error!(error = %e, "Failed to add genesis coinbase commitment to Merkle tree");
            return None;
        }
        // Track total minted with supply cap enforcement
        self.total_minted = self
            .total_minted
            .checked_add(amount)
            .filter(|&total| total <= crate::constants::MAX_TOTAL_SUPPLY)?;

        let blake3_binding = crate::crypto::commitment::blake3_512_binding(amount, &blinding);
        Some(TxOutput {
            commitment,
            stealth_address,
            encrypted_note,
            blake3_binding,
        })
    }

    /// Restore chain state from persistent storage.
    ///
    /// Rebuilds the commitment Merkle tree, nullifier set, validator registry,
    /// and epoch state from stored data. Verifies the restored commitment root
    /// matches the stored snapshot.
    pub fn restore_from_storage(
        storage: &dyn Storage,
        meta: &ChainStateMeta,
    ) -> Result<Self, StateError> {
        // 1. Rebuild the commitment Merkle tree from stored level data
        let num_leaves = meta.commitment_count as usize;
        let commitment_tree = IncrementalMerkleTree::restore(num_leaves, |level, idx| {
            storage.get_commitment_level(level, idx).ok().flatten()
        });

        // Verify restored root matches snapshot
        if commitment_tree.root() != meta.commitment_root {
            return Err(StateError::StorageError(
                "restored commitment root does not match stored snapshot".into(),
            ));
        }

        // Rebuild commitments Vec from tree leaves
        let mut commitments = Vec::with_capacity(num_leaves);
        for i in 0..num_leaves {
            commitments.push(Commitment(commitment_tree.get_node_public(0, i)));
        }

        let mut commitment_index = HashMap::new();
        for (i, c) in commitments.iter().enumerate() {
            commitment_index.insert(*c, i);
        }

        // 2. Load all nullifiers from storage
        let stored_nullifiers = storage
            .get_all_nullifiers()
            .map_err(|e| StateError::StorageError(e.to_string()))?;
        let mut nullifiers = NullifierSet::new();
        for n in &stored_nullifiers {
            nullifiers.insert(*n);
        }

        // Verify nullifier count matches
        if nullifiers.len() as u64 != meta.nullifier_count {
            return Err(StateError::StorageError(format!(
                "nullifier count mismatch: stored {} vs meta {}",
                nullifiers.len(),
                meta.nullifier_count
            )));
        }

        // 3. Load all validators from storage
        let validator_records = storage
            .get_all_validators()
            .map_err(|e| StateError::StorageError(e.to_string()))?;
        let mut validators = HashMap::new();
        let mut validator_bonds = HashMap::new();
        let mut slashed_validators = HashSet::new();
        for record in validator_records {
            let vid = record.validator.id;
            if record.slashed {
                slashed_validators.insert(vid);
            }
            if record.bond > 0 {
                validator_bonds.insert(vid, record.bond);
            }
            validators.insert(vid, record.validator);
        }

        // 4. Restore epoch state from meta
        let epoch_seed = EpochSeed {
            epoch: meta.epoch,
            seed: meta.epoch_seed,
        };

        Ok(ChainState {
            chain_id: crate::constants::chain_id(),
            commitments,
            commitment_tree,
            nullifiers,
            nullifier_storage: None,
            migrated_nullifier_count: 0,
            nullifier_hash: meta.nullifier_hash,
            validators,
            validator_bonds,
            slashed_validators,
            epoch_seed,
            epoch_fees: meta.epoch_fees,
            epoch: meta.epoch,
            last_finalized: meta.last_finalized,
            total_minted: meta.total_minted,
            commitment_index,
        })
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
    /// Requires a BFT certificate and the current committee for verification.
    /// The vertex must already be in the DAG (via `insert_vertex()`).
    /// Returns the coinbase output if one was created.
    pub fn finalize_vertex(
        &mut self,
        vertex_id: &VertexId,
        certificate: &crate::consensus::bft::Certificate,
        committee: &[crate::consensus::bft::Validator],
        chain_id: &Hash,
    ) -> Result<Option<TxOutput>, StateError> {
        // Verify BFT certificate before finalizing
        if !certificate.verify(committee, chain_id) {
            return Err(StateError::InvalidCertificate);
        }
        if certificate.vertex_id != *vertex_id {
            return Err(StateError::InvalidCertificate);
        }
        self.dag.finalize(vertex_id);
        if let Some(v) = self.dag.get(vertex_id) {
            let v = v.clone();
            return self.state.apply_vertex(&v);
        }
        Ok(None)
    }

    /// Finalize a vertex without certificate verification (internal use only).
    ///
    /// Used by `apply_finalized_vertex` (sync path) where the certificate has
    /// already been verified or the vertex is accepted on trust from a sync peer.
    /// Also used by `finalize_vertex_inner` in node.rs where the certificate
    /// was verified before calling this method.
    pub(crate) fn finalize_vertex_unchecked(
        &mut self,
        vertex_id: &VertexId,
    ) -> Result<Option<TxOutput>, StateError> {
        // Guard against double-application: if the vertex is already finalized,
        // applying its transactions again would corrupt state (double-spend, etc.).
        if self.dag.is_finalized(vertex_id) {
            return Ok(None);
        }
        self.dag.finalize(vertex_id);
        if let Some(v) = self.dag.get(vertex_id) {
            let v = v.clone();
            return self.state.apply_vertex(&v);
        }
        Ok(None)
    }

    /// Apply a finalized vertex: insert into DAG, finalize, and update state.
    ///
    /// Used during sync where the vertex is accepted from a trusted sync peer.
    /// Validates vertex structure including proposer signature. Returns the
    /// coinbase output if one was created.
    pub fn apply_finalized_vertex(
        &mut self,
        vertex: Vertex,
    ) -> Result<Option<TxOutput>, StateError> {
        let id = vertex.id;
        self.insert_vertex(vertex)?;
        self.finalize_vertex_unchecked(&id)
    }

    /// Apply a vertex directly to state without DAG insertion.
    ///
    /// Used during post-snapshot catch-up sync where the DAG does not have
    /// the vertex's parents (they were part of the snapshot, not replayed).
    pub fn apply_vertex_state_only(
        &mut self,
        vertex: &Vertex,
    ) -> Result<Option<TxOutput>, StateError> {
        self.state.apply_vertex(vertex)
    }

    /// Restore a ledger from persistent storage.
    ///
    /// Rebuilds the chain state from stored data and creates a fresh genesis-only
    /// DAG. Unfinalized vertices are lost on restart (acceptable since they were
    /// not BFT-certified).
    pub fn restore_from_storage(
        storage: &dyn Storage,
        meta: &ChainStateMeta,
    ) -> Result<Self, StateError> {
        let state = ChainState::restore_from_storage(storage, meta)?;
        let genesis = crate::consensus::dag::Dag::genesis_vertex();
        let dag = crate::consensus::dag::Dag::new(genesis);
        Ok(Ledger { dag, state })
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
    #[error("storage error during state restoration: {0}")]
    StorageError(String),
    #[error("storage persistence failed: {0}")]
    StoragePersistenceFailed(String),
    #[error("vertex contains too many transactions")]
    TooManyTransactions,
    #[error("commitment tree full: {0}")]
    CommitmentTreeFull(String),
    #[error("vertex epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },
    #[error("invalid or missing BFT certificate")]
    InvalidCertificate,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::dag::{Vertex, VertexId};
    use crate::crypto::commitment::{BlindingFactor, Commitment};
    use crate::crypto::keys::{
        FullKeypair, KemKeypair, Signature, SigningKeypair, SigningPublicKey,
    };
    use crate::crypto::nullifier::Nullifier;
    use crate::crypto::stark::spend_air::MERKLE_DEPTH;
    use crate::node::storage::SledStorage;
    use crate::transaction::builder::{InputSpec, TransactionBuilder};
    use crate::transaction::Transaction;

    fn test_proof_options() -> winterfell::ProofOptions {
        winterfell::ProofOptions::new(
            42,
            8,
            10,
            winterfell::FieldExtension::Cubic,
            8,
            255,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        )
    }

    /// Build a valid transfer transaction that spends a commitment already in the state.
    /// The commitment is added to the state before building the tx, so the merkle root matches.
    ///
    /// The fee is auto-computed by the builder (1 input, 1 output, no messages = 300).
    /// `value` must be greater than 300 so there is a positive output amount.
    fn build_valid_tx_for_state(state: &mut ChainState, value: u64, seed: u8) -> Transaction {
        // Deterministic fee for 1 input, 1 output, no messages = 300
        let det_fee = crate::constants::compute_weight_fee(1, 0);
        assert!(
            value > det_fee,
            "input value must exceed deterministic fee ({})",
            det_fee
        );

        let blinding = BlindingFactor::from_bytes([seed; 32]);
        let spend_auth = crate::hash_domain(b"test.spend_auth", &[seed]);
        let commitment = Commitment::commit(value, &blinding);

        // Add the commitment to the state so the merkle root in the spend proof matches
        state.add_commitment(commitment).unwrap();
        let index = state.find_commitment(&commitment).unwrap();
        let merkle_path = state.commitment_path(index).unwrap();

        let recipient = FullKeypair::generate();
        TransactionBuilder::new()
            .add_input(InputSpec {
                value,
                blinding,
                spend_auth,
                merkle_path,
            })
            .add_output(recipient.kem.public.clone(), value - det_fee)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap()
    }

    /// Create a test vertex containing given transactions, with a specific proposer key.
    /// Uses insert_unchecked pattern (skips signature verification).
    fn make_test_vertex(
        parents: Vec<VertexId>,
        round: u64,
        epoch: u64,
        proposer: &SigningPublicKey,
        transactions: Vec<Transaction>,
    ) -> Vertex {
        let proposer_fp = proposer.fingerprint();
        // Compute tx_root
        let tx_root = if transactions.is_empty() {
            [0u8; 32]
        } else {
            let tx_hashes: Vec<crate::Hash> = transactions.iter().map(|tx| tx.tx_id().0).collect();
            let (root, _) = crate::crypto::proof::build_merkle_tree(&tx_hashes);
            root
        };
        let id = Vertex::compute_id(
            &parents,
            epoch,
            round,
            &proposer_fp,
            &tx_root,
            None,
            &[0u8; 32],
            crate::constants::PROTOCOL_VERSION_ID,
        );
        Vertex {
            id,
            parents,
            epoch,
            round,
            proposer: proposer.clone(),
            transactions,
            timestamp: round * 1000,
            state_root: [0u8; 32],
            signature: Signature::empty(),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        }
    }

    /// Create a dummy (structurally incomplete) transaction for tests that check
    /// errors before full validation (e.g., intra-vertex duplicate nullifiers).
    fn make_dummy_tx_with_nullifier(nullifier: Nullifier) -> Transaction {
        let recipient = FullKeypair::generate();
        let blinding = BlindingFactor::random();
        let commitment = Commitment::commit(100, &blinding);
        let stealth_result =
            crate::crypto::stealth::StealthAddress::generate(&recipient.kem.public, 0).unwrap();
        let note_data = vec![0u8; 40];
        let encrypted_note =
            crate::crypto::encryption::EncryptedPayload::encrypt_with_shared_secret(
                &stealth_result.shared_secret,
                stealth_result.address.kem_ciphertext.clone(),
                &note_data,
            )
            .unwrap();
        Transaction {
            inputs: vec![crate::transaction::TxInput {
                nullifier,
                proof_link: [0u8; 32],
                spend_proof: crate::crypto::stark::types::SpendStarkProof {
                    proof_bytes: vec![],
                    public_inputs_bytes: vec![],
                },
            }],
            outputs: vec![crate::transaction::TxOutput {
                commitment,
                stealth_address: stealth_result.address,
                encrypted_note,
                blake3_binding: [0u8; 64],
            }],
            fee: 10,
            chain_id: crate::constants::chain_id(),
            expiry_epoch: 0,
            balance_proof: crate::crypto::stark::types::BalanceStarkProof {
                proof_bytes: vec![],
                public_inputs_bytes: vec![],
            },
            messages: vec![],
            tx_binding: [0u8; 32],
            tx_type: crate::transaction::TxType::Transfer,
        }
    }

    #[test]
    fn state_commitment_tree() {
        let mut state = ChainState::new();
        let blind = BlindingFactor::random();
        let c = Commitment::commit(100, &blind);

        state.add_commitment(c).unwrap();

        assert_ne!(state.commitment_root(), [0u8; 32]);
        assert_eq!(state.commitment_count(), 1);
        assert_eq!(state.find_commitment(&c), Some(0));
    }

    #[test]
    fn state_nullifier_tracking() {
        let mut state = ChainState::new();
        let n = Nullifier::derive(&[1u8; 32], &[2u8; 32]);

        assert!(!state.is_spent(&n));
        state.mark_nullifier(n).unwrap();
        assert!(state.is_spent(&n));
    }

    #[test]
    fn state_root_changes() {
        let mut state = ChainState::new();
        let root1 = state.state_root();

        let blind = BlindingFactor::random();
        state
            .add_commitment(Commitment::commit(100, &blind))
            .unwrap();

        let root2 = state.state_root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn state_root_commits_to_nullifiers() {
        let mut state1 = ChainState::new();
        let mut state2 = ChainState::new();

        let n = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        state1.mark_nullifier(n).unwrap();

        assert_ne!(state1.state_root(), state2.state_root());

        state2.mark_nullifier(n).unwrap();
        assert_eq!(state1.state_root(), state2.state_root());
    }

    #[test]
    fn canonical_root_consistency() {
        let mut state = ChainState::new();
        let blind = BlindingFactor::random();
        let c = Commitment::commit(100, &blind);
        state.add_commitment(c).unwrap();

        // The path should produce the same root
        let path = state.commitment_path(0).unwrap();
        assert_eq!(path.len(), MERKLE_DEPTH);
        let root_from_path = crate::crypto::proof::compute_merkle_root(&c.0, &path);
        assert_eq!(root_from_path, state.commitment_root());
    }

    #[test]
    fn chain_state_persist_restore_roundtrip() {
        let storage = SledStorage::open_temporary().unwrap();

        // Build up some state
        let mut state = ChainState::new();

        // Add commitments
        for i in 0..5u64 {
            let blind = BlindingFactor::from_bytes([i as u8; 32]);
            state
                .add_commitment(Commitment::commit(i * 100 + 1, &blind))
                .unwrap();
        }

        // Add nullifiers
        let n1 = Nullifier::derive(&[10u8; 32], &[20u8; 32]);
        let n2 = Nullifier::derive(&[30u8; 32], &[40u8; 32]);
        state.mark_nullifier(n1).unwrap();
        state.mark_nullifier(n2).unwrap();

        // Register a validator
        let kp = SigningKeypair::generate();
        let validator = Validator::new(kp.public.clone());
        let vid = validator.id;
        state.register_genesis_validator(validator.clone());

        // Advance epoch
        state.advance_epoch();

        let original_root = state.state_root();
        let original_commitment_root = state.commitment_root();
        let original_nullifier_hash = *state.nullifier_hash();

        // Persist to storage
        let finalized_count = 3u64;
        let meta = state.to_chain_state_meta(finalized_count);

        // Store commitment tree levels
        for level in 0..=MERKLE_DEPTH {
            for idx in 0..state.commitment_tree_level_len(level) {
                let hash = state.commitment_tree_node(level, idx);
                storage.put_commitment_level(level, idx, &hash).unwrap();
            }
        }

        // Store nullifiers
        storage.put_nullifier(&n1).unwrap();
        storage.put_nullifier(&n2).unwrap();

        // Store validators
        let bond = state.validator_bond(&vid).unwrap();
        storage.put_validator(&validator, bond, false).unwrap();

        // Store meta
        storage.put_chain_state_meta(&meta).unwrap();

        // Restore
        let restored = ChainState::restore_from_storage(&storage, &meta).unwrap();

        // Verify everything matches
        assert_eq!(restored.commitment_root(), original_commitment_root);
        assert_eq!(restored.commitment_count(), 5);
        assert_eq!(*restored.nullifier_hash(), original_nullifier_hash);
        assert_eq!(restored.nullifier_count(), 2);
        assert!(restored.is_spent(&n1));
        assert!(restored.is_spent(&n2));
        assert!(restored.is_active_validator(&vid));
        assert_eq!(
            restored.validator_bond(&vid),
            Some(crate::constants::VALIDATOR_BASE_BOND)
        );
        assert_eq!(restored.epoch(), 1);
        assert_eq!(restored.state_root(), original_root);

        // Verify commitment paths still work
        for i in 0..5 {
            let path = restored.commitment_path(i).unwrap();
            assert_eq!(path.len(), MERKLE_DEPTH);
        }
    }

    #[test]
    fn chain_state_meta_snapshot() {
        let mut state = ChainState::new();
        let blind = BlindingFactor::random();
        state
            .add_commitment(Commitment::commit(42, &blind))
            .unwrap();
        state
            .mark_nullifier(Nullifier::derive(&[1u8; 32], &[2u8; 32]))
            .unwrap();

        let meta = state.to_chain_state_meta(7);

        assert_eq!(meta.epoch, 0);
        assert_eq!(meta.commitment_count, 1);
        assert_eq!(meta.nullifier_count, 1);
        assert_eq!(meta.commitment_root, state.commitment_root());
        assert_eq!(meta.state_root, state.state_root());
        assert_eq!(meta.nullifier_hash, *state.nullifier_hash());
        assert_eq!(meta.finalized_count, 7);
    }

    #[test]
    fn register_genesis_validator_and_query() {
        let mut state = ChainState::new();
        let kp = SigningKeypair::generate();
        let v = Validator::new(kp.public.clone());
        let vid = v.id;

        state.register_genesis_validator(v);

        assert!(state.is_active_validator(&vid));
        assert!(state.get_validator(&vid).is_some());
        assert_eq!(state.active_validators().len(), 1);
        assert_eq!(state.total_validators(), 1);
        assert_eq!(
            state.validator_bond(&vid),
            Some(crate::constants::VALIDATOR_BASE_BOND)
        );
    }

    #[test]
    fn slash_validator_forfeits_bond() {
        let mut state = ChainState::new();
        let kp = SigningKeypair::generate();
        let v = Validator::new(kp.public.clone());
        let vid = v.id;

        state.register_genesis_validator(v);
        assert_eq!(state.epoch_fees(), 0);

        state.slash_validator(&vid).unwrap();

        assert!(state.is_slashed(&vid));
        assert!(!state.is_active_validator(&vid));
        assert_eq!(state.epoch_fees(), crate::constants::VALIDATOR_BASE_BOND);
        assert_eq!(state.validator_bond(&vid), None); // Bond forfeited
    }

    #[test]
    fn advance_epoch_clears_fees_and_rotates_seed() {
        let mut state = ChainState::new();
        let kp = SigningKeypair::generate();
        let v = Validator::new(kp.public.clone());
        state.register_genesis_validator(v);

        // Slash to accumulate fees
        let vid = kp.public.fingerprint();
        state.slash_validator(&vid).unwrap();
        assert!(state.epoch_fees() > 0);

        let seed_before = state.epoch_seed().clone();
        assert_eq!(state.epoch(), 0);

        let (fees, _new_seed) = state.advance_epoch();

        assert_eq!(fees, crate::constants::VALIDATOR_BASE_BOND);
        assert_eq!(state.epoch(), 1);
        assert_eq!(state.epoch_fees(), 0);
        assert_ne!(state.epoch_seed().seed, seed_before.seed);
    }

    #[test]
    fn all_validators_includes_inactive() {
        let mut state = ChainState::new();
        let kp = SigningKeypair::generate();
        let v = Validator::new(kp.public.clone());
        let vid = v.id;
        state.register_genesis_validator(v);

        // Slash makes it inactive
        state.slash_validator(&vid).unwrap();
        assert!(!state.is_active_validator(&vid));

        // But still in all_validators
        let all = state.all_validators();
        assert_eq!(all.len(), 1);
        assert!(!all[0].active);
    }

    #[test]
    fn state_tracks_last_finalized() {
        let mut state = ChainState::new();
        assert!(state.last_finalized().is_none());

        let vid = VertexId([42u8; 32]);
        state.last_finalized = Some(vid);
        assert_eq!(state.last_finalized(), Some(&vid));
    }

    #[test]
    fn ledger_restore_from_storage() {
        let storage = SledStorage::open_temporary().unwrap();

        // Build some state
        let mut state = ChainState::new();
        let blind = BlindingFactor::from_bytes([1u8; 32]);
        state
            .add_commitment(Commitment::commit(500, &blind))
            .unwrap();

        let meta = state.to_chain_state_meta(0);

        // Persist commitment tree
        for level in 0..=MERKLE_DEPTH {
            for idx in 0..state.commitment_tree_level_len(level) {
                let hash = state.commitment_tree_node(level, idx);
                storage.put_commitment_level(level, idx, &hash).unwrap();
            }
        }
        storage.put_chain_state_meta(&meta).unwrap();

        // Restore as ledger
        let ledger = Ledger::restore_from_storage(&storage, &meta).unwrap();
        assert_eq!(ledger.state.commitment_root(), state.commitment_root());
        assert_eq!(ledger.state.commitment_count(), 1);
        // DAG should have genesis only
        assert_eq!(ledger.dag.len(), 1);
    }

    #[test]
    fn sled_backed_nullifier_lookup() {
        let db = sled::Config::new().temporary(true).open().unwrap();
        let tree = db.open_tree("nullifiers").unwrap();

        let mut state = ChainState::new();
        state.set_nullifier_storage(tree);

        let n = Nullifier::derive(&[10u8; 32], &[20u8; 32]);
        assert!(!state.is_spent(&n));

        state.mark_nullifier(n).unwrap();
        assert!(state.is_spent(&n));

        // Also verify sled has it
        let sled_tree = state.nullifier_storage.as_ref().unwrap();
        assert!(sled_tree.contains_key(n.0).unwrap());
    }

    #[test]
    fn migrate_nullifiers_to_storage() {
        let mut state = ChainState::new();

        // Add nullifiers to in-memory set
        let n1 = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        let n2 = Nullifier::derive(&[3u8; 32], &[4u8; 32]);
        state.mark_nullifier(n1).unwrap();
        state.mark_nullifier(n2).unwrap();
        assert_eq!(state.nullifier_count(), 2);

        // Migrate to sled
        let db = sled::Config::new().temporary(true).open().unwrap();
        let tree = db.open_tree("nullifiers").unwrap();
        let migrated = state.migrate_nullifiers_to_storage(tree).unwrap();
        assert_eq!(migrated, 2);

        // In-memory is empty, but is_spent still works via sled
        assert_eq!(state.nullifiers.len(), 0);
        assert!(state.is_spent(&n1));
        assert!(state.is_spent(&n2));

        // New nullifiers go to both sled and memory
        let n3 = Nullifier::derive(&[5u8; 32], &[6u8; 32]);
        state.mark_nullifier(n3).unwrap();
        assert!(state.is_spent(&n3));
        assert_eq!(state.nullifiers.len(), 1);
    }

    // ── New tests ─────────────────────────────────────────────────────

    #[test]
    fn apply_vertex_basic() {
        let mut state = ChainState::new();

        // Register a validator (with KEM key so coinbase can be created)
        let val_signing = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let validator = Validator::with_kem(val_signing.public.clone(), val_kem.public.clone());
        state.register_genesis_validator(validator);

        let genesis_id = VertexId(crate::hash_domain(b"umbra.genesis", b"umbra-mainnet"));

        // Build a valid transaction against the current state
        // Deterministic fee for 1 input, 1 output, no messages = 300
        let det_fee = crate::constants::compute_weight_fee(1, 0);
        let tx = build_valid_tx_for_state(&mut state, 1000, 1);
        let tx_nullifier = tx.inputs[0].nullifier;
        let tx_output_commitment = tx.outputs[0].commitment;

        let commitments_before = state.commitment_count();
        let nullifiers_before = state.nullifier_count();
        let fees_before = state.epoch_fees();

        // Build a vertex containing this transaction
        let vertex = make_test_vertex(vec![genesis_id], 1, 0, &val_signing.public, vec![tx]);
        let vertex_id = vertex.id;

        let result = state.apply_vertex(&vertex);
        assert!(result.is_ok(), "apply_vertex failed: {:?}", result.err());

        // Verify outputs added to commitment tree (tx output + coinbase output)
        // The tx has 1 output. Coinbase adds another output.
        assert!(state.commitment_count() > commitments_before);
        assert!(state.find_commitment(&tx_output_commitment).is_some());

        // Verify nullifier recorded
        assert_eq!(state.nullifier_count(), nullifiers_before + 1);
        assert!(state.is_spent(&tx_nullifier));

        // Verify fees accumulated
        assert_eq!(state.epoch_fees(), fees_before + det_fee);

        // Verify last_finalized updated
        assert_eq!(state.last_finalized(), Some(&vertex_id));
    }

    #[test]
    fn apply_vertex_too_many_transactions() {
        let mut state = ChainState::new();

        let kp = SigningKeypair::generate();
        let genesis_id = VertexId(crate::hash_domain(b"umbra.genesis", b"umbra-mainnet"));

        // Create a vertex with MAX_TXS_PER_VERTEX + 1 dummy transactions
        let dummy_txs: Vec<Transaction> = (0..crate::constants::MAX_TXS_PER_VERTEX + 1)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
                let n = Nullifier::derive(&seed, &[0u8; 32]);
                make_dummy_tx_with_nullifier(n)
            })
            .collect();

        let vertex = make_test_vertex(vec![genesis_id], 1, 0, &kp.public, dummy_txs);

        let result = state.apply_vertex(&vertex);
        assert!(
            matches!(result, Err(StateError::TooManyTransactions)),
            "expected TooManyTransactions, got {:?}",
            result
        );
    }

    #[test]
    fn apply_vertex_intra_vertex_duplicate_nullifier() {
        let mut state = ChainState::new();

        let kp = SigningKeypair::generate();
        let genesis_id = VertexId(crate::hash_domain(b"umbra.genesis", b"umbra-mainnet"));

        // Create two dummy transactions sharing the same nullifier
        let shared_nullifier = Nullifier::derive(&[42u8; 32], &[43u8; 32]);
        let tx1 = make_dummy_tx_with_nullifier(shared_nullifier);
        let tx2 = make_dummy_tx_with_nullifier(shared_nullifier);

        let vertex = make_test_vertex(vec![genesis_id], 1, 0, &kp.public, vec![tx1, tx2]);

        let result = state.apply_vertex(&vertex);
        assert!(
            matches!(result, Err(StateError::DoubleSpend(_))),
            "expected DoubleSpend, got {:?}",
            result
        );
    }

    #[test]
    fn apply_vertex_epoch_fee_accumulation() {
        let mut state = ChainState::new();

        // Register a validator with KEM key for coinbase
        let val_signing = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let validator = Validator::with_kem(val_signing.public.clone(), val_kem.public.clone());
        state.register_genesis_validator(validator);

        let genesis_id = VertexId(crate::hash_domain(b"umbra.genesis", b"umbra-mainnet"));

        // Build and apply first vertex (deterministic fee for 1-in/1-out = 300)
        let det_fee = crate::constants::compute_weight_fee(1, 0);
        let tx1 = build_valid_tx_for_state(&mut state, 500, 10);
        let v1 = make_test_vertex(vec![genesis_id], 1, 0, &val_signing.public, vec![tx1]);
        state.apply_vertex(&v1).unwrap();
        let fees_after_v1 = state.epoch_fees();
        assert_eq!(fees_after_v1, det_fee);

        // Build and apply second vertex in the same epoch (same deterministic fee)
        let tx2 = build_valid_tx_for_state(&mut state, 2000, 20);
        let v2 = make_test_vertex(vec![genesis_id], 2, 0, &val_signing.public, vec![tx2]);
        state.apply_vertex(&v2).unwrap();
        let fees_after_v2 = state.epoch_fees();

        // Regression: fees must accumulate, not reset per vertex
        assert_eq!(
            fees_after_v2,
            det_fee * 2,
            "epoch_fees should accumulate across vertices: expected {}, got {}",
            det_fee * 2,
            fees_after_v2
        );
    }

    #[test]
    fn validate_transaction_wrong_chain_id() {
        let state = ChainState::new();

        // Build a valid transaction but with a wrong chain_id
        // Deterministic fee for 1 input, 1 output = 300
        let det_fee = crate::constants::compute_weight_fee(1, 0);
        let recipient = FullKeypair::generate();
        let wrong_chain_id = crate::hash_domain(b"wrong.chain", b"not-umbra");
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: det_fee + 100,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 100)
            .set_chain_id(wrong_chain_id)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        let result = state.validate_transaction(&tx);
        assert!(
            matches!(result, Err(StateError::WrongChainId)),
            "expected WrongChainId, got {:?}",
            result
        );
    }

    #[test]
    fn validate_transaction_double_spend() {
        let mut state = ChainState::new();

        // Build a valid transaction against the state
        let tx = build_valid_tx_for_state(&mut state, 400, 50);
        let nullifier = tx.inputs[0].nullifier;

        // First validation + application should succeed
        state.apply_transaction(&tx).unwrap();
        assert!(state.is_spent(&nullifier));

        // Second validation of the same transaction should fail with DoubleSpend
        let result = state.validate_transaction(&tx);
        assert!(
            matches!(result, Err(StateError::DoubleSpend(_))),
            "expected DoubleSpend, got {:?}",
            result
        );
    }

    #[test]
    fn validate_transaction_register_already_registered() {
        let mut state = ChainState::new();

        // Register a validator via genesis (bypasses transaction validation)
        let val_kp = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let validator = Validator::with_kem(val_kp.public.clone(), val_kem.public.clone());
        let vid = validator.id;
        state.register_genesis_validator(validator);
        assert!(state.is_active_validator(&vid));

        // Build a ValidatorRegister transaction with the same signing key.
        // The validate_transaction chain_id check passes, then validate_structure
        // runs, then the ValidatorAlreadyRegistered check happens.
        // We need a transaction that passes validate_structure first.
        let bond = crate::constants::VALIDATOR_BASE_BOND;
        let min_fee = bond + crate::constants::MIN_TX_FEE;
        let total_input = min_fee + 100; // enough for output + fee

        // Add a commitment to the state so merkle root matches
        let blinding = BlindingFactor::from_bytes([77u8; 32]);
        let spend_auth = crate::hash_domain(b"test.spend_auth", &[77u8]);
        let commitment = Commitment::commit(total_input, &blinding);
        state.add_commitment(commitment).unwrap();
        let index = state.find_commitment(&commitment).unwrap();
        let merkle_path = state.commitment_path(index).unwrap();

        let recipient = FullKeypair::generate();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: total_input,
                blinding,
                spend_auth,
                merkle_path,
            })
            .add_output(recipient.kem.public.clone(), 100)
            .set_fee(min_fee)
            .set_tx_type(crate::transaction::TxType::ValidatorRegister {
                signing_key: val_kp.public.clone(),
                kem_public_key: val_kem.public.clone(),
            })
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        let result = state.validate_transaction(&tx);
        assert!(
            matches!(result, Err(StateError::ValidatorAlreadyRegistered)),
            "expected ValidatorAlreadyRegistered, got {:?}",
            result
        );
    }

    #[test]
    fn record_nullifier_returns_result() {
        let mut state = ChainState::new();
        let n = Nullifier::derive(&[99u8; 32], &[100u8; 32]);

        // Basic regression test: record_nullifier returns Ok(())
        let result = state.record_nullifier(n);
        assert!(result.is_ok());

        // Recording the same nullifier again is also Ok (insert returns false, no error)
        let result2 = state.record_nullifier(n);
        assert!(result2.is_ok());
    }

    #[test]
    fn create_coinbase_no_kem_key() {
        let mut state = ChainState::new();

        // Register a validator WITHOUT a KEM key
        let val_kp = SigningKeypair::generate();
        let validator = Validator::new(val_kp.public.clone()); // no KEM key
        state.register_genesis_validator(validator);

        let vertex_id = VertexId([1u8; 32]);
        let amount = 50_000u64;

        // create_coinbase_output should return None because there's no KEM key
        let result = state.create_coinbase_output(&vertex_id, &val_kp.public, amount);
        assert!(
            result.is_none(),
            "expected None when validator has no KEM key"
        );

        // Now register a validator WITH a KEM key
        let val_kp2 = SigningKeypair::generate();
        let val_kem2 = KemKeypair::generate();
        let validator2 = Validator::with_kem(val_kp2.public.clone(), val_kem2.public.clone());
        state.register_genesis_validator(validator2);

        let commitments_before = state.commitment_count();
        let minted_before = state.total_minted();

        let result2 = state.create_coinbase_output(&vertex_id, &val_kp2.public, amount);
        assert!(
            result2.is_some(),
            "expected Some(TxOutput) when validator has KEM key"
        );

        // Verify commitment was added and total_minted updated
        assert_eq!(state.commitment_count(), commitments_before + 1);
        assert_eq!(state.total_minted(), minted_before + amount);
    }

    #[test]
    fn eligible_validators_respects_activation_epoch() {
        let mut state = ChainState::new();

        // Register a validator at epoch 0 with activation_epoch = 1
        // (simulating what apply_transaction_unchecked does: activation_epoch = self.epoch + 1)
        let val_kp = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let mut validator = Validator::with_kem(val_kp.public.clone(), val_kem.public.clone());
        validator.activation_epoch = 1; // eligible starting epoch 1
        let vid = validator.id;
        state.register_genesis_validator(validator);

        // At epoch 0, this validator should NOT be eligible
        let eligible_0 = state.eligible_validators(0);
        assert!(
            !eligible_0.iter().any(|v| v.id == vid),
            "validator with activation_epoch=1 should NOT be eligible at epoch 0"
        );

        // At epoch 1, this validator SHOULD be eligible
        let eligible_1 = state.eligible_validators(1);
        assert!(
            eligible_1.iter().any(|v| v.id == vid),
            "validator with activation_epoch=1 SHOULD be eligible at epoch 1"
        );

        // At epoch 5, still eligible
        let eligible_5 = state.eligible_validators(5);
        assert!(
            eligible_5.iter().any(|v| v.id == vid),
            "validator with activation_epoch=1 SHOULD be eligible at epoch 5"
        );
    }

    #[test]
    fn apply_vertex_epoch_mismatch_rejected() {
        let mut state = ChainState::new();

        // Register a validator with KEM key
        let val_signing = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let validator = Validator::with_kem(val_signing.public.clone(), val_kem.public.clone());
        state.register_genesis_validator(validator);

        let genesis_id = VertexId(crate::hash_domain(b"umbra.genesis", b"umbra-mainnet"));

        // Create a vertex with epoch=5 while state is at epoch=0 (mismatch)
        let vertex = make_test_vertex(vec![genesis_id], 1, 5, &val_signing.public, vec![]);
        let result = state.apply_vertex(&vertex);
        assert!(
            matches!(
                result,
                Err(StateError::EpochMismatch {
                    expected: 0,
                    got: 5
                })
            ),
            "expected EpochMismatch, got {:?}",
            result
        );
    }

    #[test]
    fn block_reward_uses_chain_epoch() {
        let mut state = ChainState::new();

        // Register a validator with KEM key
        let val_signing = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let validator = Validator::with_kem(val_signing.public.clone(), val_kem.public.clone());
        state.register_genesis_validator(validator);

        let genesis_id = VertexId(crate::hash_domain(b"umbra.genesis", b"umbra-mainnet"));

        // Apply a vertex at epoch=0, round=1 (matching chain epoch)
        let vertex = make_test_vertex(vec![genesis_id], 1, 0, &val_signing.public, vec![]);

        let minted_before = state.total_minted();
        let result = state.apply_vertex(&vertex);
        assert!(result.is_ok());

        // The block reward should use self.epoch (0), not a fake epoch
        let expected_reward = crate::constants::block_reward_for_epoch(0);
        assert_eq!(
            state.total_minted(),
            minted_before + expected_reward,
            "block reward should be based on chain epoch 0"
        );
    }

    #[test]
    fn finalize_vertex_requires_valid_certificate() {
        let mut ledger = Ledger::new();

        // Register a validator
        let val_signing = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let validator = Validator::with_kem(val_signing.public.clone(), val_kem.public.clone());
        let vid = validator.id;
        ledger.state.register_genesis_validator(validator.clone());

        let genesis_id = VertexId(crate::hash_domain(b"umbra.genesis", b"umbra-mainnet"));

        // Insert a vertex into the DAG
        let vertex = make_test_vertex(vec![genesis_id], 1, 0, &val_signing.public, vec![]);
        let vertex_id = vertex.id;
        ledger.dag.insert_unchecked(vertex).unwrap();

        let chain_id = *ledger.state.chain_id();

        // Try to finalize with an empty (invalid) certificate
        let fake_cert = crate::consensus::bft::Certificate {
            vertex_id,
            round: 0,
            epoch: 0,
            signatures: vec![],
        };
        let result = ledger.finalize_vertex(
            &vertex_id,
            &fake_cert,
            std::slice::from_ref(&validator),
            &chain_id,
        );
        assert!(
            matches!(result, Err(StateError::InvalidCertificate)),
            "expected InvalidCertificate, got {:?}",
            result
        );

        // Certificate for wrong vertex should also fail
        let wrong_cert = crate::consensus::bft::Certificate {
            vertex_id: VertexId([0xFF; 32]),
            round: 0,
            epoch: 0,
            signatures: vec![(vid, val_signing.sign(&[0u8; 32]))],
        };
        let result = ledger.finalize_vertex(&vertex_id, &wrong_cert, &[validator], &chain_id);
        assert!(
            matches!(result, Err(StateError::InvalidCertificate)),
            "expected InvalidCertificate for mismatched vertex, got {:?}",
            result
        );
    }

    #[test]
    fn state_root_deterministic_validator_hash() {
        // Two states with different validator sets but same count/total bonds
        // must produce different state roots.
        let mut state1 = ChainState::new();
        let mut state2 = ChainState::new();

        let kp_a = SigningKeypair::generate();
        let kp_b = SigningKeypair::generate();

        let v_a = Validator::new(kp_a.public.clone());
        let v_b = Validator::new(kp_b.public.clone());

        // Both states have 1 validator with the same bond amount
        state1.register_genesis_validator(v_a);
        state2.register_genesis_validator(v_b);

        assert_eq!(state1.total_validators(), 1);
        assert_eq!(state2.total_validators(), 1);
        assert_eq!(
            state1.validator_bonds.values().sum::<u64>(),
            state2.validator_bonds.values().sum::<u64>()
        );

        // State roots must differ because the validators have different IDs
        assert_ne!(
            state1.state_root(),
            state2.state_root(),
            "different validator sets should produce different state roots"
        );
    }

    #[test]
    fn state_root_includes_slashed_status() {
        let mut state1 = ChainState::new();
        let mut state2 = ChainState::new();

        let kp = SigningKeypair::generate();
        let v = Validator::new(kp.public.clone());
        let vid = v.id;

        state1.register_genesis_validator(v.clone());
        state2.register_genesis_validator(v);

        // Same validator in both states — roots should match
        assert_eq!(state1.state_root(), state2.state_root());

        // Slash in state1 only
        state1.slash_validator(&vid).unwrap();

        // Roots must now differ due to slashed status
        assert_ne!(
            state1.state_root(),
            state2.state_root(),
            "slashing a validator should change the state root"
        );
    }

    #[test]
    fn validator_reregistration_allowed_after_deregistration() {
        let mut state = ChainState::new();

        // Register a validator
        let val_kp = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let validator = Validator::with_kem(val_kp.public.clone(), val_kem.public.clone());
        let vid = validator.id;
        state.register_genesis_validator(validator);

        // Deregister: mark inactive and remove bond
        if let Some(v) = state.validators.get_mut(&vid) {
            v.active = false;
        }
        state.validator_bonds.remove(&vid);

        assert!(!state.is_active_validator(&vid));

        // Build a ValidatorRegister transaction for the same key
        let bond = crate::constants::VALIDATOR_BASE_BOND;
        let min_fee = bond + crate::constants::MIN_TX_FEE;
        let total_input = min_fee + 100;

        let blinding = BlindingFactor::from_bytes([88u8; 32]);
        let spend_auth = crate::hash_domain(b"test.spend_auth", &[88u8]);
        let commitment = Commitment::commit(total_input, &blinding);
        state.add_commitment(commitment).unwrap();
        let index = state.find_commitment(&commitment).unwrap();
        let merkle_path = state.commitment_path(index).unwrap();

        let recipient = FullKeypair::generate();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: total_input,
                blinding,
                spend_auth,
                merkle_path,
            })
            .add_output(recipient.kem.public.clone(), 100)
            .set_fee(min_fee)
            .set_tx_type(crate::transaction::TxType::ValidatorRegister {
                signing_key: val_kp.public.clone(),
                kem_public_key: val_kem.public.clone(),
            })
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        // Should succeed — re-registration of inactive (non-slashed) validator
        let result = state.validate_transaction(&tx);
        assert!(
            result.is_ok(),
            "re-registration should be allowed, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn validator_reregistration_blocked_when_active() {
        let mut state = ChainState::new();

        let val_kp = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let validator = Validator::with_kem(val_kp.public.clone(), val_kem.public.clone());
        state.register_genesis_validator(validator);

        // Validator is still active — re-registration should be rejected
        assert!(state.is_active_validator(&val_kp.public.fingerprint()));

        let bond = crate::constants::VALIDATOR_BASE_BOND;
        let min_fee = bond + crate::constants::MIN_TX_FEE;
        let total_input = min_fee + 100;

        let blinding = BlindingFactor::from_bytes([99u8; 32]);
        let spend_auth = crate::hash_domain(b"test.spend_auth", &[99u8]);
        let commitment = Commitment::commit(total_input, &blinding);
        state.add_commitment(commitment).unwrap();
        let index = state.find_commitment(&commitment).unwrap();
        let merkle_path = state.commitment_path(index).unwrap();

        let recipient = FullKeypair::generate();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: total_input,
                blinding,
                spend_auth,
                merkle_path,
            })
            .add_output(recipient.kem.public.clone(), 100)
            .set_fee(min_fee)
            .set_tx_type(crate::transaction::TxType::ValidatorRegister {
                signing_key: val_kp.public.clone(),
                kem_public_key: val_kem.public.clone(),
            })
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        let result = state.validate_transaction(&tx);
        assert!(
            matches!(result, Err(StateError::ValidatorAlreadyRegistered)),
            "active validator re-registration should fail, got: {:?}",
            result
        );
    }

    #[test]
    fn validator_reregistration_blocked_when_slashed() {
        let mut state = ChainState::new();

        let val_kp = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let validator = Validator::with_kem(val_kp.public.clone(), val_kem.public.clone());
        let vid = validator.id;
        state.register_genesis_validator(validator);

        // Slash the validator
        state.slash_validator(&vid).unwrap();
        assert!(state.is_slashed(&vid));

        let bond = crate::constants::VALIDATOR_BASE_BOND;
        let min_fee = bond + crate::constants::MIN_TX_FEE;
        let total_input = min_fee + 100;

        let blinding = BlindingFactor::from_bytes([77u8; 32]);
        let spend_auth = crate::hash_domain(b"test.spend_auth", &[77u8]);
        let commitment = Commitment::commit(total_input, &blinding);
        state.add_commitment(commitment).unwrap();
        let index = state.find_commitment(&commitment).unwrap();
        let merkle_path = state.commitment_path(index).unwrap();

        let recipient = FullKeypair::generate();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: total_input,
                blinding,
                spend_auth,
                merkle_path,
            })
            .add_output(recipient.kem.public.clone(), 100)
            .set_fee(min_fee)
            .set_tx_type(crate::transaction::TxType::ValidatorRegister {
                signing_key: val_kp.public.clone(),
                kem_public_key: val_kem.public.clone(),
            })
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        let result = state.validate_transaction(&tx);
        assert!(
            matches!(result, Err(StateError::ValidatorSlashed)),
            "slashed validator re-registration should fail, got: {:?}",
            result
        );
    }

    #[test]
    fn create_genesis_coinbase() {
        let mut state = ChainState::new();
        let kem_kp = KemKeypair::generate();

        let minted_before = state.total_minted();
        let commitments_before = state.commitment_count();

        let result = state.create_genesis_coinbase(&kem_kp.public);
        assert!(result.is_some());

        let output = result.unwrap();
        assert_eq!(
            state.total_minted(),
            minted_before + crate::constants::GENESIS_MINT
        );
        assert_eq!(state.commitment_count(), commitments_before + 1);

        // The commitment should be findable in the tree
        assert!(state.find_commitment(&output.commitment).is_some());
    }

    #[test]
    fn create_genesis_coinbase_deterministic_blinding() {
        let mut state1 = ChainState::new();
        let mut state2 = ChainState::new();
        let kem_kp = KemKeypair::generate();

        let out1 = state1.create_genesis_coinbase(&kem_kp.public).unwrap();
        let out2 = state2.create_genesis_coinbase(&kem_kp.public).unwrap();

        // Same KEM key should produce the same commitment (deterministic blinding)
        assert_eq!(out1.commitment, out2.commitment);
    }

    #[test]
    fn snapshot_data_export_import_roundtrip() {
        use crate::node::storage::SledStorage;

        // Build state with some data
        let storage1 = SledStorage::open_temporary().unwrap();
        let mut state = ChainState::new();

        // Add commitments
        for i in 0..5u64 {
            let blind = BlindingFactor::from_bytes([i as u8 + 1; 32]);
            state
                .add_commitment(Commitment::commit(i * 100 + 1, &blind))
                .unwrap();
        }

        // Add nullifiers
        let n1 = Nullifier::derive(&[10u8; 32], &[20u8; 32]);
        let n2 = Nullifier::derive(&[30u8; 32], &[40u8; 32]);
        state.mark_nullifier(n1).unwrap();
        state.mark_nullifier(n2).unwrap();

        // Add a validator
        let kp = SigningKeypair::generate();
        let validator = Validator::new(kp.public.clone());
        state.register_genesis_validator(validator.clone());

        // Persist to source storage
        let depth = crate::crypto::stark::spend_air::MERKLE_DEPTH;
        for level in 0..=depth {
            for idx in 0..state.commitment_tree_level_len(level) {
                let hash = state.commitment_tree_node(level, idx);
                storage1.put_commitment_level(level, idx, &hash).unwrap();
            }
        }
        storage1.put_nullifier(&n1).unwrap();
        storage1.put_nullifier(&n2).unwrap();
        let bond = state
            .validator_bonds
            .get(&validator.id)
            .copied()
            .unwrap_or(0);
        storage1.put_validator(&validator, bond, false).unwrap();

        let original_root = state.state_root();
        let original_commitment_root = state.commitment_root();

        // Export snapshot
        let snapshot = state.to_snapshot_data(&storage1, 42).unwrap();
        assert_eq!(snapshot.meta.commitment_count, 5);
        assert_eq!(snapshot.meta.nullifier_count, 2);
        assert_eq!(snapshot.meta.finalized_count, 42);

        // Simulate network transfer: serialize + deserialize
        let bytes = crate::serialize(&snapshot).unwrap();
        let received: SnapshotData = crate::deserialize_snapshot(&bytes).unwrap();

        // Import into fresh storage
        let storage2 = SledStorage::open_temporary().unwrap();
        let meta = import_snapshot_to_storage(&storage2, &received).unwrap();

        assert_eq!(meta.epoch, 0);
        assert_eq!(meta.commitment_count, 5);
        assert_eq!(meta.nullifier_count, 2);
        assert_eq!(meta.state_root, original_root);
        assert_eq!(meta.commitment_root, original_commitment_root);

        // Restore from imported storage and verify
        let restored = ChainState::restore_from_storage(&storage2, &meta).unwrap();
        assert_eq!(restored.commitment_root(), original_commitment_root);
        assert_eq!(restored.state_root(), original_root);
        assert_eq!(restored.nullifier_count(), 2);
        assert!(restored.is_spent(&n1));
        assert!(restored.is_spent(&n2));
        assert!(restored.is_active_validator(&validator.id));
    }

    #[test]
    fn dynamic_bond_rejects_insufficient_fee() {
        // Register 10 genesis validators so the required bond increases.
        let mut state = ChainState::new();
        for _ in 0..10 {
            let kp = SigningKeypair::generate();
            let kem = KemKeypair::generate();
            let v = Validator::with_kem(kp.public.clone(), kem.public.clone());
            state.register_genesis_validator(v);
        }
        assert_eq!(state.total_validators(), 10);

        // At 10 active validators: required_bond = 1M + 1M * 10/100 = 1.1M
        let required = crate::constants::required_validator_bond(10);
        assert_eq!(required, 1_100_000);

        // Build a tx with only the base bond (1M + 1), which passes structural
        // validation but should fail the state-level dynamic bond check.
        let base_fee = crate::constants::VALIDATOR_BASE_BOND + crate::constants::MIN_TX_FEE;
        let total_input = base_fee + 100;

        let blinding = BlindingFactor::from_bytes([77u8; 32]);
        let spend_auth = crate::hash_domain(b"test.spend_auth", &[77u8]);
        let commitment = Commitment::commit(total_input, &blinding);
        state.add_commitment(commitment).unwrap();
        let index = state.find_commitment(&commitment).unwrap();
        let merkle_path = state.commitment_path(index).unwrap();

        let new_kp = SigningKeypair::generate();
        let new_kem = KemKeypair::generate();
        let recipient = FullKeypair::generate();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: total_input,
                blinding,
                spend_auth,
                merkle_path,
            })
            .add_output(recipient.kem.public.clone(), 100)
            .set_fee(base_fee)
            .set_tx_type(crate::transaction::TxType::ValidatorRegister {
                signing_key: new_kp.public.clone(),
                kem_public_key: new_kem.public.clone(),
            })
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        let result = state.validate_transaction(&tx);
        assert!(
            matches!(result, Err(StateError::InsufficientBond)),
            "expected InsufficientBond, got {:?}",
            result
        );
    }

    #[test]
    fn dynamic_bond_stored_per_validator() {
        // Genesis validators get base bond
        let mut state = ChainState::new();
        let kp = SigningKeypair::generate();
        let v = Validator::new(kp.public.clone());
        let vid = v.id;
        state.register_genesis_validator(v);

        assert_eq!(
            state.validator_bond(&vid),
            Some(crate::constants::VALIDATOR_BASE_BOND)
        );

        // Verify the bond formula gives higher amounts with more validators
        let bond_at_0 = crate::constants::required_validator_bond(0);
        let bond_at_1 = crate::constants::required_validator_bond(1);
        let bond_at_100 = crate::constants::required_validator_bond(100);

        assert_eq!(bond_at_0, crate::constants::VALIDATOR_BASE_BOND);
        assert!(bond_at_1 > bond_at_0);
        assert!(bond_at_100 > bond_at_1);
        assert_eq!(bond_at_100, 2_000_000);
    }

    #[test]
    fn eligible_validators_empty_set() {
        let state = ChainState::new();
        let eligible = state.eligible_validators(0);
        assert!(eligible.is_empty());
    }

    #[test]
    fn eligible_validators_mixed_activation_epochs() {
        let mut state = ChainState::new();

        // Register 3 validators with different activation epochs
        let kp0 = SigningKeypair::generate();
        let kem0 = KemKeypair::generate();
        let v0 = Validator::with_activation(kp0.public.clone(), kem0.public.clone(), 0);
        let vid0 = v0.id;
        state.register_genesis_validator(v0);

        let kp1 = SigningKeypair::generate();
        let kem1 = KemKeypair::generate();
        let mut v1 = Validator::with_kem(kp1.public.clone(), kem1.public.clone());
        v1.activation_epoch = 1;
        let vid1 = v1.id;
        state.register_genesis_validator(v1);

        let kp5 = SigningKeypair::generate();
        let kem5 = KemKeypair::generate();
        let mut v5 = Validator::with_kem(kp5.public.clone(), kem5.public.clone());
        v5.activation_epoch = 5;
        let vid5 = v5.id;
        state.register_genesis_validator(v5);

        // Epoch 0: only v0 is eligible
        let eligible_0 = state.eligible_validators(0);
        assert_eq!(eligible_0.len(), 1);
        assert!(eligible_0.iter().any(|v| v.id == vid0));

        // Epoch 1: v0 and v1 are eligible
        let eligible_1 = state.eligible_validators(1);
        assert_eq!(eligible_1.len(), 2);
        assert!(eligible_1.iter().any(|v| v.id == vid0));
        assert!(eligible_1.iter().any(|v| v.id == vid1));

        // Epoch 5: all three are eligible
        let eligible_5 = state.eligible_validators(5);
        assert_eq!(eligible_5.len(), 3);
        assert!(eligible_5.iter().any(|v| v.id == vid0));
        assert!(eligible_5.iter().any(|v| v.id == vid1));
        assert!(eligible_5.iter().any(|v| v.id == vid5));

        // Epoch 6: all three still eligible
        let eligible_6 = state.eligible_validators(6);
        assert_eq!(eligible_6.len(), 3);
    }

    #[test]
    fn active_validators_empty() {
        let state = ChainState::new();
        let active = state.active_validators();
        assert!(active.is_empty());
    }

    #[test]
    fn validator_set_hash_deterministic() {
        let mut state1 = ChainState::new();
        let mut state2 = ChainState::new();

        let kp_a = SigningKeypair::generate();
        let kp_b = SigningKeypair::generate();

        let v_a = Validator::new(kp_a.public.clone());
        let v_b = Validator::new(kp_b.public.clone());

        // Register in different order
        state1.register_genesis_validator(v_a.clone());
        state1.register_genesis_validator(v_b.clone());

        state2.register_genesis_validator(v_b);
        state2.register_genesis_validator(v_a);

        // validator_set_hash sorts by ID, so order of registration should not matter
        assert_eq!(
            state1.state_root(),
            state2.state_root(),
            "same validators registered in different order should produce the same state root"
        );
    }

    #[test]
    fn slash_validator_already_inactive() {
        let mut state = ChainState::new();
        let kp = SigningKeypair::generate();
        let v = Validator::new(kp.public.clone());
        let vid = v.id;

        state.register_genesis_validator(v);

        // Manually deactivate the validator
        state.validators.get_mut(&vid).unwrap().active = false;
        assert!(!state.is_active_validator(&vid));

        // Slashing an already-inactive validator should still work
        let result = state.slash_validator(&vid);
        assert!(result.is_ok(), "slashing inactive validator should succeed");
        assert!(state.is_slashed(&vid));
        assert!(!state.is_active_validator(&vid));
    }

    #[test]
    fn multi_epoch_progression() {
        let mut state = ChainState::new();

        // Register a validator and slash it so we have some fees
        let kp = SigningKeypair::generate();
        let v = Validator::new(kp.public.clone());
        let _vid = v.id;
        state.register_genesis_validator(v);

        assert_eq!(state.epoch(), 0);

        let mut prev_seed = state.epoch_seed().seed;

        // Advance epoch 5 times
        for expected_epoch in 1..=5u64 {
            // Accumulate some fees (slash a new validator each round)
            let kp_new = SigningKeypair::generate();
            let v_new = Validator::new(kp_new.public.clone());
            let vid_new = v_new.id;
            state.register_genesis_validator(v_new);
            state.slash_validator(&vid_new).unwrap();
            assert!(state.epoch_fees() > 0);

            let (fees, new_seed) = state.advance_epoch();

            // Verify epoch counter incremented
            assert_eq!(state.epoch(), expected_epoch);

            // Verify fees were returned and reset
            assert!(fees > 0);
            assert_eq!(state.epoch_fees(), 0);

            // Verify seed changed
            assert_ne!(
                new_seed.seed, prev_seed,
                "epoch seed should change each epoch"
            );
            prev_seed = new_seed.seed;
        }

        assert_eq!(state.epoch(), 5);
    }

    #[test]
    fn apply_vertex_state_only_updates_state_not_dag() {
        let mut ledger = Ledger::new();

        // Register a validator with KEM key for coinbase
        let val_signing = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let validator = Validator::with_kem(val_signing.public.clone(), val_kem.public.clone());
        ledger.state.register_genesis_validator(validator);

        let genesis_id = VertexId(crate::hash_domain(b"umbra.genesis", b"umbra-mainnet"));

        // Build a vertex with a transaction
        let tx = build_valid_tx_for_state(&mut ledger.state, 500, 42);
        let tx_nullifier = tx.inputs[0].nullifier;
        let vertex = make_test_vertex(vec![genesis_id], 1, 0, &val_signing.public, vec![tx]);

        let dag_len_before = ledger.dag.len();
        let nullifiers_before = ledger.state.nullifier_count();

        // apply_vertex_state_only should NOT insert into DAG
        let result = ledger.apply_vertex_state_only(&vertex);
        assert!(
            result.is_ok(),
            "apply_vertex_state_only failed: {:?}",
            result.err()
        );

        // DAG length should NOT change
        assert_eq!(ledger.dag.len(), dag_len_before, "DAG should not grow");

        // But nullifier should be recorded in state
        assert_eq!(ledger.state.nullifier_count(), nullifiers_before + 1);
        assert!(ledger.state.is_spent(&tx_nullifier));
    }

    #[test]
    fn commitment_count_tracks_additions() {
        let mut state = ChainState::new();
        assert_eq!(state.commitment_count(), 0);

        for i in 0..3u64 {
            let blind = BlindingFactor::from_bytes([i as u8 + 1; 32]);
            state
                .add_commitment(Commitment::commit(i * 100 + 1, &blind))
                .unwrap();
        }

        assert_eq!(state.commitment_count(), 3);
    }

    #[test]
    fn nullifier_count_tracks_marking() {
        let mut state = ChainState::new();
        assert_eq!(state.nullifier_count(), 0);

        let n1 = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        let n2 = Nullifier::derive(&[3u8; 32], &[4u8; 32]);
        state.mark_nullifier(n1).unwrap();
        state.mark_nullifier(n2).unwrap();

        assert_eq!(state.nullifier_count(), 2);
    }

    #[test]
    fn get_validator_returns_none_for_missing() {
        let state = ChainState::new();
        let missing_id = [99u8; 32];
        assert!(state.get_validator(&missing_id).is_none());
    }

    #[test]
    fn is_active_validator_false_for_missing() {
        let state = ChainState::new();
        let missing_id = [99u8; 32];
        assert!(!state.is_active_validator(&missing_id));
    }

    #[test]
    fn total_minted_tracks_coinbase() {
        let mut state = ChainState::new();
        assert_eq!(state.total_minted(), 0);

        // Register a validator with KEM key so coinbase can be created
        let val_signing = SigningKeypair::generate();
        let val_kem = KemKeypair::generate();
        let validator = Validator::with_kem(val_signing.public.clone(), val_kem.public.clone());
        state.register_genesis_validator(validator);

        // Create a coinbase output
        let vertex_id = VertexId([1u8; 32]);
        let amount = 50_000u64;
        let result = state.create_coinbase_output(&vertex_id, &val_signing.public, amount);
        assert!(result.is_some());
        assert_eq!(state.total_minted(), amount);

        // Create another coinbase output
        let vertex_id2 = VertexId([2u8; 32]);
        let amount2 = 30_000u64;
        let result2 = state.create_coinbase_output(&vertex_id2, &val_signing.public, amount2);
        assert!(result2.is_some());
        assert_eq!(state.total_minted(), amount + amount2);
    }

    #[test]
    fn ledger_new_has_genesis() {
        let ledger = Ledger::new();
        assert_eq!(ledger.dag.len(), 1);
        assert_eq!(ledger.state.commitment_count(), 0);
        assert_eq!(ledger.state.nullifier_count(), 0);
    }

    #[test]
    fn ledger_finalize_vertex_unchecked_double_finalize_is_noop() {
        use crate::consensus::dag::Dag;
        let mut ledger = Ledger::new();
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;

        // Insert a vertex
        let kp = SigningKeypair::generate();
        let vertex = Vertex {
            id: VertexId(crate::hash_domain(b"test", b"v1")),
            parents: vec![gid],
            epoch: 0,
            round: 1,
            proposer: kp.public.clone(),
            transactions: vec![],
            timestamp: 1000,
            state_root: [0u8; 32],
            signature: Signature::empty(),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        };
        let vid = vertex.id;
        ledger.dag.insert_unchecked(vertex).unwrap();

        // First finalize
        let result1 = ledger.finalize_vertex_unchecked(&vid);
        assert!(result1.is_ok());

        // Second finalize should return Ok(None) (already finalized)
        let result2 = ledger.finalize_vertex_unchecked(&vid);
        assert!(result2.is_ok());
        assert!(result2.unwrap().is_none());
    }

    #[test]
    fn chain_state_double_nullifier_idempotent() {
        let mut state = ChainState::new();
        let n = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        assert!(state.mark_nullifier(n).is_ok());
        // Duplicate nullifier is idempotent (returns Ok, not error)
        assert!(state.mark_nullifier(n).is_ok());
        assert_eq!(state.nullifier_count(), 1);
    }

    #[test]
    fn chain_state_is_spent() {
        let mut state = ChainState::new();
        let n = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        assert!(!state.is_spent(&n));
        state.mark_nullifier(n).unwrap();
        assert!(state.is_spent(&n));
    }

    #[test]
    fn chain_state_epoch_starts_at_zero() {
        let state = ChainState::new();
        assert_eq!(state.epoch(), 0);
    }

    #[test]
    fn chain_state_advance_epoch() {
        let mut state = ChainState::new();
        assert_eq!(state.epoch(), 0);
        state.advance_epoch();
        assert_eq!(state.epoch(), 1);
        state.advance_epoch();
        assert_eq!(state.epoch(), 2);
    }

    #[test]
    fn chain_state_state_root_deterministic() {
        let state = ChainState::new();
        let r1 = state.state_root();
        let r2 = state.state_root();
        assert_eq!(r1, r2);
    }

    #[test]
    fn chain_state_state_root_changes_with_commits() {
        let mut state = ChainState::new();
        let root_before = state.state_root();
        let c = Commitment::commit(100, &BlindingFactor::random());
        state.add_commitment(c).unwrap();
        let root_after = state.state_root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn chain_state_eligible_validators_empty() {
        let state = ChainState::new();
        assert!(state.eligible_validators(0).is_empty());
    }

    #[test]
    fn chain_state_total_validators_empty() {
        let state = ChainState::new();
        assert_eq!(state.total_validators(), 0);
    }

    #[test]
    fn chain_state_active_validators_empty() {
        let state = ChainState::new();
        assert!(state.active_validators().is_empty());
    }

    #[test]
    fn chain_state_all_validators_empty() {
        let state = ChainState::new();
        assert!(state.all_validators().is_empty());
    }

    #[test]
    fn chain_state_find_commitment_returns_correct_index() {
        let mut state = ChainState::new();
        let c0 = Commitment::commit(100, &BlindingFactor::random());
        let c1 = Commitment::commit(200, &BlindingFactor::random());
        state.add_commitment(c0).unwrap();
        state.add_commitment(c1).unwrap();
        assert_eq!(state.find_commitment(&c0), Some(0));
        assert_eq!(state.find_commitment(&c1), Some(1));
        let c_missing = Commitment::commit(999, &BlindingFactor::random());
        assert_eq!(state.find_commitment(&c_missing), None);
    }

    #[test]
    fn chain_state_commitment_path() {
        let mut state = ChainState::new();
        let c = Commitment::commit(100, &BlindingFactor::random());
        state.add_commitment(c).unwrap();
        let path = state.commitment_path(0);
        assert!(path.is_some());
        assert!(state.commitment_path(1).is_none());
    }
}
