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
use crate::storage::{ChainStateMeta, Storage};
use crate::transaction::{deregister_sign_data, Transaction, TxOutput, TxType};
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
    /// Total coins ever minted via coinbase rewards
    total_minted: u64,
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
            total_minted: 0,
        }
    }

    /// Apply a finalized vertex to the state.
    ///
    /// Uses two-pass validation: first validates all transactions without
    /// mutating state, then applies them. Creates a coinbase output for the
    /// vertex proposer containing the block reward plus transaction fees.
    ///
    /// Returns the coinbase `TxOutput` if one was created (requires the
    /// proposer to be a registered validator with a KEM public key).
    pub fn apply_vertex(&mut self, vertex: &Vertex) -> Result<Option<TxOutput>, StateError> {
        // H9: Pass 1 — validate all transactions without applying
        for tx in &vertex.transactions {
            self.validate_transaction(tx)?;
        }

        // Record fees before applying transactions
        let fees_before = self.epoch_fees;

        // Pass 2 — apply all transactions (cannot fail after validation)
        for tx in &vertex.transactions {
            self.apply_transaction_unchecked(tx);
        }

        // Compute vertex fees and redirect to proposer (not pooled per-epoch)
        let vertex_fees = self.epoch_fees.saturating_sub(fees_before);
        self.epoch_fees = fees_before;

        // Compute total coinbase amount
        let block_reward = crate::constants::block_reward_for_epoch(vertex.epoch);
        let total_coinbase = block_reward.saturating_add(vertex_fees);

        // Create coinbase output for the proposer
        let coinbase = if total_coinbase > 0 {
            self.create_coinbase_output(&vertex.id, &vertex.proposer, total_coinbase)
        } else {
            None
        };

        // If coinbase creation failed (no KEM key), return fees to epoch pool
        if coinbase.is_none() && vertex_fees > 0 {
            self.epoch_fees = self.epoch_fees.saturating_add(vertex_fees);
        }

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
            TxType::ValidatorRegister { signing_key, .. } => {
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
            TxType::ValidatorRegister {
                signing_key,
                kem_public_key,
            } => {
                let mut validator =
                    Validator::with_kem(signing_key.clone(), kem_public_key.clone());
                validator.activation_epoch = self.epoch + 1; // eligible next epoch
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
            &self.total_minted.to_le_bytes(),
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

    // ── Persistence / Restoration ──────────────────────────────────────

    /// Create a `ChainStateMeta` snapshot for storage persistence.
    pub fn to_chain_state_meta(&self, finalized_count: u64) -> ChainStateMeta {
        ChainStateMeta {
            epoch: self.epoch,
            last_finalized: self.last_finalized,
            state_root: self.state_root(),
            commitment_root: self.commitment_root(),
            commitment_count: self.commitments.len() as u64,
            nullifier_count: self.nullifiers.len() as u64,
            nullifier_hash: self.nullifier_hash,
            epoch_fees: self.epoch_fees,
            validator_count: self.validators.values().filter(|v| v.active).count() as u64,
            epoch_seed: self.epoch_seed.seed,
            finalized_count,
            total_minted: self.total_minted,
        }
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
        let hash = crate::hash_domain(b"spectra.coinbase.blinding", &data);
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
        self.add_commitment(commitment);

        // Track total minted
        self.total_minted = self.total_minted.saturating_add(amount);

        Some(TxOutput {
            commitment,
            stealth_address,
            encrypted_note,
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
        let hash = crate::hash_domain(b"spectra.genesis.blinding", b"genesis-coinbase");
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
        self.add_commitment(commitment);
        self.total_minted = self.total_minted.saturating_add(amount);

        Some(TxOutput {
            commitment,
            stealth_address,
            encrypted_note,
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
            if !record.validator.active && record.bond == 0 {
                // Inactive with no bond = slashed
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
            nullifier_hash: meta.nullifier_hash,
            validators,
            validator_bonds,
            slashed_validators,
            epoch_seed,
            epoch_fees: meta.epoch_fees,
            epoch: meta.epoch,
            last_finalized: meta.last_finalized,
            total_minted: meta.total_minted,
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
    /// Call after BFT certification. The vertex must already be in the DAG
    /// (via `insert_vertex()`). Returns the coinbase output if one was created.
    pub fn finalize_vertex(
        &mut self,
        vertex_id: &VertexId,
    ) -> Result<Option<TxOutput>, StateError> {
        self.dag.finalize(vertex_id);
        if let Some(v) = self.dag.get(vertex_id) {
            let v = v.clone();
            return self.state.apply_vertex(&v);
        }
        Ok(None)
    }

    /// Apply a finalized vertex: insert into DAG, finalize, and update state.
    ///
    /// Convenience method that calls `insert_vertex()` then `finalize_vertex()`.
    /// Validates vertex structure including proposer signature. Returns the
    /// coinbase output if one was created.
    pub fn apply_finalized_vertex(
        &mut self,
        vertex: Vertex,
    ) -> Result<Option<TxOutput>, StateError> {
        let id = vertex.id;
        self.insert_vertex(vertex)?;
        self.finalize_vertex(&id)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::commitment::{BlindingFactor, Commitment};
    use crate::crypto::keys::SigningKeypair;
    use crate::crypto::nullifier::Nullifier;
    use crate::crypto::stark::spend_air::MERKLE_DEPTH;
    use crate::storage::SledStorage;

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

    #[test]
    fn chain_state_persist_restore_roundtrip() {
        let storage = SledStorage::open_temporary().unwrap();

        // Build up some state
        let mut state = ChainState::new();

        // Add commitments
        for i in 0..5u64 {
            let blind = BlindingFactor::from_bytes([i as u8; 32]);
            state.add_commitment(Commitment::commit(i * 100 + 1, &blind));
        }

        // Add nullifiers
        let n1 = Nullifier::derive(&[10u8; 32], &[20u8; 32]);
        let n2 = Nullifier::derive(&[30u8; 32], &[40u8; 32]);
        state.mark_nullifier(n1);
        state.mark_nullifier(n2);

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
        storage.put_validator(&validator, bond).unwrap();

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
            Some(crate::constants::VALIDATOR_BOND)
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
        state.add_commitment(Commitment::commit(42, &blind));
        state.mark_nullifier(Nullifier::derive(&[1u8; 32], &[2u8; 32]));

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
            Some(crate::constants::VALIDATOR_BOND)
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
        assert_eq!(state.epoch_fees(), crate::constants::VALIDATOR_BOND);
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

        assert_eq!(fees, crate::constants::VALIDATOR_BOND);
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
        state.add_commitment(Commitment::commit(500, &blind));

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
}
