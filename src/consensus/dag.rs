//! DAG (Directed Acyclic Graph) data structure for the Umbra ledger.
//!
//! Unlike a blockchain (linear chain of blocks), Umbra uses a DAG where
//! each vertex can reference multiple parent vertices. This enables:
//! - Parallel transaction processing
//! - Higher throughput (multiple vertices per time slot)
//! - Natural conflict resolution via causal ordering

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::crypto::keys::{Signature, SigningPublicKey};
use crate::crypto::vrf::{EpochSeed, VrfOutput};
use crate::transaction::{Transaction, TxId};
use crate::Hash;

/// Unique identifier for a DAG vertex.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VertexId(pub Hash);

/// A vertex in the DAG — the Umbra equivalent of a "block".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vertex {
    /// Unique vertex identifier (hash of header fields)
    pub id: VertexId,
    /// Parent vertex IDs (1..MAX_PARENTS)
    pub parents: Vec<VertexId>,
    /// Epoch number
    pub epoch: u64,
    /// Sequence number within the epoch (for ordering)
    pub round: u64,
    /// Validator who proposed this vertex
    pub proposer: SigningPublicKey,
    /// Transactions included in this vertex
    pub transactions: Vec<Transaction>,
    /// Timestamp (unix millis, advisory only — not used for consensus)
    pub timestamp: u64,
    /// State root after applying this vertex's transactions
    pub state_root: Hash,
    /// Proposer's signature over the vertex header
    pub signature: Signature,
    /// VRF proof showing the proposer was selected for this epoch's committee.
    /// `None` only for the genesis vertex.
    #[serde(default)]
    pub vrf_proof: Option<VrfOutput>,
    /// Protocol version signaled by this vertex (F16).
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
}

fn default_protocol_version() -> u32 {
    crate::constants::PROTOCOL_VERSION_ID
}

impl Vertex {
    /// Compute the vertex ID from its header fields.
    pub fn compute_id(
        parents: &[VertexId],
        epoch: u64,
        round: u64,
        proposer_fingerprint: &Hash,
        tx_root: &Hash,
        vrf_value: Option<&Hash>,
    ) -> VertexId {
        let mut hasher = blake3::Hasher::new_derive_key("umbra.vertex.id");
        for p in parents {
            hasher.update(&p.0);
        }
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        hasher.update(proposer_fingerprint);
        hasher.update(tx_root);
        if let Some(vrf_val) = vrf_value {
            hasher.update(vrf_val);
        }
        VertexId(*hasher.finalize().as_bytes())
    }

    /// Compute a Merkle root of the transactions in this vertex.
    pub fn tx_root(&self) -> Hash {
        if self.transactions.is_empty() {
            return [0u8; 32];
        }
        let tx_hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.tx_id().0).collect();
        let (root, _) = crate::crypto::proof::build_merkle_tree(&tx_hashes);
        root
    }

    /// Verify the vertex structure and proposer signature.
    ///
    /// `skip_signature`: set to `true` only for the genesis vertex (which has
    /// a synthetic proposer key). All other vertices MUST have valid signatures.
    pub fn validate_structure(&self, skip_signature: bool) -> Result<(), VertexError> {
        if self.parents.is_empty() && self.round != 0 {
            return Err(VertexError::NoParents);
        }
        if self.parents.len() > crate::constants::MAX_PARENTS {
            return Err(VertexError::TooManyParents);
        }
        if self.transactions.len() > crate::constants::MAX_TXS_PER_VERTEX {
            return Err(VertexError::TooManyTransactions);
        }

        // Check for duplicate parents
        let unique: HashSet<_> = self.parents.iter().collect();
        if unique.len() != self.parents.len() {
            return Err(VertexError::DuplicateParent);
        }

        // Verify proposer signature over the vertex header
        if !skip_signature {
            let vrf_value = self.vrf_proof.as_ref().map(|v| &v.value);
            let expected_id = Self::compute_id(
                &self.parents,
                self.epoch,
                self.round,
                &self.proposer.fingerprint(),
                &self.tx_root(),
                vrf_value,
            );
            if expected_id != self.id {
                return Err(VertexError::InvalidId);
            }
            if !self.proposer.verify(&self.id.0, &self.signature) {
                return Err(VertexError::InvalidSignature);
            }
        }

        Ok(())
    }

    /// Validate the VRF proof for this vertex (requires state context).
    ///
    /// Verifies the proposer was selected for the current epoch's committee.
    /// Separate from `validate_structure()` because it requires the epoch seed
    /// and total validator count.
    ///
    /// If `expected_commitment` is provided (from the BFT commitment registry),
    /// uses full `verify()` with anti-grinding commitment check. Otherwise
    /// falls back to `verify_proof_only()` for the first observation from this
    /// proposer in the epoch.
    pub fn validate_vrf(
        &self,
        epoch_seed: &EpochSeed,
        total_validators: usize,
        expected_commitment: Option<&Hash>,
    ) -> Result<(), VertexError> {
        let vrf = self.vrf_proof.as_ref().ok_or(VertexError::MissingVrf)?;
        let proposer_id = self.proposer.fingerprint();
        let vrf_input = epoch_seed.vrf_input(&proposer_id);

        // Verify VRF proof against the proposer's public key.
        // Use full verify() with commitment when available (anti-grinding).
        match expected_commitment {
            Some(commitment) => {
                if !vrf.verify(&self.proposer, &vrf_input, commitment) {
                    return Err(VertexError::InvalidVrf);
                }
            }
            None => {
                if !vrf.verify_proof_only(&self.proposer, &vrf_input) {
                    return Err(VertexError::InvalidVrf);
                }
            }
        }

        // Check that the proposer was actually selected
        if !vrf.is_selected(crate::constants::COMMITTEE_SIZE, total_validators) {
            return Err(VertexError::NotSelected);
        }

        Ok(())
    }

    /// Get all transaction IDs in this vertex.
    pub fn tx_ids(&self) -> Vec<TxId> {
        self.transactions.iter().map(|tx| tx.tx_id()).collect()
    }
}

/// The DAG data structure.
#[derive(Debug)]
pub struct Dag {
    /// All vertices indexed by their ID
    vertices: HashMap<VertexId, Vertex>,
    /// Children of each vertex (reverse edges)
    children: HashMap<VertexId, Vec<VertexId>>,
    /// The current "tips" — vertices with no children
    tips: HashSet<VertexId>,
    /// Vertices that have achieved BFT finality
    finalized: HashSet<VertexId>,
    /// Current round (monotonically increasing)
    current_round: u64,
    /// Current epoch
    current_epoch: u64,
}

impl Dag {
    /// Create a new DAG with a genesis vertex.
    pub fn new(genesis: Vertex) -> Self {
        let id = genesis.id;
        let mut vertices = HashMap::new();
        let mut tips = HashSet::new();
        let mut finalized = HashSet::new();

        vertices.insert(id, genesis);
        tips.insert(id);
        finalized.insert(id); // Genesis is finalized by definition

        Dag {
            vertices,
            children: HashMap::new(),
            tips,
            finalized,
            current_round: 0,
            current_epoch: 0,
        }
    }

    /// Create a genesis vertex.
    pub fn genesis_vertex() -> Vertex {
        let genesis_id = VertexId(crate::hash_domain(b"umbra.genesis", b"umbra-mainnet"));
        Vertex {
            id: genesis_id,
            parents: vec![],
            epoch: 0,
            round: 0,
            proposer: SigningPublicKey(vec![0; 2592]), // System (Dilithium5 key size)
            transactions: vec![],
            timestamp: 0,
            state_root: [0u8; 32],
            signature: Signature(vec![]),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        }
    }

    /// Insert a new vertex into the DAG.
    ///
    /// Validates structure and verifies the proposer's signature.
    pub fn insert(&mut self, vertex: Vertex) -> Result<(), VertexError> {
        self.insert_impl(vertex, false)
    }

    /// Insert a vertex, optionally skipping signature verification (for testing/genesis).
    pub fn insert_unchecked(&mut self, vertex: Vertex) -> Result<(), VertexError> {
        self.insert_impl(vertex, true)
    }

    fn insert_impl(&mut self, vertex: Vertex, skip_signature: bool) -> Result<(), VertexError> {
        vertex.validate_structure(skip_signature)?;

        // Limit unfinalized vertices to prevent memory exhaustion
        const MAX_UNFINALIZED: usize = 10_000;
        let unfinalized_count = self.vertices.len().saturating_sub(self.finalized.len());
        if unfinalized_count >= MAX_UNFINALIZED {
            return Err(VertexError::TooManyUnfinalized);
        }

        // Verify all parents exist
        for parent_id in &vertex.parents {
            if !self.vertices.contains_key(parent_id) {
                return Err(VertexError::MissingParent(*parent_id));
            }
        }

        // Verify round monotonicity: vertex round must be > all parent rounds
        for parent_id in &vertex.parents {
            if let Some(parent) = self.vertices.get(parent_id) {
                if vertex.round <= parent.round {
                    return Err(VertexError::RoundNotMonotonic);
                }
            }
        }

        // Check for duplicate vertex
        if self.vertices.contains_key(&vertex.id) {
            return Err(VertexError::DuplicateVertex);
        }

        let id = vertex.id;

        // Update parent-child relationships
        for parent_id in &vertex.parents {
            self.children.entry(*parent_id).or_default().push(id);
            self.tips.remove(parent_id);
        }

        self.tips.insert(id);
        self.vertices.insert(id, vertex);

        Ok(())
    }

    /// Mark a vertex as finalized (achieved BFT quorum).
    pub fn finalize(&mut self, vertex_id: &VertexId) -> bool {
        if self.vertices.contains_key(vertex_id) {
            self.finalized.insert(*vertex_id);
            true
        } else {
            false
        }
    }

    /// Get a vertex by ID.
    pub fn get(&self, id: &VertexId) -> Option<&Vertex> {
        self.vertices.get(id)
    }

    /// Get the current tips (vertices with no children).
    pub fn tips(&self) -> &HashSet<VertexId> {
        &self.tips
    }

    /// Check if a vertex is finalized.
    pub fn is_finalized(&self, id: &VertexId) -> bool {
        self.finalized.contains(id)
    }

    /// Get all finalized vertices in causal order (topological sort).
    ///
    /// Uses Kahn's algorithm (in-degree counting) to produce a correct
    /// topological order. This handles all DAG shapes including diamonds,
    /// and correctly includes finalized vertices whose only paths from
    /// genesis pass through non-finalized ancestors.
    pub fn finalized_order(&self) -> Vec<VertexId> {
        // Compute in-degree for each finalized vertex, counting only finalized parents.
        // Skip any finalized vertex that is missing from the vertices map (e.g. after pruning).
        let mut in_degree: HashMap<VertexId, usize> = HashMap::new();
        for &vid in &self.finalized {
            if let Some(v) = self.vertices.get(&vid) {
                let degree = v
                    .parents
                    .iter()
                    .filter(|p| self.finalized.contains(p))
                    .count();
                in_degree.insert(vid, degree);
            }
        }

        // Collect seed vertices (no finalized parents), sorted for determinism
        let mut seeds: Vec<VertexId> = in_degree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&v, _)| v)
            .collect();
        seeds.sort_by(|a, b| {
            let ra = self.vertices.get(a).map(|v| v.round).unwrap_or(0);
            let rb = self.vertices.get(b).map(|v| v.round).unwrap_or(0);
            ra.cmp(&rb).then_with(|| a.0.cmp(&b.0))
        });

        let mut queue: VecDeque<VertexId> = seeds.into_iter().collect();
        let mut ordered = Vec::with_capacity(self.finalized.len());

        while let Some(vid) = queue.pop_front() {
            ordered.push(vid);
            if let Some(children) = self.children.get(&vid) {
                for child in children {
                    if let Some(degree) = in_degree.get_mut(child) {
                        *degree -= 1;
                        if *degree == 0 {
                            queue.push_back(*child);
                        }
                    }
                }
            }
        }

        ordered
    }

    /// Get the total number of vertices.
    pub fn len(&self) -> usize {
        self.vertices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }

    /// Get current epoch.
    pub fn epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Advance the round counter.
    pub fn advance_round(&mut self) {
        self.current_round += 1;
        if self
            .current_round
            .is_multiple_of(crate::constants::EPOCH_LENGTH)
        {
            self.current_epoch += 1;
        }
    }

    /// Remove finalized vertices older than the given epoch from in-memory maps.
    ///
    /// Vertices remain in sled storage for historical sync. Returns the number
    /// of vertices pruned.
    pub fn prune_finalized(&mut self, before_epoch: u64) -> usize {
        let to_prune: Vec<VertexId> = self
            .finalized
            .iter()
            .filter(|vid| {
                self.vertices
                    .get(vid)
                    .map(|v| v.epoch < before_epoch)
                    .unwrap_or(false)
            })
            .copied()
            .collect();

        let count = to_prune.len();
        for vid in &to_prune {
            self.vertices.remove(vid);
            self.children.remove(vid);
            self.finalized.remove(vid);
            self.tips.remove(vid);
        }

        // Clean up stale child references
        for children_list in self.children.values_mut() {
            children_list.retain(|c| self.vertices.contains_key(c));
        }

        count
    }

    /// Get the number of finalized vertices.
    pub fn finalized_count(&self) -> usize {
        self.finalized.len()
    }

    /// Get all ancestors of a vertex (transitive parents), bounded by max depth.
    ///
    /// L8: The traversal is bounded to prevent DoS from extremely deep DAGs.
    /// Default limit is `EPOCH_LENGTH * 2` which covers two full epochs.
    pub fn ancestors(&self, id: &VertexId) -> HashSet<VertexId> {
        self.ancestors_bounded(id, crate::constants::EPOCH_LENGTH as usize * 2)
    }

    /// Get ancestors up to a maximum number of vertices visited.
    pub fn ancestors_bounded(&self, id: &VertexId, max_visited: usize) -> HashSet<VertexId> {
        let mut result = HashSet::new();
        let mut stack = vec![*id];
        while let Some(vid) = stack.pop() {
            if result.len() >= max_visited {
                break;
            }
            if let Some(v) = self.vertices.get(&vid) {
                for parent in &v.parents {
                    if result.insert(*parent) {
                        stack.push(*parent);
                    }
                }
            }
        }
        result
    }
}

/// Errors related to DAG vertices.
#[derive(Clone, Debug, thiserror::Error)]
pub enum VertexError {
    #[error("vertex has no parents (non-genesis)")]
    NoParents,
    #[error("vertex has too many parents")]
    TooManyParents,
    #[error("vertex has too many transactions")]
    TooManyTransactions,
    #[error("duplicate parent reference")]
    DuplicateParent,
    #[error("parent vertex not found: {0:?}")]
    MissingParent(VertexId),
    #[error("duplicate vertex ID")]
    DuplicateVertex,
    #[error("vertex round must be greater than all parent rounds")]
    RoundNotMonotonic,
    #[error("vertex ID does not match computed header hash")]
    InvalidId,
    #[error("proposer signature is invalid")]
    InvalidSignature,
    #[error("vertex missing VRF proof")]
    MissingVrf,
    #[error("invalid VRF proof")]
    InvalidVrf,
    #[error("proposer was not selected by VRF")]
    NotSelected,
    #[error("too many unfinalized vertices in DAG")]
    TooManyUnfinalized,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vertex_with_nonce(parents: Vec<VertexId>, round: u64, nonce: u8) -> Vertex {
        let id = Vertex::compute_id(&parents, 0, round, &[nonce; 32], &[round as u8; 32], None);
        Vertex {
            id,
            parents,
            epoch: 0,
            round,
            proposer: SigningPublicKey(vec![nonce; 32]),
            transactions: vec![],
            timestamp: round * 1000,
            state_root: [0u8; 32],
            signature: Signature(vec![]),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        }
    }

    fn make_vertex(parents: Vec<VertexId>, round: u64) -> Vertex {
        make_vertex_with_nonce(parents, round, 0)
    }

    #[test]
    fn dag_genesis() {
        let genesis = Dag::genesis_vertex();
        let dag = Dag::new(genesis.clone());
        assert_eq!(dag.len(), 1);
        assert!(dag.is_finalized(&genesis.id));
        assert!(dag.tips().contains(&genesis.id));
    }

    #[test]
    fn dag_insert_vertex() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        let v1 = make_vertex(vec![gid], 1);
        dag.insert_unchecked(v1.clone()).unwrap();

        assert_eq!(dag.len(), 2);
        assert!(dag.tips().contains(&v1.id));
        assert!(!dag.tips().contains(&gid));
    }

    #[test]
    fn dag_diamond_structure() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        // Two parallel vertices (different proposers)
        let v1 = make_vertex_with_nonce(vec![gid], 1, 0);
        let v2 = make_vertex_with_nonce(vec![gid], 1, 1);
        dag.insert_unchecked(v1.clone()).unwrap();
        dag.insert_unchecked(v2.clone()).unwrap();

        // Diamond merge
        let v3 = make_vertex(vec![v1.id, v2.id], 2);
        dag.insert_unchecked(v3.clone()).unwrap();

        assert_eq!(dag.len(), 4);
        assert_eq!(dag.tips().len(), 1);
        assert!(dag.tips().contains(&v3.id));
    }

    #[test]
    fn dag_missing_parent_rejected() {
        let genesis = Dag::genesis_vertex();
        let mut dag = Dag::new(genesis);

        let fake_parent = VertexId([99u8; 32]);
        let v = make_vertex(vec![fake_parent], 1);
        assert!(dag.insert_unchecked(v).is_err());
    }

    #[test]
    fn dag_round_not_monotonic_rejected() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        // Try to insert a vertex with round=0 (same as genesis)
        let v = make_vertex(vec![gid], 0);
        let result = dag.insert_unchecked(v);
        assert!(matches!(result, Err(VertexError::RoundNotMonotonic)));
    }

    #[test]
    fn dag_finalized_order() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        let v1 = make_vertex(vec![gid], 1);
        dag.insert_unchecked(v1.clone()).unwrap();
        dag.finalize(&v1.id);

        let order = dag.finalized_order();
        assert_eq!(order.len(), 2);
        assert_eq!(order[0], gid);
        assert_eq!(order[1], v1.id);
    }

    #[test]
    fn finalize_marks_vertex_as_finalized() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        let v1 = make_vertex(vec![gid], 1);
        let v1_id = v1.id;
        dag.insert_unchecked(v1).unwrap();

        assert!(!dag.is_finalized(&v1_id));
        dag.finalize(&v1_id);
        assert!(dag.is_finalized(&v1_id));
    }

    #[test]
    fn tips_updated_on_insert() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        // Genesis is the only tip
        assert!(dag.tips().contains(&gid));
        assert_eq!(dag.tips().len(), 1);

        // Insert child — genesis is no longer a tip
        let v1 = make_vertex(vec![gid], 1);
        let v1_id = v1.id;
        dag.insert_unchecked(v1).unwrap();

        assert!(!dag.tips().contains(&gid));
        assert!(dag.tips().contains(&v1_id));
    }

    #[test]
    fn len_and_is_empty() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let dag = Dag::new(genesis);

        assert!(!dag.is_empty());
        assert_eq!(dag.len(), 1);

        let mut dag2 = dag;
        let v1 = make_vertex(vec![gid], 1);
        dag2.insert_unchecked(v1).unwrap();
        assert_eq!(dag2.len(), 2);
    }

    #[test]
    fn insert_duplicate_rejected() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        let v1 = make_vertex(vec![gid], 1);
        dag.insert_unchecked(v1.clone()).unwrap();
        let result = dag.insert_unchecked(v1);
        assert!(matches!(result, Err(VertexError::DuplicateVertex)));
    }

    #[test]
    fn finalized_order_complex_diamond() {
        // Build a more complex DAG:
        //        genesis
        //        /     \
        //      v1       v2
        //       \      / \
        //        v3       v4
        //         \      /
        //          v5
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        let v1 = make_vertex_with_nonce(vec![gid], 1, 0);
        let v2 = make_vertex_with_nonce(vec![gid], 1, 1);
        dag.insert_unchecked(v1.clone()).unwrap();
        dag.insert_unchecked(v2.clone()).unwrap();

        let v3 = make_vertex_with_nonce(vec![v1.id, v2.id], 2, 0);
        let v4 = make_vertex_with_nonce(vec![v2.id], 2, 1);
        dag.insert_unchecked(v3.clone()).unwrap();
        dag.insert_unchecked(v4.clone()).unwrap();

        let v5 = make_vertex(vec![v3.id, v4.id], 3);
        dag.insert_unchecked(v5.clone()).unwrap();

        // Finalize all
        dag.finalize(&v1.id);
        dag.finalize(&v2.id);
        dag.finalize(&v3.id);
        dag.finalize(&v4.id);
        dag.finalize(&v5.id);

        let order = dag.finalized_order();
        assert_eq!(order.len(), 6); // genesis + 5 vertices

        // Genesis must be first
        assert_eq!(order[0], gid);

        // v1 and v2 must come before v3, v4
        let pos = |id: &VertexId| order.iter().position(|x| x == id).unwrap();
        assert!(pos(&v1.id) < pos(&v3.id));
        assert!(pos(&v2.id) < pos(&v3.id));
        assert!(pos(&v2.id) < pos(&v4.id));
        assert!(pos(&v3.id) < pos(&v5.id));
        assert!(pos(&v4.id) < pos(&v5.id));
    }

    #[test]
    fn finalized_count_tracks_correctly() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);
        assert_eq!(dag.finalized_count(), 1); // genesis is finalized

        let v1 = make_vertex(vec![gid], 1);
        dag.insert_unchecked(v1.clone()).unwrap();
        assert_eq!(dag.finalized_count(), 1);

        dag.finalize(&v1.id);
        assert_eq!(dag.finalized_count(), 2);
    }

    #[test]
    fn prune_finalized_removes_old_vertices() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        // Create vertex at epoch 5
        let id5 = Vertex::compute_id(&[gid], 5, 1, &[1; 32], &[1; 32], None);
        let v1 = Vertex {
            id: id5,
            parents: vec![gid],
            epoch: 5,
            round: 1,
            proposer: SigningPublicKey(vec![1; 32]),
            transactions: vec![],
            timestamp: 5000,
            state_root: [0u8; 32],
            signature: Signature(vec![]),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        };
        dag.insert_unchecked(v1.clone()).unwrap();
        dag.finalize(&v1.id);

        // Create vertex at epoch 200
        let id200 = Vertex::compute_id(&[v1.id], 200, 2, &[2; 32], &[2; 32], None);
        let v2 = Vertex {
            id: id200,
            parents: vec![v1.id],
            epoch: 200,
            round: 2,
            proposer: SigningPublicKey(vec![2; 32]),
            transactions: vec![],
            timestamp: 200000,
            state_root: [0u8; 32],
            signature: Signature(vec![]),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        };
        dag.insert_unchecked(v2.clone()).unwrap();
        dag.finalize(&v2.id);

        assert_eq!(dag.len(), 3); // genesis + v1 + v2
        assert_eq!(dag.finalized_count(), 3);

        // Prune vertices older than epoch 100
        let pruned = dag.prune_finalized(100);
        // Genesis (epoch 0) and v1 (epoch 5) should be pruned
        assert_eq!(pruned, 2);
        // v2 (epoch 200) remains
        assert_eq!(dag.len(), 1);
        assert!(dag.get(&v2.id).is_some());
    }

    #[test]
    fn reject_too_many_parents() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        // Build enough parent vertices first (MAX_PARENTS + 1 parents needed)
        let max = crate::constants::MAX_PARENTS; // 8
        let mut parent_ids = Vec::new();
        for i in 0..(max + 1) {
            let v = make_vertex_with_nonce(vec![gid], 1, i as u8);
            dag.insert_unchecked(v.clone()).unwrap();
            parent_ids.push(v.id);
        }

        // Create a vertex with MAX_PARENTS + 1 parents
        let bad_vertex = make_vertex_with_nonce(parent_ids, 2, 99);
        let result = dag.insert_unchecked(bad_vertex);
        assert!(matches!(result, Err(VertexError::TooManyParents)));
    }

    #[test]
    fn reject_too_many_transactions() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        // Create a vertex with more than MAX_TXS_PER_VERTEX transactions
        let id = Vertex::compute_id(&[gid], 0, 1, &[0; 32], &[0; 32], None);
        let dummy_tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            chain_id: [0u8; 32],
            expiry_epoch: 0,
            balance_proof: crate::crypto::stark::types::BalanceStarkProof {
                proof_bytes: vec![],
                public_inputs_bytes: vec![],
            },
            messages: vec![],
            tx_binding: [0u8; 32],
            tx_type: crate::transaction::TxType::Transfer,
        };
        let txs: Vec<Transaction> = (0..crate::constants::MAX_TXS_PER_VERTEX + 1)
            .map(|_| dummy_tx.clone())
            .collect();
        let v = Vertex {
            id,
            parents: vec![gid],
            epoch: 0,
            round: 1,
            proposer: SigningPublicKey(vec![0; 32]),
            transactions: txs,
            timestamp: 1000,
            state_root: [0u8; 32],
            signature: Signature(vec![]),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        };
        let result = dag.insert_unchecked(v);
        assert!(matches!(result, Err(VertexError::TooManyTransactions)));
    }

    #[test]
    fn reject_duplicate_parent() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        let v1 = make_vertex(vec![gid], 1);
        dag.insert_unchecked(v1.clone()).unwrap();

        // Create a vertex with the same parent listed twice
        let id = Vertex::compute_id(&[v1.id, v1.id], 0, 2, &[0; 32], &[0; 32], None);
        let dup_parent_vertex = Vertex {
            id,
            parents: vec![v1.id, v1.id],
            epoch: 0,
            round: 2,
            proposer: SigningPublicKey(vec![0; 32]),
            transactions: vec![],
            timestamp: 2000,
            state_root: [0u8; 32],
            signature: Signature(vec![]),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        };
        let result = dag.insert_unchecked(dup_parent_vertex);
        assert!(matches!(result, Err(VertexError::DuplicateParent)));
    }

    #[test]
    fn reject_no_parents_non_genesis() {
        let genesis = Dag::genesis_vertex();
        let mut dag = Dag::new(genesis);

        // Create a vertex with round > 0 but no parents
        let id = Vertex::compute_id(&[], 0, 1, &[0; 32], &[0; 32], None);
        let v = Vertex {
            id,
            parents: vec![],
            epoch: 0,
            round: 1,
            proposer: SigningPublicKey(vec![0; 32]),
            transactions: vec![],
            timestamp: 1000,
            state_root: [0u8; 32],
            signature: Signature(vec![]),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        };
        let result = dag.insert_unchecked(v);
        assert!(matches!(result, Err(VertexError::NoParents)));
    }

    #[test]
    fn reject_too_many_unfinalized() {
        // The MAX_UNFINALIZED limit is 10_000. To test this efficiently,
        // we manually build a DAG with a long chain and control finalization.
        // We create a chain of vertices from genesis, none finalized (except genesis).
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);
        // Genesis is finalized. We need 10_000 unfinalized vertices.
        // unfinalized_count = vertices.len() - finalized.len()
        // After inserting N vertices: vertices = N+1, finalized = 1, unfinalized = N
        // We need N = 10_000 to trigger the limit on the next insert.

        let mut prev_id = gid;
        for round in 1..=10_000u64 {
            let v = make_vertex_with_nonce(vec![prev_id], round, (round % 256) as u8);
            prev_id = v.id;
            dag.insert_unchecked(v).unwrap();
        }

        // Now unfinalized_count = 10_000, which equals MAX_UNFINALIZED
        // The next insert should be rejected
        let overflow_v = make_vertex_with_nonce(vec![prev_id], 10_001, 42);
        let result = dag.insert_unchecked(overflow_v);
        assert!(matches!(result, Err(VertexError::TooManyUnfinalized)));
    }

    #[test]
    fn finalized_order_excludes_non_finalized() {
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        let v1 = make_vertex_with_nonce(vec![gid], 1, 0);
        let v2 = make_vertex_with_nonce(vec![gid], 1, 1);
        dag.insert_unchecked(v1.clone()).unwrap();
        dag.insert_unchecked(v2.clone()).unwrap();

        // Finalize only v1, not v2
        dag.finalize(&v1.id);

        let order = dag.finalized_order();
        // Should contain genesis and v1 only
        assert_eq!(order.len(), 2);
        assert!(order.contains(&gid));
        assert!(order.contains(&v1.id));
        assert!(!order.contains(&v2.id));
    }

    #[test]
    fn finalize_unknown_vertex_returns_false() {
        let genesis = Dag::genesis_vertex();
        let mut dag = Dag::new(genesis);

        let unknown_id = VertexId([0xAB; 32]);
        assert!(!dag.finalize(&unknown_id));
    }

    #[test]
    fn safe_indexing_missing_vertex() {
        // Regression test: after pruning, finalized_order must not panic
        // even if the finalized set references vertex IDs that have been
        // removed from the vertices map.
        let genesis = Dag::genesis_vertex();
        let gid = genesis.id;
        let mut dag = Dag::new(genesis);

        // Build: genesis -> v1 (epoch 0) -> v2 (epoch 100)
        let id1 = Vertex::compute_id(&[gid], 0, 1, &[1; 32], &[1; 32], None);
        let v1 = Vertex {
            id: id1,
            parents: vec![gid],
            epoch: 0,
            round: 1,
            proposer: SigningPublicKey(vec![1; 32]),
            transactions: vec![],
            timestamp: 1000,
            state_root: [0u8; 32],
            signature: Signature(vec![]),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        };
        dag.insert_unchecked(v1.clone()).unwrap();
        dag.finalize(&v1.id);

        let id2 = Vertex::compute_id(&[v1.id], 100, 2, &[2; 32], &[2; 32], None);
        let v2 = Vertex {
            id: id2,
            parents: vec![v1.id],
            epoch: 100,
            round: 2,
            proposer: SigningPublicKey(vec![2; 32]),
            transactions: vec![],
            timestamp: 100000,
            state_root: [0u8; 32],
            signature: Signature(vec![]),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        };
        dag.insert_unchecked(v2.clone()).unwrap();
        dag.finalize(&v2.id);

        // Prune vertices older than epoch 50 (removes genesis and v1)
        let pruned = dag.prune_finalized(50);
        assert_eq!(pruned, 2);

        // finalized_order should not panic; it should return only v2
        // (genesis and v1 were pruned from vertices map)
        let order = dag.finalized_order();
        assert_eq!(order.len(), 1);
        assert_eq!(order[0], v2.id);
    }
}
