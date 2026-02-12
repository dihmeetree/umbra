//! DAG (Directed Acyclic Graph) data structure for the Spectra ledger.
//!
//! Unlike a blockchain (linear chain of blocks), Spectra uses a DAG where
//! each vertex can reference multiple parent vertices. This enables:
//! - Parallel transaction processing
//! - Higher throughput (multiple vertices per time slot)
//! - Natural conflict resolution via causal ordering

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::crypto::keys::{Signature, SigningPublicKey};
use crate::transaction::{Transaction, TxId};
use crate::Hash;

/// Unique identifier for a DAG vertex.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VertexId(pub Hash);

/// A vertex in the DAG — the Spectra equivalent of a "block".
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
}

impl Vertex {
    /// Compute the vertex ID from its header fields.
    pub fn compute_id(
        parents: &[VertexId],
        epoch: u64,
        round: u64,
        proposer_fingerprint: &Hash,
        tx_root: &Hash,
    ) -> VertexId {
        let mut hasher = blake3::Hasher::new_derive_key("spectra.vertex.id");
        for p in parents {
            hasher.update(&p.0);
        }
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        hasher.update(proposer_fingerprint);
        hasher.update(tx_root);
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
            let expected_id = Self::compute_id(
                &self.parents,
                self.epoch,
                self.round,
                &self.proposer.fingerprint(),
                &self.tx_root(),
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
        let genesis_id = VertexId(crate::hash_domain(b"spectra.genesis", b"spectra-mainnet"));
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
    pub fn finalized_order(&self) -> Vec<VertexId> {
        // BFS from genesis, only including finalized vertices
        let mut ordered = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        // Find genesis (round 0)
        for (id, v) in &self.vertices {
            if v.round == 0 && self.finalized.contains(id) {
                queue.push_back(*id);
            }
        }

        while let Some(vid) = queue.pop_front() {
            if !visited.insert(vid) {
                continue;
            }
            ordered.push(vid);
            if let Some(children) = self.children.get(&vid) {
                for child in children {
                    if self.finalized.contains(child) {
                        // Only add if all parents are visited
                        let vertex = &self.vertices[child];
                        let all_parents_visited = vertex
                            .parents
                            .iter()
                            .all(|p| visited.contains(p) || !self.finalized.contains(p));
                        if all_parents_visited {
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

    /// Get all ancestors of a vertex (transitive parents).
    pub fn ancestors(&self, id: &VertexId) -> HashSet<VertexId> {
        let mut result = HashSet::new();
        let mut stack = vec![*id];
        while let Some(vid) = stack.pop() {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vertex_with_nonce(parents: Vec<VertexId>, round: u64, nonce: u8) -> Vertex {
        let id = Vertex::compute_id(&parents, 0, round, &[nonce; 32], &[round as u8; 32]);
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
}
