//! Persistent storage for blockchain data.
//!
//! Provides a `Storage` trait and a sled-backed implementation for persisting
//! vertices, transactions, nullifiers, and chain state metadata.

use serde::{Deserialize, Serialize};

use crate::consensus::bft::Validator;
use crate::consensus::dag::{Vertex, VertexId};
use crate::crypto::nullifier::Nullifier;
use crate::transaction::{Transaction, TxId, TxOutput};
use crate::Hash;

/// Errors from storage operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage I/O error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Metadata snapshot of the chain state for persistence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainStateMeta {
    pub epoch: u64,
    pub last_finalized: Option<VertexId>,
    pub state_root: Hash,
    pub commitment_root: Hash,
    pub commitment_count: u64,
    pub nullifier_count: u64,
    pub nullifier_hash: Hash,
    pub epoch_fees: u64,
    #[serde(default)]
    pub validator_count: u64,
    #[serde(default)]
    pub epoch_seed: Hash,
    #[serde(default)]
    pub finalized_count: u64,
    #[serde(default)]
    pub total_minted: u64,
}

/// Stored validator with bond information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub validator: Validator,
    pub bond: u64,
}

/// Trait for persistent storage backends.
pub trait Storage {
    fn put_vertex(&self, vertex: &Vertex) -> Result<(), StorageError>;
    fn get_vertex(&self, id: &VertexId) -> Result<Option<Vertex>, StorageError>;
    fn has_vertex(&self, id: &VertexId) -> Result<bool, StorageError>;

    fn put_transaction(&self, tx: &Transaction) -> Result<(), StorageError>;
    fn get_transaction(&self, id: &TxId) -> Result<Option<Transaction>, StorageError>;

    fn put_nullifier(&self, nullifier: &Nullifier) -> Result<(), StorageError>;
    fn has_nullifier(&self, nullifier: &Nullifier) -> Result<bool, StorageError>;
    fn get_all_nullifiers(&self) -> Result<Vec<Nullifier>, StorageError>;

    fn put_chain_state_meta(&self, meta: &ChainStateMeta) -> Result<(), StorageError>;
    fn get_chain_state_meta(&self) -> Result<Option<ChainStateMeta>, StorageError>;

    fn put_commitment_level(
        &self,
        level: usize,
        index: usize,
        hash: &Hash,
    ) -> Result<(), StorageError>;
    fn get_commitment_level(
        &self,
        level: usize,
        index: usize,
    ) -> Result<Option<Hash>, StorageError>;

    fn put_finalized_vertex_index(
        &self,
        sequence: u64,
        vertex_id: &VertexId,
    ) -> Result<(), StorageError>;
    fn get_finalized_vertices_after(
        &self,
        after_sequence: u64,
        limit: u32,
    ) -> Result<Vec<(u64, Vertex)>, StorageError>;
    fn finalized_vertex_count(&self) -> Result<u64, StorageError>;

    fn put_validator(&self, validator: &Validator, bond: u64) -> Result<(), StorageError>;
    fn get_validator(&self, id: &Hash) -> Result<Option<ValidatorRecord>, StorageError>;
    fn get_all_validators(&self) -> Result<Vec<ValidatorRecord>, StorageError>;
    fn remove_validator(&self, id: &Hash) -> Result<(), StorageError>;

    fn put_coinbase_output(&self, sequence: u64, output: &TxOutput) -> Result<(), StorageError>;
    fn get_coinbase_output(&self, sequence: u64) -> Result<Option<TxOutput>, StorageError>;

    fn flush(&self) -> Result<(), StorageError>;
}

/// Sled-backed storage implementation.
pub struct SledStorage {
    #[allow(dead_code)]
    db: sled::Db,
    vertices: sled::Tree,
    transactions: sled::Tree,
    nullifiers: sled::Tree,
    chain_meta: sled::Tree,
    commitment_levels: sled::Tree,
    validators: sled::Tree,
    finalized_index: sled::Tree,
    coinbase_outputs: sled::Tree,
    finalized_count: std::sync::atomic::AtomicU64,
}

impl SledStorage {
    /// Open or create a sled database at the given path.
    pub fn open(path: &std::path::Path) -> Result<Self, StorageError> {
        let db = sled::open(path).map_err(|e| StorageError::Io(e.to_string()))?;
        Self::from_db(db)
    }

    /// Open a temporary in-memory sled database (for testing).
    pub fn open_temporary() -> Result<Self, StorageError> {
        let config = sled::Config::new().temporary(true);
        let db = config.open().map_err(|e| StorageError::Io(e.to_string()))?;
        Self::from_db(db)
    }

    fn from_db(db: sled::Db) -> Result<Self, StorageError> {
        let vertices = db
            .open_tree("vertices")
            .map_err(|e| StorageError::Io(e.to_string()))?;
        let transactions = db
            .open_tree("transactions")
            .map_err(|e| StorageError::Io(e.to_string()))?;
        let nullifiers = db
            .open_tree("nullifiers")
            .map_err(|e| StorageError::Io(e.to_string()))?;
        let chain_meta = db
            .open_tree("chain_meta")
            .map_err(|e| StorageError::Io(e.to_string()))?;
        let commitment_levels = db
            .open_tree("commitment_levels")
            .map_err(|e| StorageError::Io(e.to_string()))?;
        let validators = db
            .open_tree("validators")
            .map_err(|e| StorageError::Io(e.to_string()))?;
        let finalized_index = db
            .open_tree("finalized_index")
            .map_err(|e| StorageError::Io(e.to_string()))?;
        let coinbase_outputs = db
            .open_tree("coinbase_outputs")
            .map_err(|e| StorageError::Io(e.to_string()))?;
        let finalized_count = std::sync::atomic::AtomicU64::new(finalized_index.len() as u64);
        Ok(SledStorage {
            db,
            vertices,
            transactions,
            nullifiers,
            chain_meta,
            commitment_levels,
            validators,
            finalized_index,
            coinbase_outputs,
            finalized_count,
        })
    }
}

fn commitment_level_key(level: usize, index: usize) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&(level as u64).to_le_bytes());
    key[8..].copy_from_slice(&(index as u64).to_le_bytes());
    key
}

impl Storage for SledStorage {
    fn put_vertex(&self, vertex: &Vertex) -> Result<(), StorageError> {
        let value =
            crate::serialize(vertex).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.vertices
            .insert(vertex.id.0, value)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn get_vertex(&self, id: &VertexId) -> Result<Option<Vertex>, StorageError> {
        match self
            .vertices
            .get(id.0)
            .map_err(|e| StorageError::Io(e.to_string()))?
        {
            Some(bytes) => {
                let vertex = crate::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(vertex))
            }
            None => Ok(None),
        }
    }

    fn has_vertex(&self, id: &VertexId) -> Result<bool, StorageError> {
        self.vertices
            .contains_key(id.0)
            .map_err(|e| StorageError::Io(e.to_string()))
    }

    fn put_transaction(&self, tx: &Transaction) -> Result<(), StorageError> {
        let tx_id = tx.tx_id();
        let value = crate::serialize(tx).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.transactions
            .insert(tx_id.0, value)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn get_transaction(&self, id: &TxId) -> Result<Option<Transaction>, StorageError> {
        match self
            .transactions
            .get(id.0)
            .map_err(|e| StorageError::Io(e.to_string()))?
        {
            Some(bytes) => {
                let tx = crate::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    fn put_nullifier(&self, nullifier: &Nullifier) -> Result<(), StorageError> {
        self.nullifiers
            .insert(nullifier.0, &[1u8])
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn has_nullifier(&self, nullifier: &Nullifier) -> Result<bool, StorageError> {
        self.nullifiers
            .contains_key(nullifier.0)
            .map_err(|e| StorageError::Io(e.to_string()))
    }

    fn get_all_nullifiers(&self) -> Result<Vec<Nullifier>, StorageError> {
        let mut nullifiers = Vec::new();
        for entry in self.nullifiers.iter() {
            let (key, _) = entry.map_err(|e| StorageError::Io(e.to_string()))?;
            let hash: Hash = key
                .as_ref()
                .try_into()
                .map_err(|_| StorageError::Serialization("invalid nullifier key".into()))?;
            nullifiers.push(Nullifier(hash));
        }
        Ok(nullifiers)
    }

    fn put_chain_state_meta(&self, meta: &ChainStateMeta) -> Result<(), StorageError> {
        let value =
            crate::serialize(meta).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.chain_meta
            .insert(b"current", value)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn get_chain_state_meta(&self) -> Result<Option<ChainStateMeta>, StorageError> {
        match self
            .chain_meta
            .get(b"current")
            .map_err(|e| StorageError::Io(e.to_string()))?
        {
            Some(bytes) => {
                let meta = crate::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }

    fn put_commitment_level(
        &self,
        level: usize,
        index: usize,
        hash: &Hash,
    ) -> Result<(), StorageError> {
        let key = commitment_level_key(level, index);
        self.commitment_levels
            .insert(key, hash.as_ref())
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn get_commitment_level(
        &self,
        level: usize,
        index: usize,
    ) -> Result<Option<Hash>, StorageError> {
        let key = commitment_level_key(level, index);
        match self
            .commitment_levels
            .get(key)
            .map_err(|e| StorageError::Io(e.to_string()))?
        {
            Some(bytes) => {
                let hash: Hash = bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| StorageError::Serialization("invalid hash length".into()))?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    fn put_finalized_vertex_index(
        &self,
        sequence: u64,
        vertex_id: &VertexId,
    ) -> Result<(), StorageError> {
        // Use big-endian so sled's lexicographic order matches numeric order
        self.finalized_index
            .insert(sequence.to_be_bytes(), &vertex_id.0)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.finalized_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn get_finalized_vertices_after(
        &self,
        after_sequence: u64,
        limit: u32,
    ) -> Result<Vec<(u64, Vertex)>, StorageError> {
        let start = match after_sequence.checked_add(1) {
            Some(s) => s,
            None => return Ok(Vec::new()), // u64::MAX + 1 overflows, nothing to return
        };
        let start_key = start.to_be_bytes();
        let mut results = Vec::new();
        for entry in self.finalized_index.range(start_key..) {
            if results.len() >= limit as usize {
                break;
            }
            let (key_bytes, vid_bytes) = entry.map_err(|e| StorageError::Io(e.to_string()))?;
            let seq = u64::from_be_bytes(
                key_bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| StorageError::Serialization("bad sequence key".into()))?,
            );
            let vid: Hash = vid_bytes
                .as_ref()
                .try_into()
                .map_err(|_| StorageError::Serialization("bad vertex id".into()))?;
            if let Some(vertex) = self.get_vertex(&VertexId(vid))? {
                results.push((seq, vertex));
            }
        }
        Ok(results)
    }

    fn finalized_vertex_count(&self) -> Result<u64, StorageError> {
        Ok(self
            .finalized_count
            .load(std::sync::atomic::Ordering::Relaxed))
    }

    fn put_validator(&self, validator: &Validator, bond: u64) -> Result<(), StorageError> {
        let record = ValidatorRecord {
            validator: validator.clone(),
            bond,
        };
        let value =
            crate::serialize(&record).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.validators
            .insert(validator.id, value)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn get_validator(&self, id: &Hash) -> Result<Option<ValidatorRecord>, StorageError> {
        match self
            .validators
            .get(id)
            .map_err(|e| StorageError::Io(e.to_string()))?
        {
            Some(bytes) => {
                let record = crate::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    fn get_all_validators(&self) -> Result<Vec<ValidatorRecord>, StorageError> {
        let mut records = Vec::new();
        for entry in self.validators.iter() {
            let (_, value) = entry.map_err(|e| StorageError::Io(e.to_string()))?;
            let record: ValidatorRecord = crate::deserialize(&value)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            records.push(record);
        }
        Ok(records)
    }

    fn remove_validator(&self, id: &Hash) -> Result<(), StorageError> {
        self.validators
            .remove(id)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn put_coinbase_output(&self, sequence: u64, output: &TxOutput) -> Result<(), StorageError> {
        let value =
            crate::serialize(output).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.coinbase_outputs
            .insert(sequence.to_be_bytes(), value)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn get_coinbase_output(&self, sequence: u64) -> Result<Option<TxOutput>, StorageError> {
        match self
            .coinbase_outputs
            .get(sequence.to_be_bytes())
            .map_err(|e| StorageError::Io(e.to_string()))?
        {
            Some(bytes) => {
                let output = crate::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(output))
            }
            None => Ok(None),
        }
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.db
            .flush()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{Signature, SigningKeypair};

    fn temp_storage() -> SledStorage {
        SledStorage::open_temporary().unwrap()
    }

    fn test_vertex() -> Vertex {
        let id = VertexId(crate::hash_domain(b"test", b"vertex1"));
        Vertex {
            id,
            parents: vec![],
            epoch: 0,
            round: 0,
            proposer: SigningKeypair::generate().public,
            transactions: vec![],
            timestamp: 1000,
            state_root: [0u8; 32],
            signature: Signature(vec![]),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        }
    }

    #[test]
    fn vertex_put_get_roundtrip() {
        let storage = temp_storage();
        let vertex = test_vertex();
        let id = vertex.id;

        storage.put_vertex(&vertex).unwrap();
        let retrieved = storage.get_vertex(&id).unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.epoch, 0);
    }

    #[test]
    fn vertex_not_found() {
        let storage = temp_storage();
        let id = VertexId([99u8; 32]);
        assert!(storage.get_vertex(&id).unwrap().is_none());
        assert!(!storage.has_vertex(&id).unwrap());
    }

    #[test]
    fn vertex_has() {
        let storage = temp_storage();
        let vertex = test_vertex();
        let id = vertex.id;

        assert!(!storage.has_vertex(&id).unwrap());
        storage.put_vertex(&vertex).unwrap();
        assert!(storage.has_vertex(&id).unwrap());
    }

    #[test]
    fn nullifier_put_and_has() {
        let storage = temp_storage();
        let nullifier = Nullifier([42u8; 32]);

        assert!(!storage.has_nullifier(&nullifier).unwrap());
        storage.put_nullifier(&nullifier).unwrap();
        assert!(storage.has_nullifier(&nullifier).unwrap());
    }

    #[test]
    fn chain_state_meta_roundtrip() {
        let storage = temp_storage();
        let meta = ChainStateMeta {
            epoch: 5,
            last_finalized: Some(VertexId([1u8; 32])),
            state_root: [2u8; 32],
            commitment_root: [3u8; 32],
            commitment_count: 100,
            nullifier_count: 50,
            nullifier_hash: [4u8; 32],
            epoch_fees: 1000,
            validator_count: 10,
            epoch_seed: [5u8; 32],
            finalized_count: 42,
            total_minted: 500_000,
        };

        assert!(storage.get_chain_state_meta().unwrap().is_none());
        storage.put_chain_state_meta(&meta).unwrap();
        let retrieved = storage.get_chain_state_meta().unwrap().unwrap();
        assert_eq!(retrieved.epoch, 5);
        assert_eq!(retrieved.commitment_count, 100);
        assert_eq!(retrieved.epoch_fees, 1000);
    }

    #[test]
    fn commitment_level_roundtrip() {
        let storage = temp_storage();
        let hash = [55u8; 32];

        assert!(storage.get_commitment_level(3, 7).unwrap().is_none());
        storage.put_commitment_level(3, 7, &hash).unwrap();
        let retrieved = storage.get_commitment_level(3, 7).unwrap().unwrap();
        assert_eq!(retrieved, hash);
    }

    #[test]
    fn flush_succeeds() {
        let storage = temp_storage();
        storage.flush().unwrap();
    }

    #[test]
    fn finalized_index_roundtrip() {
        let storage = temp_storage();
        let v1 = test_vertex();
        storage.put_vertex(&v1).unwrap();

        assert_eq!(storage.finalized_vertex_count().unwrap(), 0);
        storage.put_finalized_vertex_index(0, &v1.id).unwrap();
        assert_eq!(storage.finalized_vertex_count().unwrap(), 1);

        let results = storage.get_finalized_vertices_after(0, 10).unwrap();
        assert!(results.is_empty()); // after=0, so starts at seq 1

        let results = storage.get_finalized_vertices_after(u64::MAX, 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn finalized_index_batch_retrieval() {
        let storage = temp_storage();

        // Create and store 5 vertices
        let mut ids = Vec::new();
        for i in 0u8..5 {
            let id = VertexId(crate::hash_domain(b"test", &[i]));
            let vertex = Vertex {
                id,
                parents: vec![],
                epoch: 0,
                round: 0,
                proposer: SigningKeypair::generate().public,
                transactions: vec![],
                timestamp: 1000,
                state_root: [0u8; 32],
                signature: Signature(vec![]),
                vrf_proof: None,
                protocol_version: crate::constants::PROTOCOL_VERSION_ID,
            };
            storage.put_vertex(&vertex).unwrap();
            storage.put_finalized_vertex_index(i as u64, &id).unwrap();
            ids.push(id);
        }

        assert_eq!(storage.finalized_vertex_count().unwrap(), 5);

        // Get all from the start (after=max meaning "before first")
        // after_sequence=u64::MAX wraps, so use a helper: get from seq 0
        // get_finalized_vertices_after(u64::MAX, ..) → starts at 0
        // Actually after_sequence + 1 would overflow. Let me test with normal values.
        let results = storage.get_finalized_vertices_after(1, 10).unwrap();
        assert_eq!(results.len(), 3); // seq 2, 3, 4
        assert_eq!(results[0].0, 2);
        assert_eq!(results[1].0, 3);
        assert_eq!(results[2].0, 4);

        // Limit works
        let results = storage.get_finalized_vertices_after(0, 2).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn get_all_nullifiers_roundtrip() {
        let storage = temp_storage();
        let n1 = Nullifier([1u8; 32]);
        let n2 = Nullifier([2u8; 32]);

        assert!(storage.get_all_nullifiers().unwrap().is_empty());
        storage.put_nullifier(&n1).unwrap();
        storage.put_nullifier(&n2).unwrap();

        let all = storage.get_all_nullifiers().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn validator_put_get_roundtrip() {
        let storage = temp_storage();
        let kp = SigningKeypair::generate();
        let validator = crate::consensus::bft::Validator::new(kp.public.clone());
        let id = validator.id;

        assert!(storage.get_validator(&id).unwrap().is_none());
        storage.put_validator(&validator, 1_000_000).unwrap();

        let record = storage.get_validator(&id).unwrap().unwrap();
        assert_eq!(record.validator.id, id);
        assert_eq!(record.bond, 1_000_000);
        assert!(record.validator.active);
    }

    #[test]
    fn validator_get_all() {
        let storage = temp_storage();
        let kp1 = SigningKeypair::generate();
        let kp2 = SigningKeypair::generate();
        let v1 = crate::consensus::bft::Validator::new(kp1.public.clone());
        let v2 = crate::consensus::bft::Validator::new(kp2.public.clone());

        storage.put_validator(&v1, 1_000_000).unwrap();
        storage.put_validator(&v2, 2_000_000).unwrap();

        let all = storage.get_all_validators().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn validator_remove() {
        let storage = temp_storage();
        let kp = SigningKeypair::generate();
        let validator = crate::consensus::bft::Validator::new(kp.public.clone());
        let id = validator.id;

        storage.put_validator(&validator, 1_000_000).unwrap();
        assert!(storage.get_validator(&id).unwrap().is_some());

        storage.remove_validator(&id).unwrap();
        assert!(storage.get_validator(&id).unwrap().is_none());
    }
}
