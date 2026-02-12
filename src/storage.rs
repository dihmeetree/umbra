//! Persistent storage for blockchain data.
//!
//! Provides a `Storage` trait and a sled-backed implementation for persisting
//! vertices, transactions, nullifiers, and chain state metadata.

use serde::{Deserialize, Serialize};

use crate::consensus::dag::{Vertex, VertexId};
use crate::crypto::nullifier::Nullifier;
use crate::transaction::{Transaction, TxId};
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
        Ok(SledStorage {
            db,
            vertices,
            transactions,
            nullifiers,
            chain_meta,
            commitment_levels,
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
            bincode::serialize(vertex).map_err(|e| StorageError::Serialization(e.to_string()))?;
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
                let vertex = bincode::deserialize(&bytes)
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
        let value =
            bincode::serialize(tx).map_err(|e| StorageError::Serialization(e.to_string()))?;
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
                let tx = bincode::deserialize(&bytes)
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

    fn put_chain_state_meta(&self, meta: &ChainStateMeta) -> Result<(), StorageError> {
        let value =
            bincode::serialize(meta).map_err(|e| StorageError::Serialization(e.to_string()))?;
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
                let meta = bincode::deserialize(&bytes)
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
}
