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
    /// Whether this validator has been permanently slashed.
    /// Added to distinguish slashed from deregistered validators on restore.
    #[serde(default)]
    pub slashed: bool,
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

    /// Retrieve all stored commitment tree level nodes.
    fn get_all_commitment_levels(&self) -> Result<Vec<(usize, usize, Hash)>, StorageError>;

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

    fn put_validator(
        &self,
        validator: &Validator,
        bond: u64,
        slashed: bool,
    ) -> Result<(), StorageError>;
    fn get_validator(&self, id: &Hash) -> Result<Option<ValidatorRecord>, StorageError>;
    fn get_all_validators(&self) -> Result<Vec<ValidatorRecord>, StorageError>;
    fn remove_validator(&self, id: &Hash) -> Result<(), StorageError>;

    fn put_coinbase_output(&self, sequence: u64, output: &TxOutput) -> Result<(), StorageError>;
    fn get_coinbase_output(&self, sequence: u64) -> Result<Option<TxOutput>, StorageError>;

    /// Persist a peer ban. `banned_until_ms` is ms since UNIX epoch.
    fn put_peer_ban(&self, peer_id: &Hash, banned_until_ms: u64) -> Result<(), StorageError>;
    /// Load all persisted peer bans (peer_id, banned_until_ms).
    fn get_peer_bans(&self) -> Result<Vec<(Hash, u64)>, StorageError>;
    /// Remove a peer ban (e.g. after expiry).
    fn remove_peer_ban(&self, peer_id: &Hash) -> Result<(), StorageError>;

    fn flush(&self) -> Result<(), StorageError>;

    /// Apply a batch of finalization writes atomically.
    ///
    /// Groups all writes (vertex, transactions, nullifiers, commitment levels,
    /// finalized index, validators, coinbase output, chain meta) into per-tree
    /// sled batches and applies them together, reducing fsync overhead.
    fn apply_finalization_batch(&self, batch: &FinalizationBatch) -> Result<(), StorageError>;

    /// Mark that a snapshot import is in progress (crash-recovery flag).
    fn set_import_in_progress(&self, in_progress: bool) -> Result<(), StorageError>;

    /// Check whether a snapshot import was interrupted.
    fn is_import_in_progress(&self) -> Result<bool, StorageError>;

    /// Clear all state-related trees for snapshot import.
    ///
    /// Clears: nullifiers, commitment_levels, validators, chain_meta, finalized_index.
    /// Does NOT clear: vertices, transactions, coinbase_outputs (historical data).
    fn clear_for_snapshot_import(&self) -> Result<(), StorageError>;
}

/// A batch of writes to apply atomically during vertex finalization.
#[derive(Default)]
pub struct FinalizationBatch {
    pub vertices: Vec<Vertex>,
    pub transactions: Vec<Transaction>,
    pub nullifiers: Vec<Nullifier>,
    pub commitment_levels: Vec<(usize, usize, Hash)>,
    pub finalized_indices: Vec<(u64, VertexId)>,
    pub validators: Vec<(Validator, u64, bool)>,
    pub removed_validators: Vec<Hash>,
    pub coinbase_outputs: Vec<(u64, TxOutput)>,
    pub chain_state_meta: Option<ChainStateMeta>,
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
    peer_bans: sled::Tree,
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
        let peer_bans = db
            .open_tree("peer_bans")
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
            peer_bans,
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

    fn get_all_commitment_levels(&self) -> Result<Vec<(usize, usize, Hash)>, StorageError> {
        let mut results = Vec::new();
        for entry in self.commitment_levels.iter() {
            let (key_bytes, value_bytes) = entry.map_err(|e| StorageError::Io(e.to_string()))?;
            if key_bytes.len() != 16 {
                tracing::warn!(
                    key_len = key_bytes.len(),
                    "Skipping corrupted commitment level entry with invalid key length"
                );
                continue;
            }
            let level = u64::from_le_bytes(
                key_bytes[..8]
                    .try_into()
                    .map_err(|_| StorageError::Serialization("bad level key".into()))?,
            ) as usize;
            let index = u64::from_le_bytes(
                key_bytes[8..16]
                    .try_into()
                    .map_err(|_| StorageError::Serialization("bad index key".into()))?,
            ) as usize;
            let hash: Hash = value_bytes
                .as_ref()
                .try_into()
                .map_err(|_| StorageError::Serialization("bad hash length".into()))?;
            results.push((level, index, hash));
        }
        Ok(results)
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
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn get_finalized_vertices_after(
        &self,
        after_sequence: u64,
        limit: u32,
    ) -> Result<Vec<(u64, Vertex)>, StorageError> {
        // u64::MAX is a sentinel meaning "start from the very beginning (seq 0)"
        let start = match after_sequence {
            u64::MAX => 0,
            s => s + 1,
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
            .load(std::sync::atomic::Ordering::Acquire))
    }

    fn put_validator(
        &self,
        validator: &Validator,
        bond: u64,
        slashed: bool,
    ) -> Result<(), StorageError> {
        let record = ValidatorRecord {
            validator: validator.clone(),
            bond,
            slashed,
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

    fn put_peer_ban(&self, peer_id: &Hash, banned_until_ms: u64) -> Result<(), StorageError> {
        self.peer_bans
            .insert(peer_id, &banned_until_ms.to_be_bytes())
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn get_peer_bans(&self) -> Result<Vec<(Hash, u64)>, StorageError> {
        let mut bans = Vec::new();
        for entry in self.peer_bans.iter() {
            let (key, value) = entry.map_err(|e| StorageError::Io(e.to_string()))?;
            if key.len() == 32 && value.len() == 8 {
                let mut peer_id = [0u8; 32];
                peer_id.copy_from_slice(&key);
                let banned_until = u64::from_be_bytes(value[..8].try_into().unwrap());
                bans.push((peer_id, banned_until));
            }
        }
        Ok(bans)
    }

    fn remove_peer_ban(&self, peer_id: &Hash) -> Result<(), StorageError> {
        self.peer_bans
            .remove(peer_id)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn apply_finalization_batch(&self, batch: &FinalizationBatch) -> Result<(), StorageError> {
        let mut vert_batch = sled::Batch::default();
        for v in &batch.vertices {
            let value =
                crate::serialize(v).map_err(|e| StorageError::Serialization(e.to_string()))?;
            vert_batch.insert(&v.id.0, value);
        }

        let mut tx_batch = sled::Batch::default();
        for tx in &batch.transactions {
            let id = tx.tx_id();
            let value =
                crate::serialize(tx).map_err(|e| StorageError::Serialization(e.to_string()))?;
            tx_batch.insert(&id.0, value);
        }

        let mut null_batch = sled::Batch::default();
        for n in &batch.nullifiers {
            null_batch.insert(&n.0, &[1u8]);
        }

        let mut cl_batch = sled::Batch::default();
        for &(level, index, ref hash) in &batch.commitment_levels {
            let key = commitment_level_key(level, index);
            cl_batch.insert(&key, hash.as_ref());
        }

        let mut fi_batch = sled::Batch::default();
        for &(seq, ref vid) in &batch.finalized_indices {
            fi_batch.insert(&seq.to_be_bytes(), &vid.0);
        }

        let mut val_batch = sled::Batch::default();
        for (validator, bond, slashed) in &batch.validators {
            let record = ValidatorRecord {
                validator: validator.clone(),
                bond: *bond,
                slashed: *slashed,
            };
            let value = crate::serialize(&record)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            val_batch.insert(&validator.id, value);
        }
        for id in &batch.removed_validators {
            val_batch.remove(id.as_ref());
        }

        let mut cb_batch = sled::Batch::default();
        for (seq, output) in &batch.coinbase_outputs {
            let value =
                crate::serialize(output).map_err(|e| StorageError::Serialization(e.to_string()))?;
            cb_batch.insert(&seq.to_be_bytes(), value);
        }

        let mut meta_batch = sled::Batch::default();
        if let Some(ref meta) = batch.chain_state_meta {
            let value =
                crate::serialize(meta).map_err(|e| StorageError::Serialization(e.to_string()))?;
            meta_batch.insert(b"current".as_ref(), value);
        }

        // Apply all batches
        self.vertices
            .apply_batch(vert_batch)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.transactions
            .apply_batch(tx_batch)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.nullifiers
            .apply_batch(null_batch)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.commitment_levels
            .apply_batch(cl_batch)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.finalized_index
            .apply_batch(fi_batch)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.validators
            .apply_batch(val_batch)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.coinbase_outputs
            .apply_batch(cb_batch)
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.chain_meta
            .apply_batch(meta_batch)
            .map_err(|e| StorageError::Io(e.to_string()))?;

        self.finalized_count.fetch_add(
            batch.finalized_indices.len() as u64,
            std::sync::atomic::Ordering::Release,
        );

        self.db
            .flush()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn set_import_in_progress(&self, in_progress: bool) -> Result<(), StorageError> {
        if in_progress {
            self.chain_meta
                .insert(b"import_in_progress", &[1u8])
                .map_err(|e| StorageError::Io(e.to_string()))?;
        } else {
            self.chain_meta
                .remove(b"import_in_progress")
                .map_err(|e| StorageError::Io(e.to_string()))?;
        }
        self.db
            .flush()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn is_import_in_progress(&self) -> Result<bool, StorageError> {
        self.chain_meta
            .contains_key(b"import_in_progress")
            .map_err(|e| StorageError::Io(e.to_string()))
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.db
            .flush()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(())
    }

    fn clear_for_snapshot_import(&self) -> Result<(), StorageError> {
        self.nullifiers
            .clear()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.commitment_levels
            .clear()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.validators
            .clear()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.chain_meta
            .clear()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.finalized_index
            .clear()
            .map_err(|e| StorageError::Io(e.to_string()))?;
        self.finalized_count
            .store(0, std::sync::atomic::Ordering::Release);
        // Flush to ensure all clears are persisted before snapshot import
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
            signature: Signature::empty(),
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

        // u64::MAX is a sentinel meaning "start from seq 0"
        let results = storage.get_finalized_vertices_after(u64::MAX, 10).unwrap();
        assert_eq!(results.len(), 1); // returns the vertex at seq 0
        assert_eq!(results[0].0, 0);
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
                signature: Signature::empty(),
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
        storage.put_validator(&validator, 1_000_000, false).unwrap();

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

        storage.put_validator(&v1, 1_000_000, false).unwrap();
        storage.put_validator(&v2, 2_000_000, false).unwrap();

        let all = storage.get_all_validators().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn validator_remove() {
        let storage = temp_storage();
        let kp = SigningKeypair::generate();
        let validator = crate::consensus::bft::Validator::new(kp.public.clone());
        let id = validator.id;

        storage.put_validator(&validator, 1_000_000, false).unwrap();
        assert!(storage.get_validator(&id).unwrap().is_some());

        storage.remove_validator(&id).unwrap();
        assert!(storage.get_validator(&id).unwrap().is_none());
    }

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

    /// Build a valid Transfer transaction with 1 input and 1 output.
    /// Deterministic fee = 200 (FEE_BASE + 1*FEE_PER_INPUT).
    fn make_test_tx(seed: u8) -> Transaction {
        let recipient = crate::crypto::keys::FullKeypair::generate();
        // 1 input, 1 output, no messages → fee = 200
        let output_value = 100u64;
        let input_value = output_value + 200; // 300
        crate::transaction::builder::TransactionBuilder::new()
            .add_input(crate::transaction::builder::InputSpec {
                value: input_value,
                blinding: crate::crypto::commitment::BlindingFactor::from_bytes([seed; 32]),
                spend_auth: crate::hash_domain(b"test", &[seed]),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), output_value)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap()
    }

    fn make_test_output() -> TxOutput {
        let recipient = crate::crypto::keys::FullKeypair::generate();
        let blinding = crate::crypto::commitment::BlindingFactor::random();
        let commitment = crate::crypto::commitment::Commitment::commit(500, &blinding);
        let stealth_result =
            crate::crypto::stealth::StealthAddress::generate(&recipient.kem.public, 0).unwrap();
        let note_data = {
            let mut d = Vec::with_capacity(40);
            d.extend_from_slice(&500u64.to_le_bytes());
            d.extend_from_slice(&blinding.0);
            d
        };
        let encrypted_note =
            crate::crypto::encryption::EncryptedPayload::encrypt_with_shared_secret(
                &stealth_result.shared_secret,
                stealth_result.address.kem_ciphertext.clone(),
                &note_data,
            )
            .unwrap();
        let blake3_binding = crate::crypto::commitment::blake3_512_binding(500, &blinding);
        TxOutput {
            commitment,
            stealth_address: stealth_result.address,
            encrypted_note,
            blake3_binding,
        }
    }

    #[test]
    fn transaction_put_get_roundtrip() {
        let storage = temp_storage();
        let tx = make_test_tx(1);
        let tx_id = tx.tx_id();

        storage.put_transaction(&tx).unwrap();
        let retrieved = storage.get_transaction(&tx_id).unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.tx_id(), tx_id);
        assert_eq!(retrieved.fee, 200); // deterministic: 1 input
        assert_eq!(retrieved.inputs.len(), tx.inputs.len());
        assert_eq!(retrieved.outputs.len(), tx.outputs.len());
    }

    #[test]
    fn transaction_not_found() {
        let storage = temp_storage();
        let missing_id = TxId([99u8; 32]);
        assert!(storage.get_transaction(&missing_id).unwrap().is_none());
    }

    #[test]
    fn coinbase_output_put_get_roundtrip() {
        let storage = temp_storage();
        let output = make_test_output();
        let sequence = 42u64;

        storage.put_coinbase_output(sequence, &output).unwrap();
        let retrieved = storage.get_coinbase_output(sequence).unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.commitment.0, output.commitment.0);
        assert_eq!(
            retrieved.stealth_address.one_time_key,
            output.stealth_address.one_time_key
        );
    }

    #[test]
    fn coinbase_output_not_found() {
        let storage = temp_storage();
        assert!(storage.get_coinbase_output(9999).unwrap().is_none());
    }

    #[test]
    fn overwrite_vertex() {
        let storage = temp_storage();

        // Create first vertex
        let id = VertexId(crate::hash_domain(b"test", b"overwrite"));
        let v1 = Vertex {
            id,
            parents: vec![],
            epoch: 1,
            round: 10,
            proposer: SigningKeypair::generate().public,
            transactions: vec![],
            timestamp: 1000,
            state_root: [0u8; 32],
            signature: Signature::empty(),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        };
        storage.put_vertex(&v1).unwrap();

        // Create second vertex with the same ID but different fields
        let v2 = Vertex {
            id,
            parents: vec![],
            epoch: 2,
            round: 20,
            proposer: SigningKeypair::generate().public,
            transactions: vec![],
            timestamp: 2000,
            state_root: [1u8; 32],
            signature: Signature::empty(),
            vrf_proof: None,
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
        };
        storage.put_vertex(&v2).unwrap();

        // Get should return the second version
        let retrieved = storage.get_vertex(&id).unwrap().unwrap();
        assert_eq!(retrieved.epoch, 2);
        assert_eq!(retrieved.round, 20);
        assert_eq!(retrieved.timestamp, 2000);
        assert_eq!(retrieved.state_root, [1u8; 32]);
    }

    #[test]
    fn get_all_commitment_levels_roundtrip() {
        let storage = temp_storage();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let h3 = [3u8; 32];

        storage.put_commitment_level(0, 0, &h1).unwrap();
        storage.put_commitment_level(0, 1, &h2).unwrap();
        storage.put_commitment_level(1, 0, &h3).unwrap();

        let all = storage.get_all_commitment_levels().unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&(0, 0, h1)));
        assert!(all.contains(&(0, 1, h2)));
        assert!(all.contains(&(1, 0, h3)));
    }

    #[test]
    fn clear_for_snapshot_import_clears_trees() {
        let storage = temp_storage();

        // Populate data
        storage.put_nullifier(&Nullifier([1u8; 32])).unwrap();
        storage.put_commitment_level(0, 0, &[2u8; 32]).unwrap();
        let kp = SigningKeypair::generate();
        let v = crate::consensus::bft::Validator::new(kp.public);
        storage.put_validator(&v, 1_000_000, false).unwrap();
        let meta = ChainStateMeta {
            epoch: 1,
            last_finalized: None,
            state_root: [0u8; 32],
            commitment_root: [0u8; 32],
            commitment_count: 0,
            nullifier_count: 0,
            nullifier_hash: [0u8; 32],
            epoch_fees: 0,
            validator_count: 0,
            epoch_seed: [0u8; 32],
            finalized_count: 0,
            total_minted: 0,
        };
        storage.put_chain_state_meta(&meta).unwrap();
        let vid = VertexId([3u8; 32]);
        storage.put_finalized_vertex_index(0, &vid).unwrap();

        // Clear
        storage.clear_for_snapshot_import().unwrap();

        // Everything should be empty
        assert!(storage.get_all_nullifiers().unwrap().is_empty());
        assert!(storage.get_all_commitment_levels().unwrap().is_empty());
        assert!(storage.get_all_validators().unwrap().is_empty());
        assert!(storage.get_chain_state_meta().unwrap().is_none());
        assert_eq!(storage.finalized_vertex_count().unwrap(), 0);
    }

    #[test]
    fn apply_finalization_batch_roundtrip() {
        let storage = temp_storage();

        let v = test_vertex();
        let vid = v.id;
        let tx = make_test_tx(10);
        let tx_id = tx.tx_id();
        let nullifier = Nullifier([77u8; 32]);
        let commit_hash = [88u8; 32];
        let cb_output = make_test_output();

        let meta = ChainStateMeta {
            epoch: 3,
            last_finalized: Some(vid),
            state_root: [9u8; 32],
            commitment_root: [10u8; 32],
            commitment_count: 1,
            nullifier_count: 1,
            nullifier_hash: [11u8; 32],
            epoch_fees: 200,
            validator_count: 0,
            epoch_seed: [12u8; 32],
            finalized_count: 1,
            total_minted: 50_000,
        };

        let batch = super::FinalizationBatch {
            vertices: vec![v],
            transactions: vec![tx],
            nullifiers: vec![nullifier],
            commitment_levels: vec![(0, 0, commit_hash)],
            finalized_indices: vec![(0, vid)],
            validators: vec![],
            removed_validators: vec![],
            coinbase_outputs: vec![(0, cb_output)],
            chain_state_meta: Some(meta),
        };

        storage.apply_finalization_batch(&batch).unwrap();

        assert!(storage.has_vertex(&vid).unwrap());
        assert!(storage.get_transaction(&tx_id).unwrap().is_some());
        assert!(storage.has_nullifier(&nullifier).unwrap());
        assert_eq!(
            storage.get_commitment_level(0, 0).unwrap().unwrap(),
            commit_hash
        );
        assert_eq!(storage.finalized_vertex_count().unwrap(), 1);
        assert!(storage.get_coinbase_output(0).unwrap().is_some());
        let restored_meta = storage.get_chain_state_meta().unwrap().unwrap();
        assert_eq!(restored_meta.epoch, 3);
    }

    #[test]
    fn import_in_progress_flag() {
        let storage = temp_storage();
        assert!(!storage.is_import_in_progress().unwrap());
        storage.set_import_in_progress(true).unwrap();
        assert!(storage.is_import_in_progress().unwrap());
        storage.set_import_in_progress(false).unwrap();
        assert!(!storage.is_import_in_progress().unwrap());
    }

    #[test]
    fn get_vertex_returns_none_for_missing() {
        let storage = SledStorage::open_temporary().unwrap();
        let missing_id = crate::consensus::dag::VertexId([0xFFu8; 32]);
        assert!(storage.get_vertex(&missing_id).unwrap().is_none());
    }

    #[test]
    fn has_vertex_returns_false_for_missing() {
        let storage = SledStorage::open_temporary().unwrap();
        let missing_id = crate::consensus::dag::VertexId([0xFFu8; 32]);
        assert!(!storage.has_vertex(&missing_id).unwrap());
    }

    #[test]
    fn has_nullifier_returns_false_for_missing() {
        let storage = SledStorage::open_temporary().unwrap();
        let missing = crate::crypto::nullifier::Nullifier([0xFFu8; 32]);
        assert!(!storage.has_nullifier(&missing).unwrap());
    }

    #[test]
    fn get_chain_state_meta_returns_none_initially() {
        let storage = SledStorage::open_temporary().unwrap();
        assert!(storage.get_chain_state_meta().unwrap().is_none());
    }

    #[test]
    fn get_transaction_returns_none_for_missing() {
        let storage = SledStorage::open_temporary().unwrap();
        let missing = crate::transaction::TxId([0xFFu8; 32]);
        assert!(storage.get_transaction(&missing).unwrap().is_none());
    }

    #[test]
    fn get_validator_returns_none_for_missing() {
        let storage = SledStorage::open_temporary().unwrap();
        let missing = [0xFFu8; 32];
        assert!(storage.get_validator(&missing).unwrap().is_none());
    }

    #[test]
    fn get_coinbase_output_returns_none_for_missing() {
        let storage = SledStorage::open_temporary().unwrap();
        let missing_seq: u64 = 0xFFFFFFFF;
        assert!(storage.get_coinbase_output(missing_seq).unwrap().is_none());
    }

    #[test]
    fn finalized_vertex_count_initially_zero() {
        let storage = SledStorage::open_temporary().unwrap();
        assert_eq!(storage.finalized_vertex_count().unwrap(), 0);
    }

    #[test]
    fn get_all_nullifiers_empty_initially() {
        let storage = SledStorage::open_temporary().unwrap();
        let nullifiers = storage.get_all_nullifiers().unwrap();
        assert!(nullifiers.is_empty());
    }

    #[test]
    fn get_all_validators_empty_initially() {
        let storage = SledStorage::open_temporary().unwrap();
        let validators = storage.get_all_validators().unwrap();
        assert!(validators.is_empty());
    }

    #[test]
    fn get_all_commitment_levels_empty_initially() {
        let storage = SledStorage::open_temporary().unwrap();
        let levels = storage.get_all_commitment_levels().unwrap();
        assert!(levels.is_empty());
    }

    #[test]
    fn put_and_get_multiple_nullifiers() {
        let storage = SledStorage::open_temporary().unwrap();
        let n1 = crate::crypto::nullifier::Nullifier([1u8; 32]);
        let n2 = crate::crypto::nullifier::Nullifier([2u8; 32]);
        let n3 = crate::crypto::nullifier::Nullifier([3u8; 32]);

        storage.put_nullifier(&n1).unwrap();
        storage.put_nullifier(&n2).unwrap();
        storage.put_nullifier(&n3).unwrap();

        assert!(storage.has_nullifier(&n1).unwrap());
        assert!(storage.has_nullifier(&n2).unwrap());
        assert!(storage.has_nullifier(&n3).unwrap());

        let all = storage.get_all_nullifiers().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn put_nullifier_idempotent() {
        let storage = SledStorage::open_temporary().unwrap();
        let n = crate::crypto::nullifier::Nullifier([42u8; 32]);
        storage.put_nullifier(&n).unwrap();
        storage.put_nullifier(&n).unwrap(); // Second insert should not error
        assert!(storage.has_nullifier(&n).unwrap());
    }

    #[test]
    fn get_finalized_vertices_after_empty() {
        let storage = SledStorage::open_temporary().unwrap();
        let vertices = storage.get_finalized_vertices_after(0, 100).unwrap();
        assert!(vertices.is_empty());
    }

    #[test]
    fn clear_for_snapshot_import_removes_all_data() {
        let storage = SledStorage::open_temporary().unwrap();
        // Put some data
        let n = crate::crypto::nullifier::Nullifier([1u8; 32]);
        storage.put_nullifier(&n).unwrap();
        assert!(storage.has_nullifier(&n).unwrap());

        // Clear everything
        storage.clear_for_snapshot_import().unwrap();

        // Should be empty now
        assert!(!storage.has_nullifier(&n).unwrap());
        assert_eq!(storage.finalized_vertex_count().unwrap(), 0);
    }

    #[test]
    fn peer_ban_roundtrip() {
        let storage = SledStorage::open_temporary().unwrap();
        let peer_id = [42u8; 32];
        let banned_until = 1_700_000_000_000u64;

        // Initially empty
        assert!(storage.get_peer_bans().unwrap().is_empty());

        // Store a ban
        storage.put_peer_ban(&peer_id, banned_until).unwrap();
        let bans = storage.get_peer_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, peer_id);
        assert_eq!(bans[0].1, banned_until);

        // Store another
        let peer2 = [99u8; 32];
        storage.put_peer_ban(&peer2, banned_until + 1000).unwrap();
        assert_eq!(storage.get_peer_bans().unwrap().len(), 2);

        // Remove first
        storage.remove_peer_ban(&peer_id).unwrap();
        let bans = storage.get_peer_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, peer2);
    }

    #[test]
    fn peer_ban_overwrite() {
        let storage = SledStorage::open_temporary().unwrap();
        let peer_id = [42u8; 32];

        storage.put_peer_ban(&peer_id, 1000).unwrap();
        storage.put_peer_ban(&peer_id, 2000).unwrap();

        let bans = storage.get_peer_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].1, 2000);
    }
}
