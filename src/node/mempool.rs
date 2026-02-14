//! Transaction mempool with fee-priority ordering and nullifier conflict detection.
//!
//! The mempool holds unconfirmed transactions waiting to be included in DAG vertices.
//! Transactions are ordered by fee (highest first) for vertex proposers to drain.
//! Nullifier conflicts are detected to prevent including conflicting transactions.

use std::collections::{BTreeMap, HashMap};

use crate::crypto::nullifier::Nullifier;
use crate::transaction::{Transaction, TxId};

/// Errors from mempool operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("transaction already in mempool")]
    Duplicate,
    #[error("nullifier conflict with existing mempool transaction")]
    NullifierConflict(Nullifier),
    #[error("transaction validation failed: {0}")]
    ValidationFailed(#[from] crate::transaction::TxValidationError),
    #[error("transaction fee {fee} below mempool minimum {min_fee}")]
    FeeTooLow { fee: u64, min_fee: u64 },
}

/// A transaction entry in the mempool with metadata.
#[derive(Clone, Debug)]
struct MempoolEntry {
    tx: Transaction,
    fee: u64,
    size: usize,
    insertion_order: u64,
}

/// Configuration for the mempool.
#[derive(Clone, Debug)]
pub struct MempoolConfig {
    pub max_transactions: usize,
    pub max_bytes: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        MempoolConfig {
            max_transactions: crate::constants::MEMPOOL_MAX_TXS,
            max_bytes: crate::constants::MEMPOOL_MAX_BYTES,
        }
    }
}

/// Fee-based ordering key for the BTreeMap priority index.
///
/// Uses negated fee so BTreeMap's ascending order gives lowest-priority first
/// (for easy eviction). Iterating from the start gives highest-fee transactions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FeeKey {
    /// u64::MAX - fee, so higher fee = lower key = earlier in BTreeMap
    neg_fee: u64,
    /// Tie-break: earlier insertion = higher priority = lower key
    insertion_order: u64,
}

impl FeeKey {
    fn new(fee: u64, insertion_order: u64) -> Self {
        FeeKey {
            neg_fee: u64::MAX - fee,
            insertion_order,
        }
    }

    fn fee(&self) -> u64 {
        u64::MAX - self.neg_fee
    }
}

/// Summary statistics for RPC reporting.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MempoolStats {
    pub transaction_count: usize,
    pub total_bytes: usize,
    pub max_transactions: usize,
    pub max_bytes: usize,
    pub min_fee: Option<u64>,
}

/// Transaction mempool with fee-priority ordering and nullifier conflict detection.
pub struct Mempool {
    config: MempoolConfig,
    /// All transactions by TxId.
    txs: HashMap<TxId, MempoolEntry>,
    /// Fee-priority index: lowest key = highest fee.
    fee_index: BTreeMap<FeeKey, TxId>,
    /// Nullifier -> TxId that contains it (for conflict detection).
    nullifier_index: HashMap<Nullifier, TxId>,
    /// Total estimated byte size of all transactions.
    total_bytes: usize,
    /// Monotonic counter for insertion ordering.
    insertion_counter: u64,
    /// Current epoch (for validate_structure).
    current_epoch: u64,
}

impl Mempool {
    /// Create a new mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        Mempool {
            config,
            txs: HashMap::new(),
            fee_index: BTreeMap::new(),
            nullifier_index: HashMap::new(),
            total_bytes: 0,
            insertion_counter: 0,
            current_epoch: 0,
        }
    }

    /// Create a mempool with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(MempoolConfig::default())
    }

    /// Set the current epoch (used for tx.validate_structure).
    pub fn set_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
    }

    /// Insert a transaction into the mempool.
    ///
    /// Performs duplicate check, structural validation, nullifier conflict
    /// detection, and size-limit eviction.
    pub fn insert(&mut self, tx: Transaction) -> Result<TxId, MempoolError> {
        let tx_id = tx.tx_id();

        // 1. Duplicate check
        if self.txs.contains_key(&tx_id) {
            return Err(MempoolError::Duplicate);
        }

        // 2. Structural validation
        tx.validate_structure(self.current_epoch)?;

        // 3. Nullifier conflict detection
        for input in &tx.inputs {
            if let Some(&_conflicting_id) = self.nullifier_index.get(&input.nullifier) {
                return Err(MempoolError::NullifierConflict(input.nullifier));
            }
        }

        let fee = tx.fee;
        let size = tx.estimated_size();

        // 4. Size-limit eviction: evict lowest-fee txs until there is space
        while self.txs.len() >= self.config.max_transactions
            || self.total_bytes + size > self.config.max_bytes
        {
            // Find the lowest-fee transaction (last entry in BTreeMap)
            if let Some((&lowest_key, _)) = self.fee_index.last_key_value() {
                let lowest_fee = lowest_key.fee();
                if fee <= lowest_fee {
                    return Err(MempoolError::FeeTooLow {
                        fee,
                        min_fee: lowest_fee.saturating_add(1),
                    });
                }
                // Evict the lowest-fee tx
                let Some(&lowest_id) = self.fee_index.get(&lowest_key) else {
                    break;
                };
                self.remove_entry(&lowest_id);
            } else {
                break;
            }
        }

        // 5. Insert
        let insertion_order = self.insertion_counter;
        self.insertion_counter += 1;
        let key = FeeKey::new(fee, insertion_order);

        for input in &tx.inputs {
            self.nullifier_index.insert(input.nullifier, tx_id);
        }
        self.fee_index.insert(key, tx_id);
        self.total_bytes += size;
        self.txs.insert(
            tx_id,
            MempoolEntry {
                tx,
                fee,
                size,
                insertion_order,
            },
        );

        Ok(tx_id)
    }

    /// Remove a transaction by TxId.
    pub fn remove(&mut self, tx_id: &TxId) -> Option<Transaction> {
        self.remove_entry(tx_id).map(|e| e.tx)
    }

    /// Remove all transactions whose nullifiers conflict with the given set.
    /// Called after a vertex is finalized to purge conflicting txs.
    pub fn remove_conflicting(&mut self, nullifiers: &[Nullifier]) -> Vec<Transaction> {
        let mut removed = Vec::new();
        let tx_ids: Vec<TxId> = nullifiers
            .iter()
            .filter_map(|n| self.nullifier_index.get(n).copied())
            .collect();

        for tx_id in tx_ids {
            if let Some(entry) = self.remove_entry(&tx_id) {
                removed.push(entry.tx);
            }
        }
        removed
    }

    /// Drain up to `max_count` highest-fee transactions for vertex proposal.
    /// Removes them from the pool and returns them ordered by fee (highest first).
    pub fn drain_highest_fee(&mut self, max_count: usize) -> Vec<Transaction> {
        let mut result = Vec::with_capacity(max_count);
        let keys_to_remove: Vec<FeeKey> = self.fee_index.keys().take(max_count).copied().collect();

        for key in keys_to_remove {
            if let Some(tx_id) = self.fee_index.remove(&key) {
                if let Some(entry) = self.txs.remove(&tx_id) {
                    for input in &entry.tx.inputs {
                        self.nullifier_index.remove(&input.nullifier);
                    }
                    self.total_bytes = self.total_bytes.saturating_sub(entry.size);
                    result.push(entry.tx);
                }
            }
        }
        result
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, tx_id: &TxId) -> bool {
        self.txs.contains_key(tx_id)
    }

    /// Get a transaction by TxId without removing it.
    pub fn get(&self, tx_id: &TxId) -> Option<&Transaction> {
        self.txs.get(tx_id).map(|e| &e.tx)
    }

    /// Current number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Total estimated byte size of all pooled transactions.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Get the minimum fee in the pool (fee of the lowest-priority tx).
    pub fn min_fee(&self) -> Option<u64> {
        self.fee_index.last_key_value().map(|(k, _)| k.fee())
    }

    /// Remove all transactions whose `expiry_epoch` has passed.
    ///
    /// A transaction is considered expired when `tx.expiry_epoch > 0` (has an
    /// expiry) and `tx.expiry_epoch < self.current_epoch`. Returns the number
    /// of transactions evicted.
    pub fn evict_expired(&mut self) -> usize {
        let expired_ids: Vec<TxId> = self
            .txs
            .iter()
            .filter(|(_, entry)| {
                entry.tx.expiry_epoch > 0 && entry.tx.expiry_epoch < self.current_epoch
            })
            .map(|(id, _)| *id)
            .collect();

        let count = expired_ids.len();
        for id in expired_ids {
            self.remove_entry(&id);
        }
        count
    }

    /// Compute fee percentiles [p10, p25, p50, p75, p90] from the fee index.
    /// Returns `None` if the mempool is empty.
    pub fn fee_percentiles(&self) -> Option<[u64; 5]> {
        if self.txs.is_empty() {
            return None;
        }
        // Collect all fees in ascending order (BTreeMap uses neg_fee key, so reverse)
        let mut fees: Vec<u64> = self.fee_index.keys().map(|k| k.fee()).collect();
        fees.reverse();
        let n = fees.len();
        let percentile = |p: usize| -> u64 {
            let idx = (p * n / 100).min(n - 1);
            fees[idx]
        };
        Some([
            percentile(10),
            percentile(25),
            percentile(50),
            percentile(75),
            percentile(90),
        ])
    }

    /// Stats for RPC reporting.
    pub fn stats(&self) -> MempoolStats {
        MempoolStats {
            transaction_count: self.txs.len(),
            total_bytes: self.total_bytes,
            max_transactions: self.config.max_transactions,
            max_bytes: self.config.max_bytes,
            min_fee: self.min_fee(),
        }
    }

    /// Remove an entry by TxId, cleaning up all indices.
    fn remove_entry(&mut self, tx_id: &TxId) -> Option<MempoolEntry> {
        let entry = self.txs.remove(tx_id)?;
        let key = FeeKey::new(entry.fee, entry.insertion_order);
        self.fee_index.remove(&key);
        for input in &entry.tx.inputs {
            self.nullifier_index.remove(&input.nullifier);
        }
        self.total_bytes = self.total_bytes.saturating_sub(entry.size);
        Some(entry)
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::commitment::BlindingFactor;
    use crate::transaction::builder::{InputSpec, TransactionBuilder};

    fn test_proof_options() -> winterfell::ProofOptions {
        winterfell::ProofOptions::new(
            42,
            8,
            10,
            winterfell::FieldExtension::Quadratic,
            8,
            255,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        )
    }

    /// Build a test Transfer transaction with 1 input and 1 output.
    /// Deterministic fee = FEE_BASE + 1*FEE_PER_INPUT + 1*FEE_PER_OUTPUT = 300.
    fn make_test_tx(seed: u8) -> Transaction {
        let recipient = crate::crypto::keys::FullKeypair::generate();
        let output_value = 100u64;
        let fee = 300u64; // deterministic: 100 + 100 + 100
        let input_value = output_value + fee;
        TransactionBuilder::new()
            .add_input(InputSpec {
                value: input_value,
                blinding: BlindingFactor::from_bytes([seed; 32]),
                spend_auth: crate::hash_domain(b"test", &[seed]),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), output_value)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap()
    }

    /// Build a test Transfer transaction with 1 input and `num_outputs` outputs.
    /// This allows creating transactions with different deterministic fees:
    ///   fee = FEE_BASE + FEE_PER_INPUT + num_outputs * FEE_PER_OUTPUT
    ///       = 100 + 100 + num_outputs * 100 = 200 + num_outputs * 100
    /// So: 1 output → 300, 2 outputs → 400, 3 outputs → 500, etc.
    fn make_test_tx_n_outputs(num_outputs: usize, seed: u8) -> Transaction {
        let output_value_each = 100u64;
        let fee = 200 + (num_outputs as u64) * 100;
        let input_value = output_value_each * num_outputs as u64 + fee;
        let mut builder = TransactionBuilder::new().add_input(InputSpec {
            value: input_value,
            blinding: BlindingFactor::from_bytes([seed; 32]),
            spend_auth: crate::hash_domain(b"test", &[seed]),
            merkle_path: vec![],
        });
        for _ in 0..num_outputs {
            let recipient = crate::crypto::keys::FullKeypair::generate();
            builder = builder.add_output(recipient.kem.public.clone(), output_value_each);
        }
        builder
            .set_proof_options(test_proof_options())
            .build()
            .unwrap()
    }

    #[test]
    fn insert_and_retrieve() {
        let mut pool = Mempool::with_defaults();
        let tx = make_test_tx(1);
        let tx_id = tx.tx_id();

        let result = pool.insert(tx);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), tx_id);
        assert!(pool.contains(&tx_id));
        assert_eq!(pool.len(), 1);
        assert!(pool.get(&tx_id).is_some());
    }

    #[test]
    fn reject_duplicate() {
        let mut pool = Mempool::with_defaults();
        let tx = make_test_tx(2);

        assert!(pool.insert(tx.clone()).is_ok());
        match pool.insert(tx) {
            Err(MempoolError::Duplicate) => {}
            other => panic!("expected Duplicate, got {:?}", other),
        }
    }

    #[test]
    fn reject_nullifier_conflict() {
        let mut pool = Mempool::with_defaults();
        // Two transactions with the exact same input (same value, blinding, spend_auth
        // produces the same nullifier) but different outputs (different recipients)
        let recipient1 = crate::crypto::keys::FullKeypair::generate();
        let recipient2 = crate::crypto::keys::FullKeypair::generate();

        // 1 input, 1 output → deterministic fee = 300
        let fee = 300u64;
        let output_value = 100u64;
        let input_value = output_value + fee; // 400

        let tx1 = TransactionBuilder::new()
            .add_input(InputSpec {
                value: input_value,
                blinding: BlindingFactor::from_bytes([3; 32]),
                spend_auth: crate::hash_domain(b"test", &[3]),
                merkle_path: vec![],
            })
            .add_output(recipient1.kem.public.clone(), output_value)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        let tx2 = TransactionBuilder::new()
            .add_input(InputSpec {
                value: input_value,
                blinding: BlindingFactor::from_bytes([3; 32]),
                spend_auth: crate::hash_domain(b"test", &[3]),
                merkle_path: vec![],
            })
            .add_output(recipient2.kem.public.clone(), output_value)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        // Same nullifier in both since same (value, blinding, spend_auth)
        assert_eq!(tx1.inputs[0].nullifier, tx2.inputs[0].nullifier);

        assert!(pool.insert(tx1).is_ok());
        match pool.insert(tx2) {
            Err(MempoolError::NullifierConflict(_)) => {}
            other => panic!("expected NullifierConflict, got {:?}", other),
        }
    }

    #[test]
    fn evict_lowest_fee_when_full() {
        let config = MempoolConfig {
            max_transactions: 2,
            max_bytes: usize::MAX,
        };
        let mut pool = Mempool::new(config);

        // Different output counts → different deterministic fees:
        // 1 output → fee=300, 2 outputs → fee=400, 3 outputs → fee=500
        let tx_low = make_test_tx_n_outputs(1, 10); // fee=300
        let tx_mid = make_test_tx_n_outputs(2, 11); // fee=400
        let tx_high = make_test_tx_n_outputs(3, 12); // fee=500

        assert!(pool.insert(tx_low).is_ok());
        assert!(pool.insert(tx_mid.clone()).is_ok());
        assert_eq!(pool.len(), 2);

        // Insert higher-fee tx should evict the lowest
        assert!(pool.insert(tx_high).is_ok());
        assert_eq!(pool.len(), 2);

        // The mid and high fee txs should remain
        assert!(pool.contains(&tx_mid.tx_id()));
    }

    #[test]
    fn drain_highest_fee_ordering() {
        let mut pool = Mempool::with_defaults();

        // Different output counts → different deterministic fees
        let tx1 = make_test_tx_n_outputs(1, 20); // fee=300
        let tx2 = make_test_tx_n_outputs(3, 21); // fee=500
        let tx3 = make_test_tx_n_outputs(2, 22); // fee=400

        pool.insert(tx1).unwrap();
        pool.insert(tx2).unwrap();
        pool.insert(tx3).unwrap();

        let drained = pool.drain_highest_fee(2);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].fee, 500); // highest first
        assert_eq!(drained[1].fee, 400);
        assert_eq!(pool.len(), 1); // one left
    }

    #[test]
    fn remove_by_txid() {
        let mut pool = Mempool::with_defaults();
        let tx = make_test_tx(30);
        let tx_id = tx.tx_id();

        pool.insert(tx).unwrap();
        assert_eq!(pool.len(), 1);

        let removed = pool.remove(&tx_id);
        assert!(removed.is_some());
        assert_eq!(pool.len(), 0);
        assert!(!pool.contains(&tx_id));
    }

    #[test]
    fn remove_conflicting_nullifiers() {
        let mut pool = Mempool::with_defaults();
        let tx = make_test_tx(40);
        let nullifiers: Vec<Nullifier> = tx.inputs.iter().map(|i| i.nullifier).collect();

        pool.insert(tx).unwrap();
        assert_eq!(pool.len(), 1);

        let removed = pool.remove_conflicting(&nullifiers);
        assert_eq!(removed.len(), 1);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn stats_reporting() {
        let mut pool = Mempool::with_defaults();
        let stats = pool.stats();
        assert_eq!(stats.transaction_count, 0);
        assert_eq!(stats.total_bytes, 0);

        pool.insert(make_test_tx(50)).unwrap();
        let stats = pool.stats();
        assert_eq!(stats.transaction_count, 1);
        assert!(stats.total_bytes > 0);
        assert_eq!(stats.min_fee, Some(300)); // deterministic fee: 1 input, 1 output
    }

    #[test]
    fn evict_expired_removes_old_transactions() {
        let mut pool = Mempool::with_defaults();

        // Build a tx with expiry_epoch = 5 through the builder
        // 1 input, 1 output → deterministic fee = 300
        let recipient = crate::crypto::keys::FullKeypair::generate();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 400,
                blinding: BlindingFactor::from_bytes([60; 32]),
                spend_auth: crate::hash_domain(b"test", &[60]),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 100)
            .set_expiry_epoch(5)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        pool.set_epoch(0);
        pool.insert(tx).unwrap();
        assert_eq!(pool.len(), 1);

        // expiry_epoch=5 means tx is valid through epoch 5; expired at epoch 6
        pool.set_epoch(5);
        assert_eq!(pool.evict_expired(), 0); // 5 < 5 is false

        pool.set_epoch(6);
        assert_eq!(pool.evict_expired(), 1);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn evict_expired_keeps_no_expiry() {
        let mut pool = Mempool::with_defaults();
        let tx = make_test_tx(61); // expiry_epoch = 0 (no expiry)
        pool.insert(tx).unwrap();
        pool.set_epoch(1000);
        assert_eq!(pool.evict_expired(), 0);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn empty_pool_operations() {
        let pool = Mempool::with_defaults();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.min_fee(), None);
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn fee_percentiles_empty_pool() {
        let pool = Mempool::with_defaults();
        assert!(pool.fee_percentiles().is_none());
    }

    #[test]
    fn fee_percentiles_with_transactions() {
        let mut pool = Mempool::with_defaults();
        // Insert transactions with different deterministic fees via different output counts:
        // 1 output → 300, 2 outputs → 400, 3 outputs → 500, 4 outputs → 600, 5 outputs → 700
        for (i, num_outputs) in [1, 2, 3, 4, 5].iter().enumerate() {
            pool.insert(make_test_tx_n_outputs(*num_outputs, 70 + i as u8))
                .unwrap();
        }

        let percentiles = pool.fee_percentiles().unwrap();
        // p10, p25, p50, p75, p90
        assert_eq!(percentiles.len(), 5);
        // Values should be in ascending order
        for i in 0..4 {
            assert!(percentiles[i] <= percentiles[i + 1]);
        }
    }

    #[test]
    fn byte_limit_eviction() {
        // Insert a single tx to measure its size (use largest variant for sizing)
        let sample_tx = make_test_tx_n_outputs(3, 80);
        let one_tx_size = sample_tx.estimated_size();

        // Set max_bytes to hold at most 2 transactions of the largest size
        let config = MempoolConfig {
            max_transactions: usize::MAX,
            max_bytes: one_tx_size * 2 + one_tx_size / 2, // ~2.5x one tx
        };
        let mut pool = Mempool::new(config);

        // Different output counts → different deterministic fees for eviction ordering
        let tx_low = make_test_tx_n_outputs(1, 81); // fee=300
        let tx_mid = make_test_tx_n_outputs(2, 82); // fee=400
        pool.insert(tx_low.clone()).unwrap();
        pool.insert(tx_mid.clone()).unwrap();
        assert_eq!(pool.len(), 2);
        let bytes_after_two = pool.total_bytes();
        assert!(bytes_after_two > 0);

        // Inserting a third tx with a higher fee should evict the lowest-fee tx
        let tx_high = make_test_tx_n_outputs(3, 83); // fee=500
        pool.insert(tx_high.clone()).unwrap();
        assert_eq!(pool.len(), 2);
        // The lowest fee tx (fee=300) should have been evicted
        assert!(!pool.contains(&tx_low.tx_id()));
        assert!(pool.contains(&tx_mid.tx_id()));
        assert!(pool.contains(&tx_high.tx_id()));
        // total_bytes should stay within max_bytes
        assert!(pool.total_bytes() <= pool.config.max_bytes);
    }

    #[test]
    fn fee_too_low_boundary() {
        let config = MempoolConfig {
            max_transactions: 2,
            max_bytes: usize::MAX,
        };
        let mut pool = Mempool::new(config);

        // Use different output counts for different fees:
        // 1 output → fee=300, 3 outputs → fee=500
        let tx_a = make_test_tx_n_outputs(1, 90); // fee=300
        let tx_b = make_test_tx_n_outputs(3, 91); // fee=500
        pool.insert(tx_a.clone()).unwrap();
        pool.insert(tx_b.clone()).unwrap();
        assert_eq!(pool.len(), 2);

        // The minimum fee in pool is 300. Inserting a tx with fee == 300 should
        // be rejected because the condition is `fee <= lowest_fee`.
        let tx_equal = make_test_tx_n_outputs(1, 92); // fee=300
        match pool.insert(tx_equal) {
            Err(MempoolError::FeeTooLow { fee, min_fee }) => {
                assert_eq!(fee, 300);
                assert_eq!(min_fee, 301); // lowest_fee + 1
            }
            other => panic!("expected FeeTooLow, got {:?}", other),
        }
        assert_eq!(pool.len(), 2);

        // Inserting a tx with fee=400 (next tier above lowest) should succeed and evict fee=300
        let tx_above = make_test_tx_n_outputs(2, 93); // fee=400
        pool.insert(tx_above.clone()).unwrap();
        assert_eq!(pool.len(), 2);
        assert!(!pool.contains(&tx_a.tx_id())); // fee=300 evicted
        assert!(pool.contains(&tx_b.tx_id())); // fee=500 stays
        assert!(pool.contains(&tx_above.tx_id())); // fee=400 accepted
    }

    #[test]
    fn drain_cleans_nullifier_index() {
        let mut pool = Mempool::with_defaults();

        // Build two transactions with the same nullifier (same value, blinding, spend_auth)
        // but different outputs (different recipients) so they have different tx_ids.
        // 1 input, 1 output → deterministic fee = 300
        let fee = 300u64;
        let output_value = 100u64;
        let value = output_value + fee; // 400
        let blinding = BlindingFactor::from_bytes([100; 32]);
        let spend_auth = crate::hash_domain(b"test", &[100]);

        let recipient1 = crate::crypto::keys::FullKeypair::generate();
        let tx1 = TransactionBuilder::new()
            .add_input(InputSpec {
                value,
                blinding: blinding.clone(),
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(recipient1.kem.public.clone(), output_value)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        let recipient2 = crate::crypto::keys::FullKeypair::generate();
        let tx2 = TransactionBuilder::new()
            .add_input(InputSpec {
                value,
                blinding: blinding.clone(),
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(recipient2.kem.public.clone(), output_value)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        // Confirm same nullifier, different tx_ids
        let nullifier = tx1.inputs[0].nullifier;
        assert_eq!(tx2.inputs[0].nullifier, nullifier);
        assert_ne!(tx1.tx_id(), tx2.tx_id());

        // Insert tx1, then drain
        pool.insert(tx1).unwrap();
        assert_eq!(pool.len(), 1);
        let drained = pool.drain_highest_fee(100);
        assert_eq!(drained.len(), 1);
        assert_eq!(pool.len(), 0);

        // tx2 has the same nullifier; it should be accepted since drain cleaned nullifier index
        assert!(pool.insert(tx2).is_ok());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn epoch_reject_expired_on_insert() {
        let mut pool = Mempool::with_defaults();
        pool.set_epoch(10);

        // Build a tx with expiry_epoch=5: it's already expired at epoch 10
        // 1 input, 1 output → deterministic fee = 300
        let recipient = crate::crypto::keys::FullKeypair::generate();
        let tx_expired = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 400,
                blinding: BlindingFactor::from_bytes([110; 32]),
                spend_auth: crate::hash_domain(b"test", &[110]),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 100)
            .set_expiry_epoch(5)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        // validate_structure(10) should reject: 10 > 5 → Expired
        match pool.insert(tx_expired) {
            Err(MempoolError::ValidationFailed(ref e)) => {
                // Should be a TxValidationError::Expired wrapped in ValidationFailed
                let msg = e.to_string();
                assert!(
                    msg.contains("expired") || msg.contains("Expired"),
                    "unexpected error: {}",
                    msg
                );
            }
            other => panic!("expected ValidationFailed(Expired), got {:?}", other),
        }

        // Build a tx with expiry_epoch=0 (no expiry) — should be accepted
        let tx_no_expiry = make_test_tx(111);
        assert_eq!(tx_no_expiry.expiry_epoch, 0);
        assert!(pool.insert(tx_no_expiry).is_ok());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn fee_percentiles_single_tx() {
        let mut pool = Mempool::with_defaults();
        pool.insert(make_test_tx(120)).unwrap();

        let percentiles = pool.fee_percentiles().unwrap();
        // With a single transaction (fee=300), all percentiles should be the same value
        for &p in &percentiles {
            assert_eq!(p, 300);
        }
    }

    #[test]
    fn total_bytes_accurate_after_operations() {
        let mut pool = Mempool::with_defaults();

        let tx1 = make_test_tx(130);
        let tx2 = make_test_tx(131);
        let tx3 = make_test_tx(132);
        let tx1_size = tx1.estimated_size();
        let tx2_size = tx2.estimated_size();
        let tx3_size = tx3.estimated_size();
        let tx2_id = tx2.tx_id();

        pool.insert(tx1).unwrap();
        pool.insert(tx2).unwrap();
        pool.insert(tx3).unwrap();

        let bytes_after_three = pool.total_bytes();
        assert_eq!(bytes_after_three, tx1_size + tx2_size + tx3_size);

        // Remove tx2 by txid
        pool.remove(&tx2_id);
        assert_eq!(pool.total_bytes(), bytes_after_three - tx2_size);

        // Insert another
        let tx4 = make_test_tx(133);
        let tx4_size = tx4.estimated_size();
        pool.insert(tx4).unwrap();
        assert_eq!(pool.total_bytes(), bytes_after_three - tx2_size + tx4_size);

        // Drain all
        pool.drain_highest_fee(100);
        assert_eq!(pool.total_bytes(), 0);
    }
}
