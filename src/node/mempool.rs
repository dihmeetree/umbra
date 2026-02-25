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
    #[error("mempool full: all transactions have maximum fee, no eviction possible")]
    MempoolFullMaxFee,
    #[error("nullifier already spent in finalized state")]
    NullifierAlreadySpent(Nullifier),
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

        // 4. Size-limit eviction: evict lowest-fee txs until there is space.
        // Cap evictions to prevent excessive churn from a single insert.
        let mut evictions = 0usize;
        while self.txs.len() >= self.config.max_transactions
            || self.total_bytes + size > self.config.max_bytes
        {
            if evictions >= crate::constants::MAX_MEMPOOL_EVICTIONS {
                return Err(MempoolError::MempoolFullMaxFee);
            }
            // Find the lowest-fee transaction (last entry in BTreeMap)
            if let Some((&lowest_key, _)) = self.fee_index.last_key_value() {
                let lowest_fee = lowest_key.fee();
                if fee <= lowest_fee {
                    if lowest_fee >= u64::MAX - 1 {
                        return Err(MempoolError::MempoolFullMaxFee);
                    }
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
                evictions += 1;
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

    /// Insert a transaction into the mempool with an additional state check.
    ///
    /// Before inserting, checks each nullifier against finalized state using the
    /// provided `is_spent` closure. This prevents re-accepting transactions whose
    /// nullifiers have already been finalized but whose mempool conflict entries
    /// may have been cleared.
    pub fn insert_with_state_check<F>(
        &mut self,
        tx: Transaction,
        is_spent: F,
    ) -> Result<TxId, MempoolError>
    where
        F: Fn(&Nullifier) -> bool,
    {
        for input in &tx.inputs {
            if is_spent(&input.nullifier) {
                return Err(MempoolError::NullifierAlreadySpent(input.nullifier));
            }
        }
        self.insert(tx)
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
            winterfell::FieldExtension::Cubic,
            8,
            255,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        )
    }

    /// Build a test Transfer transaction with 1 input and 1 output.
    /// Deterministic fee = FEE_BASE + 1*FEE_PER_INPUT = 200.
    fn make_test_tx(seed: u8) -> Transaction {
        let recipient = crate::crypto::keys::FullKeypair::generate();
        let output_value = 100u64;
        let fee = 200u64; // deterministic: 100 + 100
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

    /// Build a test Transfer transaction with `num_inputs` inputs and 1 output.
    /// This allows creating transactions with different deterministic fees:
    ///   fee = FEE_BASE + num_inputs * FEE_PER_INPUT = 100 + num_inputs * 100
    /// So: 1 input → 200, 2 inputs → 300, 3 inputs → 400, etc.
    fn make_test_tx_n_inputs(num_inputs: usize, seed: u8) -> Transaction {
        let output_value = 100u64;
        let fee = 100 + (num_inputs as u64) * 100;
        let input_value_each = (output_value + fee).div_ceil(num_inputs as u64);
        let total_input = input_value_each * num_inputs as u64;
        let actual_output = total_input - fee;
        let mut builder = TransactionBuilder::new();
        for i in 0..num_inputs {
            let s = seed.wrapping_add(i as u8);
            builder = builder.add_input(InputSpec {
                value: input_value_each,
                blinding: BlindingFactor::from_bytes([s; 32]),
                spend_auth: crate::hash_domain(b"test", &[s]),
                merkle_path: vec![],
            });
        }
        let recipient = crate::crypto::keys::FullKeypair::generate();
        builder = builder.add_output(recipient.kem.public.clone(), actual_output);
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

        // 1 input, 1 output → deterministic fee = 200
        let fee = 200u64;
        let output_value = 100u64;
        let input_value = output_value + fee; // 300

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

        // Different input counts → different deterministic fees:
        // 1 input → fee=200, 2 inputs → fee=300, 3 inputs → fee=400
        let tx_low = make_test_tx_n_inputs(1, 10); // fee=200
        let tx_mid = make_test_tx_n_inputs(2, 11); // fee=300
        let tx_high = make_test_tx_n_inputs(3, 12); // fee=400

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

        // Different input counts → different deterministic fees
        let tx1 = make_test_tx_n_inputs(1, 20); // fee=200
        let tx2 = make_test_tx_n_inputs(3, 21); // fee=400
        let tx3 = make_test_tx_n_inputs(2, 22); // fee=300

        pool.insert(tx1).unwrap();
        pool.insert(tx2).unwrap();
        pool.insert(tx3).unwrap();

        let drained = pool.drain_highest_fee(2);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].fee, 400); // highest first
        assert_eq!(drained[1].fee, 300);
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
        assert_eq!(stats.min_fee, Some(200)); // deterministic fee: 1 input
    }

    #[test]
    fn evict_expired_removes_old_transactions() {
        let mut pool = Mempool::with_defaults();

        // Build a tx with expiry_epoch = 5 through the builder
        // 1 input, 1 output → deterministic fee = 200
        let recipient = crate::crypto::keys::FullKeypair::generate();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 300,
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
            pool.insert(make_test_tx_n_inputs(*num_outputs, 70 + i as u8))
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
        // Build all three transactions first to measure sizes
        let tx_low = make_test_tx_n_inputs(1, 81); // fee=200
        let tx_mid = make_test_tx_n_inputs(2, 82); // fee=300
        let tx_high = make_test_tx_n_inputs(3, 83); // fee=400

        let _size_low = tx_low.estimated_size();
        let size_mid = tx_mid.estimated_size();
        let size_high = tx_high.estimated_size();

        // Set max_bytes so it can hold tx_mid + tx_high but NOT all three.
        // After inserting tx_low + tx_mid, adding tx_high should trigger eviction
        // of tx_low (lowest fee) to make room.
        let config = MempoolConfig {
            max_transactions: usize::MAX,
            max_bytes: size_mid + size_high + size_high / 4, // enough for 2 larger txs
        };
        let mut pool = Mempool::new(config);

        pool.insert(tx_low.clone()).unwrap();
        pool.insert(tx_mid.clone()).unwrap();
        assert_eq!(pool.len(), 2);
        let bytes_after_two = pool.total_bytes();
        assert!(bytes_after_two > 0);

        // Inserting a third tx with a higher fee should evict the lowest-fee tx
        pool.insert(tx_high.clone()).unwrap();
        assert_eq!(pool.len(), 2);
        // The lowest fee tx (fee=200) should have been evicted
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

        // Use different input counts for different fees:
        // 1 input → fee=200, 3 inputs → fee=400
        let tx_a = make_test_tx_n_inputs(1, 90); // fee=200
        let tx_b = make_test_tx_n_inputs(3, 91); // fee=400
        pool.insert(tx_a.clone()).unwrap();
        pool.insert(tx_b.clone()).unwrap();
        assert_eq!(pool.len(), 2);

        // The minimum fee in pool is 200. Inserting a tx with fee == 200 should
        // be rejected because the condition is `fee <= lowest_fee`.
        let tx_equal = make_test_tx_n_inputs(1, 92); // fee=200
        match pool.insert(tx_equal) {
            Err(MempoolError::FeeTooLow { fee, min_fee }) => {
                assert_eq!(fee, 200);
                assert_eq!(min_fee, 201); // lowest_fee + 1
            }
            other => panic!("expected FeeTooLow, got {:?}", other),
        }
        assert_eq!(pool.len(), 2);

        // Inserting a tx with fee=300 (next tier above lowest) should succeed and evict fee=200
        let tx_above = make_test_tx_n_inputs(2, 93); // fee=300
        pool.insert(tx_above.clone()).unwrap();
        assert_eq!(pool.len(), 2);
        assert!(!pool.contains(&tx_a.tx_id())); // fee=200 evicted
        assert!(pool.contains(&tx_b.tx_id())); // fee=400 stays
        assert!(pool.contains(&tx_above.tx_id())); // fee=300 accepted
    }

    #[test]
    fn drain_cleans_nullifier_index() {
        let mut pool = Mempool::with_defaults();

        // Build two transactions with the same nullifier (same value, blinding, spend_auth)
        // but different outputs (different recipients) so they have different tx_ids.
        // 1 input, 1 output → deterministic fee = 200
        let fee = 200u64;
        let output_value = 100u64;
        let value = output_value + fee; // 300
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
        // 1 input, 1 output → deterministic fee = 200
        let recipient = crate::crypto::keys::FullKeypair::generate();
        let tx_expired = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 300,
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
        // With a single transaction (fee=200), all percentiles should be the same value
        for &p in &percentiles {
            assert_eq!(p, 200);
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

    #[test]
    fn insert_at_exact_byte_limit() {
        // Create a single test tx and measure its size
        let tx1 = make_test_tx(140);
        let one_tx_size = tx1.estimated_size();

        // Set max_bytes to exactly one transaction's estimated_size
        let config = MempoolConfig {
            max_transactions: usize::MAX,
            max_bytes: one_tx_size,
        };
        let mut pool = Mempool::new(config);

        // Insert first tx — should succeed (exactly fits)
        assert!(pool.insert(tx1).is_ok());
        assert_eq!(pool.len(), 1);

        // Insert a second tx with higher fee — should evict the first due to byte limit
        let tx2 = make_test_tx_n_inputs(2, 141); // fee=300 > fee=200
        assert!(pool.insert(tx2.clone()).is_ok());
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&tx2.tx_id()));
    }

    #[test]
    fn multiple_transactions_identical_fees() {
        let mut pool = Mempool::with_defaults();

        // All 3 transactions have the same fee (1 input, 1 output → fee=200)
        let tx1 = make_test_tx(150);
        let tx2 = make_test_tx(151);
        let tx3 = make_test_tx(152);
        let id1 = tx1.tx_id();
        let id2 = tx2.tx_id();
        let id3 = tx3.tx_id();

        pool.insert(tx1).unwrap();
        pool.insert(tx2).unwrap();
        pool.insert(tx3).unwrap();
        assert_eq!(pool.len(), 3);

        // Drain all — with identical fees, insertion order (FIFO) should be the tie-breaker
        let drained = pool.drain_highest_fee(3);
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].tx_id(), id1);
        assert_eq!(drained[1].tx_id(), id2);
        assert_eq!(drained[2].tx_id(), id3);
    }

    #[test]
    fn nullifier_index_consistency_after_eviction() {
        // Use a small pool that holds at most 2 txs
        let config = MempoolConfig {
            max_transactions: 2,
            max_bytes: usize::MAX,
        };
        let mut pool = Mempool::new(config);

        // Insert two low-fee txs (both fee=200).
        // With equal fees, eviction takes the last BTreeMap entry (higher
        // insertion_order = later inserted = tx_low2), so capture its nullifiers.
        let tx_low1 = make_test_tx_n_inputs(1, 160);
        let tx_low2 = make_test_tx_n_inputs(1, 161);
        let nullifiers2: Vec<Nullifier> = tx_low2.inputs.iter().map(|i| i.nullifier).collect();

        pool.insert(tx_low1).unwrap();
        pool.insert(tx_low2).unwrap();
        assert_eq!(pool.len(), 2);

        // Insert a higher-fee tx, evicting the lowest-priority (tx_low2, later inserted)
        let tx_high = make_test_tx_n_inputs(2, 162); // fee=300
        pool.insert(tx_high).unwrap();
        assert_eq!(pool.len(), 2);

        // The evicted tx's nullifiers should no longer be in the index.
        // Verify by inserting a new tx with the same nullifier as the evicted one.
        // Build a tx that reuses tx_low2's nullifier (same input spec with seed=161).
        let recipient = crate::crypto::keys::FullKeypair::generate();
        let tx_reuse = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 300,
                blinding: BlindingFactor::from_bytes([161; 32]),
                spend_auth: crate::hash_domain(b"test", &[161]),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 100)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        // Confirm same nullifier as the evicted tx
        assert_eq!(tx_reuse.inputs[0].nullifier, nullifiers2[0]);

        // This insert must succeed — no stale nullifier entry should block it.
        // It may fail with FeeTooLow if the pool is full and its fee is too low,
        // so we check that it's not a NullifierConflict error.
        let result = pool.insert(tx_reuse);
        assert!(
            !matches!(result, Err(MempoolError::NullifierConflict(_))),
            "stale nullifier entry found after eviction: {:?}",
            result
        );
    }

    #[test]
    fn expiry_epoch_exact_boundary() {
        let mut pool = Mempool::with_defaults();

        // Build a tx with expiry_epoch=10
        // 1 input, 1 output → deterministic fee = 200
        let recipient = crate::crypto::keys::FullKeypair::generate();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 300,
                blinding: BlindingFactor::from_bytes([170; 32]),
                spend_auth: crate::hash_domain(b"test", &[170]),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 100)
            .set_expiry_epoch(10)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        pool.set_epoch(0);
        pool.insert(tx).unwrap();
        assert_eq!(pool.len(), 1);

        // set_epoch(10), evict_expired() — should NOT evict (10 < 10 is false)
        pool.set_epoch(10);
        assert_eq!(pool.evict_expired(), 0);
        assert_eq!(pool.len(), 1);

        // set_epoch(11), evict_expired() — should evict (10 < 11 is true)
        pool.set_epoch(11);
        assert_eq!(pool.evict_expired(), 1);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn zero_fee_transaction() {
        let mut pool = Mempool::with_defaults();

        // Build a valid tx and then mutate its fee to 0.
        // validate_structure enforces MIN_TX_FEE, so this should be rejected.
        let mut tx = make_test_tx(180);
        tx.fee = 0;

        match pool.insert(tx) {
            Err(MempoolError::ValidationFailed(_)) => {}
            other => panic!("expected ValidationFailed for zero-fee tx, got {:?}", other),
        }
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn drain_cleans_all_indices() {
        let mut pool = Mempool::with_defaults();

        // Insert 5 transactions
        for seed in 190..195 {
            pool.insert(make_test_tx(seed)).unwrap();
        }
        assert_eq!(pool.len(), 5);
        assert!(pool.total_bytes() > 0);
        assert!(!pool.is_empty());

        // Drain all
        let drained = pool.drain_highest_fee(100);
        assert_eq!(drained.len(), 5);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.total_bytes(), 0);
        assert!(pool.is_empty());
    }

    #[test]
    fn fee_percentiles_two_transactions() {
        let mut pool = Mempool::with_defaults();

        // Insert 2 transactions with different fees:
        // 1 input → fee=200, 2 inputs → fee=300
        pool.insert(make_test_tx_n_inputs(1, 200)).unwrap();
        pool.insert(make_test_tx_n_inputs(2, 201)).unwrap();

        let percentiles = pool.fee_percentiles().unwrap();
        assert_eq!(percentiles.len(), 5);
        // With 2 txs (fees 200 and 300 in ascending order):
        // All percentiles should be within [200, 300]
        for &p in &percentiles {
            assert!((200..=300).contains(&p), "percentile {} out of range", p);
        }
    }

    #[test]
    fn remove_conflicting_multiple_nullifiers() {
        let mut pool = Mempool::with_defaults();

        // Build a transaction with 2 inputs (2 nullifiers).
        // 2 inputs, 1 output → fee = FEE_BASE + 2*FEE_PER_INPUT = 300
        let recipient = crate::crypto::keys::FullKeypair::generate();
        let fee = 300u64; // 100 + 200
        let output_value = 100u64;

        let tx_multi = TransactionBuilder::new()
            .add_input(InputSpec {
                value: output_value + fee / 2, // first input
                blinding: BlindingFactor::from_bytes([210; 32]),
                spend_auth: crate::hash_domain(b"test", &[210]),
                merkle_path: vec![],
            })
            .add_input(InputSpec {
                value: fee / 2, // second input
                blinding: BlindingFactor::from_bytes([211; 32]),
                spend_auth: crate::hash_domain(b"test", &[211]),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), output_value)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        assert_eq!(tx_multi.inputs.len(), 2);
        let nullifier0 = tx_multi.inputs[0].nullifier;
        let nullifier1 = tx_multi.inputs[1].nullifier;
        assert_ne!(nullifier0, nullifier1);

        pool.insert(tx_multi).unwrap();
        assert_eq!(pool.len(), 1);

        // Call remove_conflicting with only ONE of the two nullifiers
        let removed = pool.remove_conflicting(&[nullifier1]);
        assert_eq!(removed.len(), 1);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn get_returns_transaction() {
        let mut pool = Mempool::with_defaults();
        let tx = make_test_tx(250);
        let tx_id = tx.tx_id();
        let expected_fee = tx.fee;
        pool.insert(tx).unwrap();

        let retrieved = pool.get(&tx_id).unwrap();
        assert_eq!(retrieved.fee, expected_fee);
        assert_eq!(retrieved.tx_id(), tx_id);
    }

    #[test]
    fn get_returns_none_for_missing() {
        let pool = Mempool::with_defaults();
        let fake_id = crate::transaction::TxId([0xFFu8; 32]);
        assert!(pool.get(&fake_id).is_none());
    }

    #[test]
    fn drain_zero_returns_empty() {
        let mut pool = Mempool::with_defaults();
        pool.insert(make_test_tx(251)).unwrap();
        let drained = pool.drain_highest_fee(0);
        assert!(drained.is_empty());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn drain_more_than_pool_size() {
        let mut pool = Mempool::with_defaults();
        pool.insert(make_test_tx(252)).unwrap();
        pool.insert(make_test_tx(253)).unwrap();
        let drained = pool.drain_highest_fee(100);
        assert_eq!(drained.len(), 2);
        assert!(pool.is_empty());
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut pool = Mempool::with_defaults();
        let fake_id = crate::transaction::TxId([0xAAu8; 32]);
        assert!(pool.remove(&fake_id).is_none());
    }

    #[test]
    fn remove_conflicting_empty_nullifiers() {
        let mut pool = Mempool::with_defaults();
        pool.insert(make_test_tx(254)).unwrap();
        let removed = pool.remove_conflicting(&[]);
        assert!(removed.is_empty());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn set_epoch_to_zero() {
        let mut pool = Mempool::with_defaults();
        pool.set_epoch(100);
        pool.set_epoch(0);
        // Should accept a no-expiry tx at epoch 0
        let tx = make_test_tx(255);
        assert!(pool.insert(tx).is_ok());
    }

    #[test]
    fn multiple_evictions_in_single_insert() {
        // Create a pool that can hold 3 txs by count
        let sample = make_test_tx(1);
        let one_tx_size = sample.estimated_size();
        let config = MempoolConfig {
            max_transactions: usize::MAX,
            max_bytes: one_tx_size * 2 + one_tx_size / 4, // Can hold ~2.25 txs
        };
        let mut pool = Mempool::new(config);

        // Insert 2 low-fee txs (1 input each, fee=200)
        let tx1 = make_test_tx(10);
        let tx2 = make_test_tx(11);
        pool.insert(tx1).unwrap();
        pool.insert(tx2).unwrap();
        assert_eq!(pool.len(), 2);

        // Insert a higher-fee tx that needs at least one eviction
        let tx3 = make_test_tx_n_inputs(2, 12); // fee=300, larger size
        let result = pool.insert(tx3);
        // Should succeed by evicting one of the low-fee txs
        assert!(result.is_ok());
    }

    #[test]
    fn fee_percentiles_empty_returns_none() {
        let pool = Mempool::with_defaults();
        assert!(pool.fee_percentiles().is_none());
    }

    #[test]
    fn stats_after_insert_and_remove() {
        let mut pool = Mempool::with_defaults();
        let tx = make_test_tx(220);
        let tx_id = tx.tx_id();
        let tx_size = tx.estimated_size();

        pool.insert(tx).unwrap();
        let stats = pool.stats();
        assert_eq!(stats.transaction_count, 1);
        assert_eq!(stats.total_bytes, tx_size);

        pool.remove(&tx_id);
        let stats = pool.stats();
        assert_eq!(stats.transaction_count, 0);
        assert_eq!(stats.total_bytes, 0);
    }

    #[test]
    fn contains_after_remove() {
        let mut pool = Mempool::with_defaults();
        let tx = make_test_tx(221);
        let tx_id = tx.tx_id();
        pool.insert(tx).unwrap();
        assert!(pool.contains(&tx_id));
        pool.remove(&tx_id);
        assert!(!pool.contains(&tx_id));
    }
}
