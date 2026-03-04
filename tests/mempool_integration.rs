//! Mempool integration tests.
//!
//! Tests fee-priority ordering, eviction under capacity pressure,
//! nullifier conflict detection, duplicate rejection, and epoch expiry.

use umbra::constants;
use umbra::crypto::commitment::BlindingFactor;
use umbra::crypto::keys::FullKeypair;
use umbra::hash_domain;
use umbra::node::mempool::{Mempool, MempoolConfig, MempoolError};
use umbra::transaction::builder::{InputSpec, TransactionBuilder};
use umbra::transaction::Transaction;

// ── Helpers ──────────────────────────────────────────────────────────────

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

/// Build a test transaction with `num_inputs` inputs (fee scales with input count).
/// Each (seed, input_index) pair gives a unique nullifier.
/// Fee = compute_weight_fee(num_inputs, 0).
fn make_tx_with_inputs(seed: u8, num_inputs: usize) -> Transaction {
    let fee = constants::compute_weight_fee(num_inputs, 0);
    let recipient = FullKeypair::generate();
    let per_input = (fee / num_inputs as u64) + 100;

    let mut builder = TransactionBuilder::new();
    for i in 0..num_inputs {
        let input_seed = [seed, i as u8];
        builder = builder.add_input(InputSpec {
            value: per_input,
            blinding: BlindingFactor::from_bytes(hash_domain(b"umbra.blinding", &input_seed)),
            spend_auth: hash_domain(b"umbra.spend_auth", &input_seed),
            merkle_path: vec![],
        });
    }

    let total_input: u64 = per_input * num_inputs as u64;
    let output_value = total_input - fee;

    builder
        .add_output(recipient.kem.public.clone(), output_value)
        .set_proof_options(test_proof_options())
        .build()
        .unwrap()
}

/// Build a test tx with 1 input and deterministic fee (200).
fn make_tx(seed: u8) -> Transaction {
    make_tx_with_inputs(seed, 1)
}

/// Build a test tx with an expiry epoch set.
fn make_tx_with_expiry(seed: u8, expiry: u64) -> Transaction {
    let fee = constants::compute_weight_fee(1, 0);
    let recipient = FullKeypair::generate();
    let input_value = 1000u64;

    TransactionBuilder::new()
        .add_input(InputSpec {
            value: input_value,
            blinding: BlindingFactor::from_bytes([seed; 32]),
            spend_auth: hash_domain(b"umbra.spend_auth", &[seed]),
            merkle_path: vec![],
        })
        .add_output(recipient.kem.public.clone(), input_value - fee)
        .set_expiry_epoch(expiry)
        .set_proof_options(test_proof_options())
        .build()
        .unwrap()
}

// ── Group A: Fast tests ──────────────────────────────────────────────────

#[test]
fn test_fee_priority_ordering() {
    let mut pool = Mempool::with_defaults();

    // Txs with 1, 2, 3, 4, 5 inputs → increasing fees
    for i in 1..=5u8 {
        let tx = make_tx_with_inputs(i, i as usize);
        pool.insert(tx).unwrap();
    }

    assert_eq!(pool.len(), 5);

    let drained = pool.drain_highest_fee(5);
    assert_eq!(drained.len(), 5);

    let drained_fees: Vec<u64> = drained.iter().map(|tx| tx.fee).collect();
    for i in 1..drained_fees.len() {
        assert!(
            drained_fees[i - 1] >= drained_fees[i],
            "fees should be in descending order: {:?}",
            drained_fees
        );
    }
}

#[test]
fn test_eviction_lowest_fee() {
    let mut pool = Mempool::new(MempoolConfig {
        max_transactions: 3,
        max_bytes: 100_000_000,
    });

    // 1, 2, 3 inputs → fees 200, 300, 400
    let tx1 = make_tx_with_inputs(1, 1);
    let fee1 = tx1.fee;
    let tx2 = make_tx_with_inputs(2, 2);
    let tx3 = make_tx_with_inputs(3, 3);

    pool.insert(tx1).unwrap();
    pool.insert(tx2).unwrap();
    pool.insert(tx3).unwrap();
    assert_eq!(pool.len(), 3);

    // Insert tx with 4 inputs (higher fee) — should evict lowest-fee tx
    let tx4 = make_tx_with_inputs(4, 4);
    pool.insert(tx4).unwrap();
    assert_eq!(pool.len(), 3);

    let drained = pool.drain_highest_fee(3);
    let min_fee = drained.iter().map(|tx| tx.fee).min().unwrap();
    assert!(
        min_fee > fee1,
        "lowest-fee tx (fee={}) should have been evicted, min remaining={}",
        fee1,
        min_fee
    );
}

#[test]
fn test_nullifier_conflict_rejection() {
    let mut pool = Mempool::with_defaults();

    let tx1 = make_tx(1);
    let tx1_nullifiers: Vec<_> = tx1.inputs.iter().map(|i| i.nullifier).collect();

    pool.insert(tx1).unwrap();

    // Same seed = same nullifier
    let tx2 = make_tx(1);
    let tx2_nullifiers: Vec<_> = tx2.inputs.iter().map(|i| i.nullifier).collect();
    assert_eq!(tx1_nullifiers, tx2_nullifiers);

    let result = pool.insert(tx2);
    assert!(
        matches!(result, Err(MempoolError::NullifierConflict(_))),
        "expected NullifierConflict, got {:?}",
        result
    );
}

#[test]
fn test_duplicate_tx_rejection() {
    let mut pool = Mempool::with_defaults();

    let tx = make_tx(42);
    pool.insert(tx.clone()).unwrap();

    let result = pool.insert(tx);
    assert!(
        matches!(result, Err(MempoolError::Duplicate)),
        "expected Duplicate, got {:?}",
        result
    );
}

#[test]
fn test_epoch_expiry_eviction() {
    let mut pool = Mempool::with_defaults();

    let tx = make_tx_with_expiry(1, 5);
    assert_eq!(tx.expiry_epoch, 5);
    pool.insert(tx).unwrap();
    assert_eq!(pool.len(), 1);

    // Epoch 5: not yet expired (current_epoch must be > expiry_epoch)
    pool.set_epoch(5);
    let evicted = pool.evict_expired();
    assert_eq!(evicted, 0);
    assert_eq!(pool.len(), 1);

    // Epoch 6: now expired
    pool.set_epoch(6);
    let evicted = pool.evict_expired();
    assert!(evicted > 0, "expired tx should be evicted");
    assert_eq!(pool.len(), 0);
}

// ── Group B: Medium tests (1 STARK proof) ────────────────────────────────

#[test]
fn test_real_tx_insert_and_drain() {
    let mut pool = Mempool::with_defaults();

    let tx = make_tx(99);
    let tx_id = tx.tx_id();
    let original_fee = tx.fee;

    pool.insert(tx).unwrap();
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(&tx_id));

    let drained = pool.drain_highest_fee(1);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].tx_id(), tx_id);
    assert_eq!(drained[0].fee, original_fee);
    assert_eq!(pool.len(), 0);
}
