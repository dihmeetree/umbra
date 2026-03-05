//! Benchmarks for transaction building, serialization, and deserialization.
//!
//! Includes parallel spend proof generation via `TransactionBuilder::build()`
//! and serialization round-trip benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::OnceLock;
use umbra::crypto::commitment::BlindingFactor;
use umbra::crypto::keys::KemKeypair;
use umbra::crypto::proof::MerkleNode;
use umbra::transaction::builder::{InputSpec, TransactionBuilder};
use umbra::transaction::Transaction;

mod common;
use common::light_proof_options;

fn cached_tx() -> &'static Transaction {
    static TX: OnceLock<Transaction> = OnceLock::new();
    TX.get_or_init(|| {
        let recipient = KemKeypair::generate();

        // Build a depth-20 Merkle path with dummy siblings
        let merkle_path: Vec<MerkleNode> = (0..20)
            .map(|i| MerkleNode {
                hash: umbra::hash_domain(b"umbra.bench.sibling", &[i as u8; 32]),
                is_left: i % 2 == 0,
            })
            .collect();

        let spend_auth = umbra::hash_domain(b"umbra.bench.spend_auth", &[1u8; 32]);

        TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth,
                merkle_path,
            })
            .add_output(recipient.public.clone(), 800)
            .set_proof_options(light_proof_options())
            .build()
            .expect("build_valid_tx failed")
    })
}

/// Benchmark TransactionBuilder::build() with multiple inputs, exercising the
/// rayon par_iter() path (triggered when inputs > 1).
fn bench_build_tx_parallel(c: &mut Criterion) {
    let recipient = KemKeypair::generate();
    let opts = light_proof_options();

    let mut group = c.benchmark_group("build_tx_parallel");
    group.sample_size(10);

    for count in [2usize, 4] {
        group.bench_function(format!("{count}"), |b| {
            b.iter_batched(
                || {
                    let mut builder = TransactionBuilder::new();
                    for i in 0..count {
                        let merkle_path: Vec<MerkleNode> = (0..20)
                            .map(|j| MerkleNode {
                                hash: umbra::hash_domain(
                                    b"umbra.bench.sibling",
                                    &[(i * 20 + j) as u8; 32],
                                ),
                                is_left: j % 2 == 0,
                            })
                            .collect();
                        let spend_auth =
                            umbra::hash_domain(b"umbra.bench.spend_auth", &[i as u8; 32]);
                        builder = builder.add_input(InputSpec {
                            value: 1000,
                            blinding: BlindingFactor::random(),
                            spend_auth,
                            merkle_path,
                        });
                    }
                    // fee = FEE_BASE(100) + count * FEE_PER_INPUT(100)
                    let total_fee = 100 + count as u64 * 100;
                    let output_value = count as u64 * 1000 - total_fee;
                    builder
                        .add_output(recipient.public.clone(), output_value)
                        .set_proof_options(opts.clone())
                },
                |builder| black_box(builder.build().expect("build failed")),
                criterion::BatchSize::PerIteration,
            )
        });
    }
    group.finish();
}

fn bench_serialize_tx(c: &mut Criterion) {
    let tx = cached_tx();
    c.bench_function("serialize_tx", |b| {
        b.iter(|| black_box(umbra::serialize(black_box(tx)).unwrap()))
    });
}

fn bench_deserialize_tx(c: &mut Criterion) {
    let tx = cached_tx();
    let bytes = umbra::serialize(tx).unwrap();
    c.bench_function("deserialize_tx", |b| {
        b.iter(|| black_box(umbra::deserialize::<Transaction>(black_box(&bytes)).unwrap()))
    });
}

criterion_group! {
    name = transaction_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_build_tx_parallel, bench_serialize_tx, bench_deserialize_tx
}
criterion_main!(transaction_benches);
