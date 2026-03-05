//! Benchmarks for transaction serialization and deserialization.
//!
//! Builds one valid transaction with real STARK proofs at startup,
//! then benchmarks the serialization round-trip.

use criterion::{criterion_group, criterion_main, Criterion};
use umbra::crypto::commitment::BlindingFactor;
use umbra::crypto::keys::KemKeypair;
use umbra::crypto::proof::MerkleNode;
use umbra::transaction::builder::{InputSpec, TransactionBuilder};
use umbra::transaction::Transaction;
use winterfell::ProofOptions;

fn light_proof_options() -> ProofOptions {
    ProofOptions::new(
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

fn build_valid_tx() -> Transaction {
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
        .set_fee(200)
        .set_proof_options(light_proof_options())
        .build()
        .expect("build_valid_tx failed")
}

fn bench_serialize_tx(c: &mut Criterion) {
    let tx = build_valid_tx();
    c.bench_function("serialize_tx", |b| {
        b.iter(|| umbra::serialize(&tx).unwrap())
    });
}

fn bench_deserialize_tx(c: &mut Criterion) {
    let tx = build_valid_tx();
    let bytes = umbra::serialize(&tx).unwrap();
    c.bench_function("deserialize_tx", |b| {
        b.iter(|| umbra::deserialize::<Transaction>(&bytes).unwrap())
    });
}

criterion_group! {
    name = transaction_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_serialize_tx, bench_deserialize_tx
}
criterion_main!(transaction_benches);
