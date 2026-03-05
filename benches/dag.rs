//! Benchmarks for DAG operations: insertion, finalized ordering, pruning.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use umbra::consensus::dag::{Dag, Vertex, VertexId};
use umbra::crypto::keys::SigningKeypair;

fn make_vertex(parents: Vec<VertexId>, round: u64, nonce: u8, keypair: &SigningKeypair) -> Vertex {
    let epoch = round / umbra::constants::EPOCH_LENGTH;
    let id = Vertex::compute_id(
        &parents,
        epoch,
        round,
        &[nonce; 32],
        &[round as u8; 32],
        None,
        &[0u8; 32],
        umbra::constants::PROTOCOL_VERSION_ID,
    );
    Vertex {
        id,
        parents,
        epoch,
        round,
        proposer: keypair.public.clone(),
        transactions: vec![],
        timestamp: 0,
        state_root: [0u8; 32],
        signature: umbra::crypto::keys::Signature::empty(),
        vrf_proof: None,
        protocol_version: umbra::constants::PROTOCOL_VERSION_ID,
    }
}

/// Build a linear chain DAG of `n` finalized vertices.
/// Uses multiple keypairs to avoid per-proposer rate limiting (100/epoch).
fn build_dag(n: usize, keypairs: &[SigningKeypair]) -> Dag {
    let genesis = Dag::genesis_vertex();
    let gid = genesis.id;
    let mut dag = Dag::new(genesis);

    let mut prev = gid;
    for i in 1..n {
        let kp = &keypairs[i % keypairs.len()];
        let v = make_vertex(vec![prev], i as u64, i as u8, kp);
        let vid = v.id;
        dag.insert_unchecked(v).unwrap();
        assert!(dag.finalize(&vid));
        prev = vid;
    }
    dag
}

/// Generate enough keypairs to avoid rate limiting for `n` vertices.
fn gen_keypairs(n: usize) -> Vec<SigningKeypair> {
    let count = (n / 50).max(1); // 50 vertices per proposer leaves headroom
    (0..count).map(|_| SigningKeypair::generate()).collect()
}

fn bench_dag_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_insert");
    for size in [10, 100, 1000] {
        let keypairs = gen_keypairs(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || {
                    let dag = build_dag(size, &keypairs);
                    let tip = *dag.tips().iter().next().unwrap();
                    let v = make_vertex(vec![tip], size as u64, 0xFF, &keypairs[0]);
                    (dag, v)
                },
                |(mut dag, v)| dag.insert_unchecked(v).unwrap(),
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_finalized_order(c: &mut Criterion) {
    let mut group = c.benchmark_group("finalized_order");
    for size in [10, 100, 1000] {
        let keypairs = gen_keypairs(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let dag = build_dag(size, &keypairs);
            b.iter(|| dag.finalized_order())
        });
    }
    group.finish();
}

fn bench_dag_prune(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_prune");
    for size in [100, 1000] {
        let keypairs = gen_keypairs(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || build_dag(size, &keypairs),
                |mut dag| dag.prune_finalized(u64::MAX),
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(
    dag_benches,
    bench_dag_insert,
    bench_finalized_order,
    bench_dag_prune
);
criterion_main!(dag_benches);
