//! Benchmarks for STARK proof generation and verification.
//!
//! These are the most expensive operations in the system. Uses light proof
//! options (grinding factor 10) for faster iteration; production uses 16.

use criterion::{criterion_group, criterion_main, Criterion};
use umbra::crypto::stark::balance_prover::prove_balance;
use umbra::crypto::stark::rescue;
use umbra::crypto::stark::spend_prover::prove_spend;
use umbra::crypto::stark::types::{
    BalancePublicInputs, BalanceWitness, SpendPublicInputs, SpendWitness,
};
use umbra::crypto::stark::verify::{verify_balance_proof, verify_spend_proof};
use winterfell::math::fields::f64::BaseElement as Felt;
use winterfell::math::FieldElement;

mod common;
use common::light_proof_options;

fn make_input_proof_link(value: u64, blinding: &[Felt; 4], link_nonce: &[Felt; 4]) -> [Felt; 4] {
    let commitment = rescue::hash_commitment(Felt::new(value), blinding);
    rescue::hash_proof_link(&commitment, link_nonce)
}

fn build_balance_inputs() -> (BalanceWitness, BalancePublicInputs) {
    let input_values = vec![100u64];
    let output_values = vec![95u64];
    let fee = 5u64;

    let input_blindings = vec![[Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]];
    let output_blindings = vec![[Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]];
    let input_link_nonces = vec![[Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]];

    let input_proof_links = vec![make_input_proof_link(
        input_values[0],
        &input_blindings[0],
        &input_link_nonces[0],
    )];
    let output_commitments = vec![rescue::hash_commitment(
        Felt::new(output_values[0]),
        &output_blindings[0],
    )];

    let pub_inputs = BalancePublicInputs {
        input_proof_links,
        output_commitments,
        fee: Felt::new(fee),
        tx_content_hash: [Felt::ZERO; 4],
    };
    let witness = BalanceWitness {
        input_values,
        input_blindings,
        input_link_nonces,
        output_values,
        output_blindings,
    };
    (witness, pub_inputs)
}

fn build_spend_inputs(nonce_offset: u64) -> (SpendWitness, SpendPublicInputs) {
    let spend_auth = [
        Felt::new(100 + nonce_offset),
        Felt::new(200 + nonce_offset),
        Felt::new(300 + nonce_offset),
        Felt::new(400 + nonce_offset),
    ];
    let commitment = [
        Felt::new(42 + nonce_offset),
        Felt::new(43 + nonce_offset),
        Felt::new(44 + nonce_offset),
        Felt::new(45 + nonce_offset),
    ];
    let nullifier = rescue::hash_nullifier(&spend_auth, &commitment);
    let link_nonce = [
        Felt::new(500 + nonce_offset),
        Felt::new(600 + nonce_offset),
        Felt::new(700 + nonce_offset),
        Felt::new(800 + nonce_offset),
    ];
    let proof_link = rescue::hash_proof_link(&commitment, &link_nonce);

    let mut current = commitment;
    let mut path = Vec::with_capacity(20);
    for level in 0..20 {
        let sibling = [
            Felt::new((level * 4 + 1000) as u64),
            Felt::new((level * 4 + 1001) as u64),
            Felt::new((level * 4 + 1002) as u64),
            Felt::new((level * 4 + 1003) as u64),
        ];
        let is_right = level % 2 == 0;
        path.push((sibling, is_right));
        if is_right {
            current = rescue::hash_merge(&sibling, &current);
        } else {
            current = rescue::hash_merge(&current, &sibling);
        }
    }
    let merkle_root = current;

    let pub_inputs = SpendPublicInputs {
        merkle_root,
        nullifier,
        proof_link,
    };
    let witness = SpendWitness {
        spend_auth,
        commitment,
        link_nonce,
        merkle_path: path,
    };
    (witness, pub_inputs)
}

fn bench_prove_balance(c: &mut Criterion) {
    let (witness, pub_inputs) = build_balance_inputs();
    let opts = light_proof_options();
    c.bench_function("prove_balance", |b| {
        b.iter(|| prove_balance(&witness, &pub_inputs, opts.clone()).unwrap())
    });
}

fn bench_prove_spend(c: &mut Criterion) {
    let (witness, pub_inputs) = build_spend_inputs(0);
    let opts = light_proof_options();
    c.bench_function("prove_spend", |b| {
        b.iter(|| prove_spend(&witness, &pub_inputs, opts.clone()).unwrap())
    });
}

fn bench_verify_balance(c: &mut Criterion) {
    let (witness, pub_inputs) = build_balance_inputs();
    let proof = prove_balance(&witness, &pub_inputs, light_proof_options()).unwrap();
    c.bench_function("verify_balance_proof", |b| {
        b.iter(|| verify_balance_proof(&proof).unwrap())
    });
}

fn bench_verify_spend(c: &mut Criterion) {
    let (witness, pub_inputs) = build_spend_inputs(0);
    let proof = prove_spend(&witness, &pub_inputs, light_proof_options()).unwrap();
    c.bench_function("verify_spend_proof", |b| {
        b.iter(|| verify_spend_proof(&proof).unwrap())
    });
}

fn bench_prove_spend_sequential(c: &mut Criterion) {
    let inputs: Vec<_> = (0..4).map(|i| build_spend_inputs(i * 100)).collect();
    let opts = light_proof_options();

    let mut group = c.benchmark_group("prove_spend_sequential");
    for count in [2, 4] {
        group.bench_function(format!("{count}"), |b| {
            b.iter(|| {
                for (witness, pub_inputs) in inputs.iter().take(count) {
                    prove_spend(witness, pub_inputs, opts.clone()).unwrap();
                }
            })
        });
    }
    group.finish();
}

criterion_group! {
    name = stark_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_prove_balance, bench_prove_spend, bench_verify_balance,
              bench_verify_spend, bench_prove_spend_sequential
}
criterion_main!(stark_benches);
