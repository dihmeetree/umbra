//! Benchmarks for cryptographic primitives: signatures, hashing, VRF.

use criterion::{criterion_group, criterion_main, Criterion};
use umbra::crypto::keys::SigningKeypair;
use umbra::crypto::stark::rescue;
use umbra::crypto::vrf::VrfOutput;
use winterfell::math::fields::f64::BaseElement as Felt;

fn bench_dilithium_sign(c: &mut Criterion) {
    let keypair = SigningKeypair::generate();
    let message = [0xABu8; 256];
    c.bench_function("dilithium5_sign", |b| b.iter(|| keypair.sign(&message)));
}

fn bench_dilithium_verify(c: &mut Criterion) {
    let keypair = SigningKeypair::generate();
    let message = [0xABu8; 256];
    let signature = keypair.sign(&message);
    c.bench_function("dilithium5_verify", |b| {
        b.iter(|| keypair.public.verify(&message, &signature))
    });
}

fn bench_blake3_hash_domain(c: &mut Criterion) {
    let data = [0u8; 256];
    c.bench_function("blake3_hash_domain", |b| {
        b.iter(|| umbra::hash_domain(b"umbra.bench", &data))
    });
}

fn bench_blake3_hash_concat(c: &mut Criterion) {
    let parts: [&[u8]; 4] = [&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32]];
    c.bench_function("blake3_hash_concat", |b| {
        b.iter(|| umbra::hash_concat(&parts))
    });
}

fn bench_rescue_prime_commitment(c: &mut Criterion) {
    let value = Felt::new(1000);
    let blinding = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
    c.bench_function("rescue_prime_commitment", |b| {
        b.iter(|| rescue::hash_commitment(value, &blinding))
    });
}

fn bench_vrf_evaluate(c: &mut Criterion) {
    let keypair = SigningKeypair::generate();
    let input = [0xCDu8; 32];
    c.bench_function("vrf_evaluate", |b| {
        b.iter(|| VrfOutput::evaluate(&keypair, &input))
    });
}

criterion_group!(
    crypto_benches,
    bench_dilithium_sign,
    bench_dilithium_verify,
    bench_blake3_hash_domain,
    bench_blake3_hash_concat,
    bench_rescue_prime_commitment,
    bench_vrf_evaluate
);
criterion_main!(crypto_benches);
