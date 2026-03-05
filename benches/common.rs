//! Shared helpers for benchmark suites.

use winterfell::ProofOptions;

/// Light proof options for benchmarks (grinding factor 10 vs production 16).
pub fn light_proof_options() -> ProofOptions {
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
