//! zk-STARK proof system for Umbra.
//!
//! Uses the winterfell library with Rescue Prime (Rp64_256) over the Goldilocks
//! field (p = 2^64 - 2^32 + 1) to provide zero-knowledge proofs with:
//! - No trusted setup
//! - Post-quantum security (hash-based)
//! - ~128-bit conjectured security
//!
//! Two proof types:
//! - **BalanceStarkProof**: proves commitment openings + balance equation + range
//! - **SpendStarkProof**: proves Merkle membership + nullifier derivation

pub mod convert;
pub mod rescue;
pub mod types;

pub mod balance_air;
pub mod balance_prover;
pub mod spend_air;
pub mod spend_prover;
pub mod verify;

#[cfg(test)]
mod formal_verification;

use winterfell::crypto::hashers::Rp64_256;
use winterfell::crypto::DefaultRandomCoin;
use winterfell::crypto::MerkleTree;
use winterfell::{BatchingMethod, FieldExtension, ProofOptions};

/// The hash function used for STARK proofs (Rescue Prime over Goldilocks).
pub type StarkHash = Rp64_256;

/// Merkle tree commitment scheme for STARK proofs.
pub type StarkMerkle = MerkleTree<Rp64_256>;

/// Random coin for Fiat-Shamir in STARK proofs.
pub type StarkCoin = DefaultRandomCoin<Rp64_256>;

// Re-export prover entry points for convenience.
pub use balance_prover::prove_balance;
pub use spend_prover::prove_spend;

/// Lightweight proof options for testing and simulation.
///
/// NOT suitable for production use — provides weaker security guarantees.
/// Uses reduced grinding factor for faster proof generation.
#[cfg(test)]
pub fn light_proof_options() -> ProofOptions {
    ProofOptions::new(
        42, // num_queries
        8,  // blowup_factor (winterfell minimum)
        10, // grinding_factor (reduced from 16)
        FieldExtension::Quadratic,
        8,   // FRI folding factor
        255, // FRI max remainder degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Default STARK proof options targeting ~128-bit conjectured security.
///
/// Uses quadratic field extension (128-bit field security) so the bottleneck
/// is query security: 42 queries × log2(8) + 16 grinding = 142 bits,
/// capped by collision resistance (128) → 128-bit conjectured security.
pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        42, // num_queries
        8,  // blowup_factor
        16, // grinding_factor
        FieldExtension::Quadratic,
        8,   // FRI folding factor
        255, // FRI max remainder degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}
