//! zk-STARK proof system for Umbra.
//!
//! Uses the winterfell library with Rescue Prime (Rp64_256) over the Goldilocks
//! field (p = 2^64 - 2^32 + 1) to provide zero-knowledge proofs with:
//! - No trusted setup
//! - Post-quantum security (hash-based)
//! - ~128-bit conjectured security (capped by Rp64_256 collision resistance)
//!
//! Three proof types:
//! - **BalanceStarkProof**: proves commitment openings + balance equation + range
//! - **SpendStarkProof**: proves Merkle membership + nullifier derivation
//! - **ExecutionStarkProof**: proves correct contract VM execution

pub mod convert;
pub mod rescue;
pub mod types;

pub mod balance_air;
pub mod balance_prover;
pub mod execution_air;
pub mod execution_prover;
pub mod spend_air;
pub mod spend_prover;
pub mod verify;

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
pub use execution_prover::prove_execution;
pub use spend_prover::prove_spend;

/// Lightweight proof options for testing and simulation.
///
/// NOT suitable for production use — provides weaker security guarantees.
/// Uses reduced grinding factor for faster proof generation.
pub fn light_proof_options() -> ProofOptions {
    ProofOptions::new(
        42, // num_queries
        8,  // blowup_factor (winterfell minimum)
        10, // grinding_factor (reduced from 16)
        FieldExtension::Cubic,
        8,   // FRI folding factor
        255, // FRI max remainder degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Default STARK proof options targeting ~128-bit conjectured security.
///
/// Uses cubic field extension (192-bit field security) so the field is not
/// the bottleneck. Query security: 42 queries × log2(8) + 16 grinding = 142 bits.
/// Actual conjectured security is capped at 128 bits by Rp64_256 hash collision
/// resistance (256-bit output → 128-bit birthday bound).
pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(
        42, // num_queries
        8,  // blowup_factor
        16, // grinding_factor
        FieldExtension::Cubic,
        8,   // FRI folding factor
        255, // FRI max remainder degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn light_proof_options_parameters() {
        let opts = light_proof_options();
        assert_eq!(opts.num_queries(), 42);
        assert_eq!(opts.blowup_factor(), 8);
        assert_eq!(opts.grinding_factor(), 10);
    }

    #[test]
    fn default_proof_options_parameters() {
        let opts = default_proof_options();
        assert_eq!(opts.num_queries(), 42);
        assert_eq!(opts.blowup_factor(), 8);
        assert_eq!(opts.grinding_factor(), 16);
    }

    #[test]
    fn default_proof_options_stronger_than_light() {
        let light = light_proof_options();
        let default = default_proof_options();
        assert!(default.grinding_factor() > light.grinding_factor());
    }
}
