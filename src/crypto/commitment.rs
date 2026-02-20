//! Hash-based commitments for confidential amounts.
//!
//! Uses Rescue Prime (Rp64_256) domain-separated hashing over the Goldilocks field:
//!   Commit(value, blinding) = RescuePrime("commit" || value || blinding)
//!
//! Properties:
//! - **Hiding**: Given C, cannot determine value without blinding factor
//! - **Binding**: Cannot find (v', b') != (v, b) such that Commit(v', b') = C
//! - **No trusted setup**: Pure hash-based, transparent
//! - **STARK-friendly**: Same hash function used inside zk-STARK circuits

use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::stark::convert::{felts_to_hash, hash_to_felts, Felt};
use crate::crypto::stark::rescue;
use crate::Hash;

/// Compute a Blake3-512 binding for defense-in-depth against quantum preimage attacks.
///
/// The binding is: Blake3-XOF-512("umbra.commitment.blake3_binding" || value_le || blinding).
/// This provides ~256-bit quantum preimage resistance (Grover halves the 512-bit output).
/// Even if Rescue Prime has undiscovered algebraic weaknesses, an attacker cannot recover
/// (value, blinding) without also breaking Blake3-512.
///
/// Verified outside STARK circuits (the STARK proves Rescue Prime commitment knowledge;
/// Blake3 adds a redundant binding layer).
pub fn blake3_512_binding(value: u64, blinding: &BlindingFactor) -> [u8; 64] {
    let mut hasher = blake3::Hasher::new_derive_key("umbra.commitment.blake3_binding");
    hasher.update(&value.to_le_bytes());
    hasher.update(&blinding.0);
    let mut output = [0u8; 64];
    hasher.finalize_xof().fill(&mut output);
    output
}

/// Verify that a Blake3-512 binding matches the given value and blinding factor.
pub fn verify_blake3_binding(binding: &[u8; 64], value: u64, blinding: &BlindingFactor) -> bool {
    let expected = blake3_512_binding(value, blinding);
    crate::constant_time_eq(binding, &expected)
}

/// A commitment to a value with a blinding factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Commitment(pub Hash);

/// A blinding factor used to hide the committed value.
///
/// Debug output is redacted to prevent accidental logging of secret values.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BlindingFactor(pub(crate) [u8; 32]);

impl std::fmt::Debug for BlindingFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlindingFactor([REDACTED])")
    }
}

impl BlindingFactor {
    /// Generate a random blinding factor.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        BlindingFactor(bytes)
    }

    /// Create from known bytes (for testing or derivation).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        BlindingFactor(bytes)
    }

    /// Convert to field elements for STARK witness.
    pub fn to_felts(&self) -> [Felt; 4] {
        hash_to_felts(&self.0)
    }
}

impl Commitment {
    /// Create a commitment: C = RescuePrime(domain || value || blinding).
    pub fn commit(value: u64, blinding: &BlindingFactor) -> Self {
        let value_felt = Felt::new(value);
        let blinding_felts = blinding.to_felts();
        let digest = rescue::hash_commitment(value_felt, &blinding_felts);
        Commitment(felts_to_hash(&digest))
    }

    /// Verify that a commitment opens to the given value and blinding.
    pub fn verify(&self, value: u64, blinding: &BlindingFactor) -> bool {
        let expected = Self::commit(value, blinding);
        crate::constant_time_eq(&self.0, &expected.0)
    }

    /// A commitment to zero with a specific blinding factor.
    pub fn zero(blinding: &BlindingFactor) -> Self {
        Self::commit(0, blinding)
    }

    /// Convert to field elements for STARK public inputs.
    pub fn to_felts(&self) -> [Felt; 4] {
        hash_to_felts(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_roundtrip() {
        let blind = BlindingFactor::random();
        let c = Commitment::commit(42, &blind);
        assert!(c.verify(42, &blind));
        assert!(!c.verify(43, &blind));
    }

    #[test]
    fn different_blindings_produce_different_commitments() {
        let b1 = BlindingFactor::random();
        let b2 = BlindingFactor::random();
        let c1 = Commitment::commit(100, &b1);
        let c2 = Commitment::commit(100, &b2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn commitment_deterministic() {
        let b = BlindingFactor::from_bytes([42u8; 32]);
        let c1 = Commitment::commit(1000, &b);
        let c2 = Commitment::commit(1000, &b);
        assert_eq!(c1, c2);
    }

    #[test]
    fn zero_commitment() {
        let b = BlindingFactor::random();
        let c = Commitment::zero(&b);
        assert!(c.verify(0, &b));
        assert!(!c.verify(1, &b));
    }

    #[test]
    fn to_felts_roundtrip() {
        let b = BlindingFactor::from_bytes([7u8; 32]);
        let c = Commitment::commit(500, &b);
        let felts = c.to_felts();
        let hash = felts_to_hash(&felts);
        assert_eq!(hash, c.0);
    }

    #[test]
    fn commitment_max_value() {
        let blind = BlindingFactor::random();
        let c = Commitment::commit(u64::MAX, &blind);
        assert!(c.verify(u64::MAX, &blind));
    }

    #[test]
    fn commitment_different_values_different_commitments() {
        let blind = BlindingFactor::from_bytes([42u8; 32]);
        let c1 = Commitment::commit(100, &blind);
        let c2 = Commitment::commit(200, &blind);
        assert_ne!(c1, c2);
    }

    #[test]
    fn multiple_random_blindings_different_commitments() {
        let c1 = Commitment::commit(100, &BlindingFactor::random());
        let c2 = Commitment::commit(100, &BlindingFactor::random());
        let c3 = Commitment::commit(100, &BlindingFactor::random());
        // Three random blindings should produce three different commitments
        assert_ne!(c1, c2);
        assert_ne!(c2, c3);
        assert_ne!(c1, c3);
    }

    #[test]
    fn zero_commitment_equals_commit_zero() {
        let blind = BlindingFactor::from_bytes([99u8; 32]);
        let zero_c = Commitment::zero(&blind);
        let explicit_c = Commitment::commit(0, &blind);
        assert_eq!(zero_c, explicit_c);
    }

    #[test]
    fn commitment_verify_wrong_blinding_fails() {
        let b1 = BlindingFactor::from_bytes([1u8; 32]);
        let b2 = BlindingFactor::from_bytes([2u8; 32]);
        let c = Commitment::commit(42, &b1);
        assert!(!c.verify(42, &b2));
    }

    #[test]
    fn commitment_zero_value_nonzero_hash() {
        let blind = BlindingFactor::from_bytes([0u8; 32]);
        let c = Commitment::commit(0, &blind);
        // Commitment hash should not be all zeros even for zero inputs
        assert_ne!(c.0, [0u8; 32]);
    }

    #[test]
    fn blinding_factor_from_bytes_roundtrip() {
        let bytes = [77u8; 32];
        let bf = BlindingFactor::from_bytes(bytes);
        assert_eq!(bf.0, bytes);
    }

    #[test]
    fn blinding_factor_debug_redacted() {
        let bf = BlindingFactor::from_bytes([42u8; 32]);
        let debug_str = format!("{:?}", bf);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("42"));
    }

    #[test]
    fn blinding_factor_to_felts_deterministic() {
        let bf = BlindingFactor::from_bytes([7u8; 32]);
        let f1 = bf.to_felts();
        let f2 = bf.to_felts();
        assert_eq!(f1, f2);
    }

    // ── Blake3-512 binding tests ──

    #[test]
    fn blake3_binding_deterministic() {
        let b = BlindingFactor::from_bytes([42u8; 32]);
        let b1 = blake3_512_binding(100, &b);
        let b2 = blake3_512_binding(100, &b);
        assert_eq!(b1, b2);
    }

    #[test]
    fn blake3_binding_is_64_bytes() {
        let b = BlindingFactor::random();
        let binding = blake3_512_binding(42, &b);
        assert_eq!(binding.len(), 64);
    }

    #[test]
    fn blake3_binding_differs_by_value() {
        let b = BlindingFactor::from_bytes([1u8; 32]);
        let b1 = blake3_512_binding(100, &b);
        let b2 = blake3_512_binding(200, &b);
        assert_ne!(b1, b2);
    }

    #[test]
    fn blake3_binding_differs_by_blinding() {
        let b1 = BlindingFactor::from_bytes([1u8; 32]);
        let b2 = BlindingFactor::from_bytes([2u8; 32]);
        let binding1 = blake3_512_binding(100, &b1);
        let binding2 = blake3_512_binding(100, &b2);
        assert_ne!(binding1, binding2);
    }

    #[test]
    fn blake3_binding_nonzero_for_zero_inputs() {
        let b = BlindingFactor::from_bytes([0u8; 32]);
        let binding = blake3_512_binding(0, &b);
        assert_ne!(binding, [0u8; 64]);
    }

    #[test]
    fn verify_blake3_binding_correct() {
        let b = BlindingFactor::random();
        let binding = blake3_512_binding(42, &b);
        assert!(verify_blake3_binding(&binding, 42, &b));
    }

    #[test]
    fn verify_blake3_binding_wrong_value() {
        let b = BlindingFactor::random();
        let binding = blake3_512_binding(42, &b);
        assert!(!verify_blake3_binding(&binding, 43, &b));
    }

    #[test]
    fn verify_blake3_binding_wrong_blinding() {
        let b1 = BlindingFactor::from_bytes([1u8; 32]);
        let b2 = BlindingFactor::from_bytes([2u8; 32]);
        let binding = blake3_512_binding(42, &b1);
        assert!(!verify_blake3_binding(&binding, 42, &b2));
    }

    #[test]
    fn blake3_binding_max_value() {
        let b = BlindingFactor::random();
        let binding = blake3_512_binding(u64::MAX, &b);
        assert!(verify_blake3_binding(&binding, u64::MAX, &b));
        assert!(!verify_blake3_binding(&binding, u64::MAX - 1, &b));
    }
}
