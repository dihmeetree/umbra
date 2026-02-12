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

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::stark::convert::{felts_to_hash, hash_to_felts, Felt};
use crate::crypto::stark::rescue;
use crate::Hash;

/// A commitment to a value with a blinding factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Commitment(pub Hash);

/// A blinding factor used to hide the committed value.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct BlindingFactor(pub [u8; 32]);

impl BlindingFactor {
    /// Generate a random blinding factor.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
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
}
