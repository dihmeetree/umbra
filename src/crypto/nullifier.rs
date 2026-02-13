//! Nullifiers for double-spend prevention.
//!
//! When a user spends an output, they reveal a nullifier derived from their
//! secret key material and the output's commitment. The nullifier is deterministic:
//! spending the same output twice would produce the same nullifier.
//!
//! The nullifier itself does not reveal which output is being spent — only
//! the spender (who knows the secret) can compute the nullifier. The
//! commitment is never published on-chain; inputs reveal only a one-way
//! `proof_link` that binds the spend and balance proofs without exposing
//! which commitment is being spent.
//!
//!   nullifier = RescuePrime("null" || spend_auth_key || commitment)

use serde::{Deserialize, Serialize};

use crate::crypto::stark::convert::{felts_to_hash, hash_to_felts, Felt};
use crate::crypto::stark::rescue;
use crate::Hash;

/// A nullifier that marks an output as spent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub Hash);

impl Nullifier {
    /// Derive a nullifier from a spending key and the output's commitment hash.
    ///
    /// `spend_auth`: the secret spending authorization key (derived from stealth handshake)
    /// `commitment_hash`: the commitment to the output being spent
    pub fn derive(spend_auth: &Hash, commitment_hash: &Hash) -> Self {
        let auth_felts = hash_to_felts(spend_auth);
        let commitment_felts = hash_to_felts(commitment_hash);
        let digest = rescue::hash_nullifier(&auth_felts, &commitment_felts);
        Nullifier(felts_to_hash(&digest))
    }

    /// Verify that a nullifier was correctly derived (only possible with the secret).
    ///
    /// Uses constant-time comparison to avoid timing side-channels.
    pub fn verify(&self, spend_auth: &Hash, commitment_hash: &Hash) -> bool {
        let expected = Self::derive(spend_auth, commitment_hash);
        crate::constant_time_eq(&self.0, &expected.0)
    }

    /// Convert to field elements for STARK public inputs.
    pub fn to_felts(&self) -> [Felt; 4] {
        hash_to_felts(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A set of revealed nullifiers, used by the state to prevent double-spends.
#[derive(Clone, Debug, Default)]
pub struct NullifierSet {
    nullifiers: std::collections::HashSet<Nullifier>,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a nullifier has already been revealed (output already spent).
    pub fn contains(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(nullifier)
    }

    /// Insert a nullifier. Returns false if it was already present (double-spend).
    pub fn insert(&mut self, nullifier: Nullifier) -> bool {
        self.nullifiers.insert(nullifier)
    }

    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }

    /// Remove a nullifier from the set (used for rollback on partial vertex application).
    pub fn remove(&mut self, nullifier: &Nullifier) -> bool {
        self.nullifiers.remove(nullifier)
    }

    /// Iterate over all nullifiers in the set.
    pub fn iter(&self) -> impl Iterator<Item = &Nullifier> {
        self.nullifiers.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullifier_deterministic() {
        let auth = [42u8; 32];
        let commitment = [7u8; 32];
        let n1 = Nullifier::derive(&auth, &commitment);
        let n2 = Nullifier::derive(&auth, &commitment);
        assert_eq!(n1, n2);
    }

    #[test]
    fn different_commitments_different_nullifiers() {
        let auth = [42u8; 32];
        let c1 = [1u8; 32];
        let c2 = [2u8; 32];
        assert_ne!(Nullifier::derive(&auth, &c1), Nullifier::derive(&auth, &c2));
    }

    #[test]
    fn nullifier_set_detects_double_spend() {
        let mut set = NullifierSet::new();
        let n = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        assert!(set.insert(n));
        assert!(!set.insert(n)); // double-spend detected
    }

    #[test]
    fn nullifier_verify() {
        let auth = [99u8; 32];
        let commitment = [55u8; 32];
        let n = Nullifier::derive(&auth, &commitment);
        assert!(n.verify(&auth, &commitment));
        assert!(!n.verify(&[0u8; 32], &commitment));
    }
}
