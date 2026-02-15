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

    #[test]
    fn nullifier_to_felts_roundtrip() {
        let auth = [42u8; 32];
        let commitment = [7u8; 32];
        let n = Nullifier::derive(&auth, &commitment);
        let felts = n.to_felts();
        // Should produce 4 field elements
        assert_eq!(felts.len(), 4);
        // Converting back should give the same hash (for field-native values)
        let back = crate::crypto::stark::convert::felts_to_hash(&felts);
        assert_eq!(back, n.0);
    }

    #[test]
    fn nullifier_as_bytes() {
        let auth = [42u8; 32];
        let commitment = [7u8; 32];
        let n = Nullifier::derive(&auth, &commitment);
        assert_eq!(n.as_bytes().len(), 32);
        assert_eq!(n.as_bytes(), &n.0);
    }

    #[test]
    fn nullifier_set_len_and_is_empty() {
        let mut set = NullifierSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);

        let n1 = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        set.insert(n1);
        assert!(!set.is_empty());
        assert_eq!(set.len(), 1);

        let n2 = Nullifier::derive(&[3u8; 32], &[4u8; 32]);
        set.insert(n2);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn nullifier_set_contains() {
        let mut set = NullifierSet::new();
        let n = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        assert!(!set.contains(&n));
        set.insert(n);
        assert!(set.contains(&n));
    }

    #[test]
    fn nullifier_set_remove() {
        let mut set = NullifierSet::new();
        let n = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        set.insert(n);
        assert!(set.contains(&n));

        assert!(set.remove(&n)); // returns true when removed
        assert!(!set.contains(&n));
        assert!(set.is_empty());

        assert!(!set.remove(&n)); // returns false when not present
    }

    #[test]
    fn nullifier_set_iter() {
        let mut set = NullifierSet::new();
        let n1 = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
        let n2 = Nullifier::derive(&[3u8; 32], &[4u8; 32]);
        set.insert(n1);
        set.insert(n2);

        let collected: std::collections::HashSet<Nullifier> = set.iter().copied().collect();
        assert_eq!(collected.len(), 2);
        assert!(collected.contains(&n1));
        assert!(collected.contains(&n2));
    }

    #[test]
    fn nullifier_zero_inputs() {
        let n = Nullifier::derive(&[0u8; 32], &[0u8; 32]);
        assert_ne!(n.0, [0u8; 32]);
    }

    #[test]
    fn nullifier_different_inputs_different_outputs() {
        let commitment = [7u8; 32];
        let n1 = Nullifier::derive(&[1u8; 32], &commitment);
        let n2 = Nullifier::derive(&[2u8; 32], &commitment);
        assert_ne!(n1, n2);
    }

    #[test]
    fn nullifier_permuted_inputs_different() {
        // Swapping auth and commitment should produce different nullifiers
        let a = [1u8; 32];
        let b = [2u8; 32];
        let n1 = Nullifier::derive(&a, &b);
        let n2 = Nullifier::derive(&b, &a);
        assert_ne!(n1, n2);
    }

    #[test]
    fn nullifier_set_insert_returns_correct_bool() {
        let mut set = NullifierSet::new();
        let n = Nullifier::derive(&[10u8; 32], &[20u8; 32]);
        assert!(set.insert(n)); // first insert returns true
        assert!(!set.insert(n)); // duplicate returns false
        assert_eq!(set.len(), 1); // only one entry
    }

    #[test]
    fn nullifier_set_multiple_inserts() {
        let mut set = NullifierSet::new();
        for i in 0..10u8 {
            let n = Nullifier::derive(&[i; 32], &[0u8; 32]);
            assert!(set.insert(n));
        }
        assert_eq!(set.len(), 10);
        // Re-inserting all should return false
        for i in 0..10u8 {
            let n = Nullifier::derive(&[i; 32], &[0u8; 32]);
            assert!(!set.insert(n));
        }
        assert_eq!(set.len(), 10);
    }

    #[test]
    fn nullifier_verify_wrong_commitment_fails() {
        let auth = [42u8; 32];
        let commitment = [7u8; 32];
        let n = Nullifier::derive(&auth, &commitment);
        assert!(!n.verify(&auth, &[8u8; 32]));
    }
}
