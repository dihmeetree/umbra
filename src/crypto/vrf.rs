//! Verifiable Random Function (VRF) for committee selection.
//!
//! A VRF produces a pseudorandom output that can be publicly verified but not
//! predicted without the secret key. Used to:
//! - Randomly select BFT committee members each epoch
//! - Ensure selection is unbiased and unpredictable
//! - Allow anyone to verify the selection was legitimate
//!
//! Construction: VRF(sk, input) = (H(dilithium_sign(sk, input)), proof=dilithium_sign(sk, input))
//! Uses Dilithium signatures as the VRF base — the VRF output is derived from
//! the Dilithium signature, which is deterministic for a given (sk, input) pair.
//! SPHINCS+ provides authentication redundancy via a separate proof.
//!
//! **Anti-grinding**: Because Dilithium may use randomized signing internally,
//! the protocol uses a commit-reveal scheme to prevent grinding:
//! 1. Validators must submit a binding commitment H(VRF_proof) before the
//!    epoch seed is finalized.
//! 2. After the seed is revealed, validators publish the VRF proof.
//! 3. Only proofs matching the pre-committed hash are accepted.
//!
//! Additionally, `evaluate()` binds the VRF to the validator's public key
//! fingerprint, ensuring that each validator has exactly one valid evaluation
//! per epoch (even if the underlying signature is non-deterministic, the
//! committed proof pins the output).

use serde::{Deserialize, Serialize};

use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature as SigTrait, SecretKey as SignSkTrait};

#[cfg(not(feature = "fast-tests"))]
use super::keys::SPHINCS_SIG_BYTES;
use super::keys::{SigningKeypair, SigningPublicKey, DILITHIUM5_SIG_BYTES};
use crate::Hash;

/// A VRF output and its proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VrfOutput {
    /// The pseudorandom value (32 bytes), derived from the Dilithium signature
    pub value: Hash,
    /// The Dilithium proof (a Dilithium signature over the input)
    pub proof: Vec<u8>,
    /// SPHINCS+ authentication proof (redundancy for quantum-safe assurance)
    pub sphincs_proof: Vec<u8>,
    /// Commitment to the proof: H(proof). Must be submitted before the epoch
    /// seed is revealed, preventing grinding attacks.
    pub proof_commitment: Hash,
}

impl VrfOutput {
    /// Evaluate the VRF: produce a pseudorandom output for a given input.
    ///
    /// # Determinism assumption
    ///
    /// Dilithium5 signing MAY be internally randomized depending on the
    /// implementation. If the underlying `dilithium5::detached_sign` is
    /// deterministic (as in the pqcrypto reference implementation), then
    /// `evaluate(sk, input)` is a true VRF: identical inputs always produce
    /// identical outputs. If the implementation is randomized, the commit-
    /// reveal scheme (see below) pins the output to the first evaluation,
    /// preserving security.
    ///
    /// The `proof_commitment` field is computed as H(proof) and must be
    /// submitted to the chain before the epoch seed is revealed. This
    /// prevents grinding: even if Dilithium signing is randomized, the
    /// validator is bound to the first proof they committed to.
    pub fn evaluate(keypair: &SigningKeypair, input: &[u8]) -> Self {
        // Tag the input to avoid domain confusion
        let tagged_input = crate::hash_concat(&[b"umbra.vrf.input", input]);

        // Sign the tagged input with the hybrid keypair
        let signature = keypair.sign(&tagged_input);

        // Derive the VRF output from the Dilithium signature only.
        // Dilithium is deterministic, which is required for VRF correctness:
        // the same (key, input) must always produce the same VRF value.
        // SPHINCS+ signing is randomized in pqcrypto, so it CANNOT be mixed
        // into the VRF value without breaking determinism.
        //
        // VRF unpredictability is ~128-bit (Dilithium), but VRF proof
        // authentication is ~256-bit (AND composition: both signatures must
        // verify). An attacker who weakens Dilithium still cannot forge VRF
        // proofs without also breaking SPHINCS+.
        let value = crate::hash_domain(b"umbra.vrf.output", &signature.dilithium);

        // Compute the proof commitment (anti-grinding)
        let proof_commitment =
            crate::hash_domain(b"umbra.vrf.proof_commitment", &signature.dilithium);

        VrfOutput {
            value,
            proof: signature.dilithium,
            sphincs_proof: signature.sphincs,
            proof_commitment,
        }
    }

    /// Verify the VRF output against a pre-registered commitment (full anti-grinding).
    ///
    /// `expected_commitment` is the commitment hash that was submitted on-chain
    /// before the epoch seed was revealed. This MUST be checked to prevent
    /// grinding attacks where a validator re-evaluates the VRF until they get
    /// a favorable committee selection.
    pub fn verify(
        &self,
        public_key: &SigningPublicKey,
        input: &[u8],
        expected_commitment: &Hash,
    ) -> bool {
        let tagged_input = crate::hash_concat(&[b"umbra.vrf.input", input]);

        // Validate proof lengths before constructing a Signature
        if self.proof.len() != DILITHIUM5_SIG_BYTES {
            return false;
        }
        #[cfg(not(feature = "fast-tests"))]
        if self.sphincs_proof.len() != SPHINCS_SIG_BYTES {
            return false;
        }

        // Verify the hybrid signature (both Dilithium AND SPHINCS+ must pass)
        let sig = super::keys::Signature {
            dilithium: self.proof.clone(),
            sphincs: self.sphincs_proof.clone(),
        };
        if !public_key.verify(&tagged_input, &sig) {
            return false;
        }

        // Verify the output is correctly derived from the Dilithium proof
        let expected_value = crate::hash_domain(b"umbra.vrf.output", &self.proof);
        if !crate::constant_time_eq(&self.value, &expected_value) {
            return false;
        }

        // Verify proof commitment matches (anti-grinding)
        let computed_commitment = crate::hash_domain(b"umbra.vrf.proof_commitment", &self.proof);
        if !crate::constant_time_eq(&self.proof_commitment, &computed_commitment) {
            return false;
        }

        // Verify against the pre-registered on-chain commitment
        if !crate::constant_time_eq(expected_commitment, &computed_commitment) {
            return false;
        }

        true
    }

    /// Verify the VRF proof cryptographically **without** checking against a
    /// pre-registered commitment.
    ///
    /// # Safety
    ///
    /// **DO NOT use for consensus-critical verification.** Without commitment
    /// checking, a validator could grind VRF evaluations to bias committee
    /// selection. This method is intended ONLY for:
    /// - Local self-checks after `evaluate()`
    /// - First-seen VRF observations before a commitment is registered
    ///   (the commitment MUST be registered immediately after)
    ///
    /// For on-chain verification, always use `verify()` with the pre-registered
    /// commitment.
    pub fn verify_proof_only(&self, public_key: &SigningPublicKey, input: &[u8]) -> bool {
        let tagged_input = crate::hash_concat(&[b"umbra.vrf.input", input]);

        // Validate proof lengths
        if self.proof.len() != DILITHIUM5_SIG_BYTES {
            return false;
        }
        #[cfg(not(feature = "fast-tests"))]
        if self.sphincs_proof.len() != SPHINCS_SIG_BYTES {
            return false;
        }

        let sig = super::keys::Signature {
            dilithium: self.proof.clone(),
            sphincs: self.sphincs_proof.clone(),
        };
        if !public_key.verify(&tagged_input, &sig) {
            return false;
        }

        let expected_value = crate::hash_domain(b"umbra.vrf.output", &self.proof);
        if !crate::constant_time_eq(&self.value, &expected_value) {
            return false;
        }

        let computed_commitment = crate::hash_domain(b"umbra.vrf.proof_commitment", &self.proof);
        if !crate::constant_time_eq(&self.proof_commitment, &computed_commitment) {
            return false;
        }

        true
    }

    /// Check if this VRF output selects us for a committee of given size,
    /// given the total number of eligible validators.
    ///
    /// Selection criterion: interpret the VRF output as a number and check
    /// if it falls in the selected range.
    pub fn is_selected(&self, committee_size: usize, total_validators: usize) -> bool {
        if total_validators == 0 || committee_size >= total_validators {
            return true;
        }
        // Use first 8 bytes as a u64 for the lottery
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.value[..8]);
        let random_val = u64::from_le_bytes(bytes);
        // Use u128 to avoid overflow: selected if random_val/u64::MAX < committee_size/total_validators
        (random_val as u128) * (total_validators as u128)
            < (committee_size as u128) * ((u64::MAX as u128) + 1)
    }

    /// Derive a sort key from the VRF output.
    /// Used to deterministically order committee members.
    pub fn sort_key(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.value[..8]);
        u64::from_le_bytes(bytes)
    }
}

/// Assert that the underlying Dilithium5 implementation produces deterministic
/// signatures. Call once at node startup to catch non-deterministic implementations
/// that would break VRF correctness.
///
/// Panics if signing the same message twice produces different Dilithium signatures.
pub fn assert_deterministic_signing(keypair: &SigningKeypair) {
    let test_msg = crate::hash_domain(b"umbra.vrf.determinism_check", b"test");
    let dil_sk = dilithium5::SecretKey::from_bytes(&keypair.secret.dilithium)
        .expect("FATAL: corrupted Dilithium5 secret key");
    let sig1 = dilithium5::detached_sign(&test_msg, &dil_sk);
    let sig2 = dilithium5::detached_sign(&test_msg, &dil_sk);
    assert_eq!(
        sig1.as_bytes(),
        sig2.as_bytes(),
        "FATAL: Dilithium5 signing is not deterministic. \
         The VRF construction requires deterministic signatures."
    );
}

/// Seed for VRF evaluation, derived from the previous epoch's state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochSeed {
    pub epoch: u64,
    pub seed: Hash,
}

impl EpochSeed {
    /// Create the genesis epoch seed.
    pub fn genesis() -> Self {
        EpochSeed {
            epoch: 0,
            seed: crate::hash_domain(b"umbra.epoch.genesis", b"umbra"),
        }
    }

    /// Derive the next epoch's seed from the current epoch's final state.
    pub fn next(&self, epoch_final_hash: &Hash) -> Self {
        EpochSeed {
            epoch: self.epoch.checked_add(1).expect("epoch overflow"),
            seed: crate::hash_concat(&[
                b"umbra.epoch.seed",
                &self.epoch.to_le_bytes(),
                &self.seed,
                epoch_final_hash,
            ]),
        }
    }

    /// Build the VRF input for a specific validator in this epoch.
    pub fn vrf_input(&self, validator_id: &Hash) -> Vec<u8> {
        crate::hash_concat(&[
            b"umbra.vrf.epoch_input",
            &self.epoch.to_le_bytes(),
            &self.seed,
            validator_id,
        ])
        .to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vrf_evaluate_verify() {
        let kp = SigningKeypair::generate();
        let input = b"epoch-42-committee-selection";
        let output = VrfOutput::evaluate(&kp, input);
        // Full verify with the pre-registered commitment
        assert!(output.verify(&kp.public, input, &output.proof_commitment));
        // Local verify (no commitment check)
        assert!(output.verify_proof_only(&kp.public, input));
    }

    #[test]
    fn dilithium5_signing_is_deterministic() {
        let kp = SigningKeypair::generate();
        assert_deterministic_signing(&kp); // Should not panic
    }

    #[test]
    fn vrf_wrong_key_fails() {
        let kp1 = SigningKeypair::generate();
        let kp2 = SigningKeypair::generate();
        let output = VrfOutput::evaluate(&kp1, b"test");
        assert!(!output.verify(&kp2.public, b"test", &output.proof_commitment));
    }

    #[test]
    fn vrf_wrong_input_fails() {
        let kp = SigningKeypair::generate();
        let output = VrfOutput::evaluate(&kp, b"input1");
        assert!(!output.verify(&kp.public, b"input2", &output.proof_commitment));
    }

    #[test]
    fn vrf_wrong_commitment_fails() {
        let kp = SigningKeypair::generate();
        let output = VrfOutput::evaluate(&kp, b"test");
        let fake_commitment = [0xFFu8; 32];
        assert!(!output.verify(&kp.public, b"test", &fake_commitment));
    }

    #[test]
    fn vrf_deterministic() {
        let kp = SigningKeypair::generate();
        let o1 = VrfOutput::evaluate(&kp, b"same-input");
        let o2 = VrfOutput::evaluate(&kp, b"same-input");
        assert_eq!(o1.value, o2.value);
    }

    #[test]
    fn epoch_seed_progression() {
        let genesis = EpochSeed::genesis();
        let next = genesis.next(&[0u8; 32]);
        assert_eq!(next.epoch, 1);
        assert_ne!(next.seed, genesis.seed);
    }

    #[test]
    fn committee_selection_statistics() {
        let committee = 21;
        let total = 1000;
        let mut selected = 0;

        for i in 0..total {
            let kp = SigningKeypair::generate();
            let input = format!("test-{}", i);
            let output = VrfOutput::evaluate(&kp, input.as_bytes());
            if output.is_selected(committee, total) {
                selected += 1;
            }
        }

        assert!(
            selected > 5 && selected < 60,
            "Expected ~21 selected, got {}",
            selected
        );
    }

    #[test]
    fn sort_key_deterministic() {
        let kp = SigningKeypair::generate();
        let output = VrfOutput::evaluate(&kp, b"sort-test");
        let key1 = output.sort_key();
        let key2 = output.sort_key();
        assert_eq!(key1, key2);
    }

    #[test]
    fn sort_key_matches_first_8_bytes() {
        let kp = SigningKeypair::generate();
        let output = VrfOutput::evaluate(&kp, b"sort-test");
        let mut expected_bytes = [0u8; 8];
        expected_bytes.copy_from_slice(&output.value[..8]);
        assert_eq!(output.sort_key(), u64::from_le_bytes(expected_bytes));
    }

    #[test]
    fn epoch_seed_vrf_input_deterministic() {
        let seed = EpochSeed::genesis();
        let validator_id = [42u8; 32];
        let input1 = seed.vrf_input(&validator_id);
        let input2 = seed.vrf_input(&validator_id);
        assert_eq!(input1, input2);
    }

    #[test]
    fn epoch_seed_vrf_input_differs_by_validator() {
        let seed = EpochSeed::genesis();
        let v1 = [1u8; 32];
        let v2 = [2u8; 32];
        assert_ne!(seed.vrf_input(&v1), seed.vrf_input(&v2));
    }

    #[test]
    fn epoch_seed_vrf_input_differs_by_epoch() {
        let genesis = EpochSeed::genesis();
        let next = genesis.next(&[0u8; 32]);
        let validator_id = [42u8; 32];
        assert_ne!(
            genesis.vrf_input(&validator_id),
            next.vrf_input(&validator_id)
        );
    }

    #[test]
    fn is_selected_edge_cases() {
        let kp = SigningKeypair::generate();
        let output = VrfOutput::evaluate(&kp, b"edge");

        // total_validators == 0 -> always selected
        assert!(output.is_selected(5, 0));
        // committee >= total -> always selected
        assert!(output.is_selected(10, 5));
        assert!(output.is_selected(10, 10));
    }

    #[test]
    fn vrf_tampered_value_fails_verify() {
        let kp = SigningKeypair::generate();
        let mut output = VrfOutput::evaluate(&kp, b"tamper");
        output.value[0] ^= 0xff;
        assert!(!output.verify(&kp.public, b"tamper", &output.proof_commitment));
        assert!(!output.verify_proof_only(&kp.public, b"tamper"));
    }

    #[test]
    fn vrf_tampered_proof_commitment_fails_verify() {
        let kp = SigningKeypair::generate();
        let mut output = VrfOutput::evaluate(&kp, b"tamper2");
        output.proof_commitment[0] ^= 0xff;
        assert!(!output.verify_proof_only(&kp.public, b"tamper2"));
    }

    #[test]
    fn vrf_verify_rejects_tampered_value() {
        let kp = SigningKeypair::generate();
        let mut output = VrfOutput::evaluate(&kp, b"value-tamper");
        output.value[0] ^= 0x01;
        assert!(!output.verify(&kp.public, b"value-tamper", &output.proof_commitment));
        assert!(!output.verify_proof_only(&kp.public, b"value-tamper"));
    }

    #[test]
    fn vrf_verify_rejects_tampered_commitment() {
        let kp = SigningKeypair::generate();
        let mut output = VrfOutput::evaluate(&kp, b"commitment-tamper");
        output.proof_commitment[0] ^= 0x01;
        assert!(!output.verify(&kp.public, b"commitment-tamper", &output.proof_commitment));
        assert!(!output.verify_proof_only(&kp.public, b"commitment-tamper"));
    }

    #[test]
    fn epoch_seed_genesis_deterministic() {
        let g1 = EpochSeed::genesis();
        let g2 = EpochSeed::genesis();
        assert_eq!(g1.seed, g2.seed);
        assert_eq!(g1.epoch, g2.epoch);
    }

    #[test]
    fn epoch_seed_different_after_next() {
        let genesis = EpochSeed::genesis();
        let next = genesis.next(&[0u8; 32]);
        assert_ne!(genesis.seed, next.seed);
    }

    #[test]
    fn vrf_verify_rejects_wrong_proof_length() {
        let kp = SigningKeypair::generate();
        let mut output = VrfOutput::evaluate(&kp, b"proof-len-test");
        let commitment = output.proof_commitment;
        output.proof = vec![0u8; 100];
        assert!(!output.verify(&kp.public, b"proof-len-test", &commitment));
        assert!(!output.verify_proof_only(&kp.public, b"proof-len-test"));
    }

    #[test]
    fn vrf_different_inputs_different_outputs() {
        let kp = SigningKeypair::generate();
        let o1 = VrfOutput::evaluate(&kp, b"input-a");
        let o2 = VrfOutput::evaluate(&kp, b"input-b");
        assert_ne!(o1.value, o2.value);
    }

    #[test]
    fn vrf_different_keys_different_outputs() {
        let kp1 = SigningKeypair::generate();
        let kp2 = SigningKeypair::generate();
        let o1 = VrfOutput::evaluate(&kp1, b"same-input");
        let o2 = VrfOutput::evaluate(&kp2, b"same-input");
        assert_ne!(o1.value, o2.value);
    }

    #[test]
    fn epoch_seed_next_differs_by_hash() {
        let genesis = EpochSeed::genesis();
        let next1 = genesis.next(&[0u8; 32]);
        let next2 = genesis.next(&[1u8; 32]);
        assert_ne!(next1.seed, next2.seed);
        assert_eq!(next1.epoch, next2.epoch);
    }

    #[test]
    fn epoch_seed_chain_is_deterministic() {
        let genesis = EpochSeed::genesis();
        let chain1 = genesis.next(&[42u8; 32]).next(&[43u8; 32]);
        let chain2 = genesis.next(&[42u8; 32]).next(&[43u8; 32]);
        assert_eq!(chain1.seed, chain2.seed);
        assert_eq!(chain1.epoch, chain2.epoch);
    }

    #[test]
    fn is_selected_always_true_when_committee_equals_total() {
        let kp = SigningKeypair::generate();
        let output = VrfOutput::evaluate(&kp, b"equal-test");
        assert!(output.is_selected(100, 100));
    }

    #[test]
    fn vrf_proof_commitment_differs_from_value() {
        let kp = SigningKeypair::generate();
        let output = VrfOutput::evaluate(&kp, b"commitment-value-test");
        assert_ne!(output.value, output.proof_commitment);
    }

    #[test]
    fn is_selected_committee_size_zero() {
        let kp = SigningKeypair::generate();
        let output = VrfOutput::evaluate(&kp, b"zero-committee");
        assert!(!output.is_selected(0, 100));
    }

    #[test]
    fn sort_key_uniqueness_across_keys() {
        let mut sort_keys = std::collections::HashSet::new();
        for i in 0..20u32 {
            let kp = SigningKeypair::generate();
            let input = format!("unique-{}", i);
            let output = VrfOutput::evaluate(&kp, input.as_bytes());
            sort_keys.insert(output.sort_key());
        }
        assert_eq!(sort_keys.len(), 20);
    }

    #[test]
    fn vrf_verify_with_empty_proof_fails() {
        let kp = SigningKeypair::generate();
        let mut output = VrfOutput::evaluate(&kp, b"empty-proof");
        let commitment = output.proof_commitment;
        output.proof = vec![];
        assert!(!output.verify(&kp.public, b"empty-proof", &commitment));
        assert!(!output.verify_proof_only(&kp.public, b"empty-proof"));
    }

    #[test]
    fn vrf_verify_with_single_byte_proof_fails() {
        let kp = SigningKeypair::generate();
        let mut output = VrfOutput::evaluate(&kp, b"one-byte-proof");
        let commitment = output.proof_commitment;
        output.proof = vec![0x42];
        assert!(!output.verify(&kp.public, b"one-byte-proof", &commitment));
        assert!(!output.verify_proof_only(&kp.public, b"one-byte-proof"));
    }

    #[test]
    fn epoch_seed_next_increments_epoch() {
        let genesis = EpochSeed::genesis();
        assert_eq!(genesis.epoch, 0);
        let e1 = genesis.next(&[0u8; 32]);
        assert_eq!(e1.epoch, 1);
        let e2 = e1.next(&[0u8; 32]);
        assert_eq!(e2.epoch, 2);
    }

    #[test]
    #[cfg(not(feature = "fast-tests"))]
    fn vrf_sphincs_proof_verified() {
        let kp = SigningKeypair::generate();
        let mut output = VrfOutput::evaluate(&kp, b"sphincs-test");
        // Tampering with SPHINCS+ proof should fail verification
        if !output.sphincs_proof.is_empty() {
            output.sphincs_proof[0] ^= 0xFF;
        }
        assert!(!output.verify(&kp.public, b"sphincs-test", &output.proof_commitment));
    }
}
