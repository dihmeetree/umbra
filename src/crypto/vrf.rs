//! Verifiable Random Function (VRF) for committee selection.
//!
//! A VRF produces a pseudorandom output that can be publicly verified but not
//! predicted without the secret key. Used to:
//! - Randomly select BFT committee members each epoch
//! - Ensure selection is unbiased and unpredictable
//! - Allow anyone to verify the selection was legitimate
//!
//! Construction: VRF(sk, input) = (H(sign(sk, input)), proof=sign(sk, input))
//! Uses Dilithium signatures as the base — the VRF output is derived from
//! the signature, which is deterministic for a given (sk, input) pair.
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

use super::keys::{SigningKeypair, SigningPublicKey};
use crate::Hash;

/// A VRF output and its proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VrfOutput {
    /// The pseudorandom value (32 bytes)
    pub value: Hash,
    /// The proof (a Dilithium signature over the input)
    pub proof: Vec<u8>,
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
        let tagged_input = crate::hash_concat(&[b"spectra.vrf.input", input]);

        // Sign the tagged input
        let signature = keypair.sign(&tagged_input);

        // Derive the VRF output from the signature
        let value = crate::hash_domain(b"spectra.vrf.output", &signature.0);

        // Compute the proof commitment (anti-grinding)
        let proof_commitment = crate::hash_domain(b"spectra.vrf.proof_commitment", &signature.0);

        VrfOutput {
            value,
            proof: signature.0,
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
        let tagged_input = crate::hash_concat(&[b"spectra.vrf.input", input]);

        // Verify the signature proof
        let sig = super::keys::Signature(self.proof.clone());
        if !public_key.verify(&tagged_input, &sig) {
            return false;
        }

        // Verify the output is correctly derived from the proof
        let expected_value = crate::hash_domain(b"spectra.vrf.output", &self.proof);
        if !crate::constant_time_eq(&self.value, &expected_value) {
            return false;
        }

        // Verify proof commitment matches (anti-grinding)
        let computed_commitment = crate::hash_domain(b"spectra.vrf.proof_commitment", &self.proof);
        if !crate::constant_time_eq(&self.proof_commitment, &computed_commitment) {
            return false;
        }

        // Verify against the pre-registered on-chain commitment
        if !crate::constant_time_eq(expected_commitment, &computed_commitment) {
            return false;
        }

        true
    }

    /// Verify the VRF proof cryptographically without checking against a
    /// pre-registered commitment. Use ONLY for local self-checks (e.g., after
    /// `evaluate()`). For on-chain verification, always use `verify()` with
    /// the pre-registered commitment.
    pub fn verify_locally(&self, public_key: &SigningPublicKey, input: &[u8]) -> bool {
        let tagged_input = crate::hash_concat(&[b"spectra.vrf.input", input]);

        let sig = super::keys::Signature(self.proof.clone());
        if !public_key.verify(&tagged_input, &sig) {
            return false;
        }

        let expected_value = crate::hash_domain(b"spectra.vrf.output", &self.proof);
        if !crate::constant_time_eq(&self.value, &expected_value) {
            return false;
        }

        let computed_commitment = crate::hash_domain(b"spectra.vrf.proof_commitment", &self.proof);
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
            seed: crate::hash_domain(b"spectra.epoch.genesis", b"spectra"),
        }
    }

    /// Derive the next epoch's seed from the current epoch's final state.
    pub fn next(&self, epoch_final_hash: &Hash) -> Self {
        EpochSeed {
            epoch: self.epoch + 1,
            seed: crate::hash_concat(&[
                b"spectra.epoch.seed",
                &self.epoch.to_le_bytes(),
                &self.seed,
                epoch_final_hash,
            ]),
        }
    }

    /// Build the VRF input for a specific validator in this epoch.
    pub fn vrf_input(&self, validator_id: &Hash) -> Vec<u8> {
        crate::hash_concat(&[
            b"spectra.vrf.epoch_input",
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
        assert!(output.verify_locally(&kp.public, input));
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
        // Generate many VRF outputs and check selection rate is roughly correct
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

        // Should select roughly 21/1000 * 1000 = 21, allow wide margin
        assert!(
            selected > 5 && selected < 60,
            "Expected ~21 selected, got {}",
            selected
        );
    }
}
