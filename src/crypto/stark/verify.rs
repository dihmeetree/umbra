//! Verification functions for STARK proofs.
//!
//! Wraps winterfell's `verify()` with correct type parameters and
//! deserializes proof bytes into the format needed by the verifier.

use winterfell::crypto::hashers::Rp64_256;
use winterfell::crypto::{DefaultRandomCoin, MerkleTree};
use winterfell::{AcceptableOptions, Proof};

use super::balance_air::BalanceAir;
use super::spend_air::SpendAir;
use super::types::{
    BalancePublicInputs, BalanceStarkProof, SpendPublicInputs, SpendStarkProof, StarkError,
};

/// Minimum conjectured security level (bits) required for proof acceptance.
/// Production proofs must meet 128-bit conjectured security.
/// Minimum conjectured security level in bits.
/// 127 is the maximum achievable with Goldilocks quadratic extension (p^2 ≈ 2^128).
const MIN_SECURITY: u32 = 127;

/// Verify a balance STARK proof.
///
/// Checks that the proof attests to:
/// - All commitment openings are correct
/// - Each proof_link is correctly derived from (commitment, link_nonce)
/// - sum(input_values) == sum(output_values) + fee
pub fn verify_balance_proof(proof: &BalanceStarkProof) -> Result<BalancePublicInputs, StarkError> {
    let pub_inputs = BalancePublicInputs::from_bytes(&proof.public_inputs_bytes)
        .ok_or_else(|| StarkError::DeserializationFailed("invalid balance public inputs".into()))?;

    let stark_proof = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|e| StarkError::DeserializationFailed(e.to_string()))?;

    let acceptable = AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY);

    winterfell::verify::<BalanceAir, Rp64_256, DefaultRandomCoin<Rp64_256>, MerkleTree<Rp64_256>>(
        stark_proof,
        pub_inputs.clone(),
        &acceptable,
    )
    .map_err(|e| StarkError::VerificationFailed(e.to_string()))?;

    Ok(pub_inputs)
}

/// Verify a spend STARK proof.
///
/// Checks that the proof attests to:
/// - Nullifier is correctly derived
/// - Commitment exists in the Merkle tree with the given root
/// - Proof link is correctly derived from (commitment, link_nonce)
pub fn verify_spend_proof(proof: &SpendStarkProof) -> Result<SpendPublicInputs, StarkError> {
    let pub_inputs = SpendPublicInputs::from_bytes(&proof.public_inputs_bytes)
        .ok_or_else(|| StarkError::DeserializationFailed("invalid spend public inputs".into()))?;

    let stark_proof = Proof::from_bytes(&proof.proof_bytes)
        .map_err(|e| StarkError::DeserializationFailed(e.to_string()))?;

    let acceptable = AcceptableOptions::MinConjecturedSecurity(MIN_SECURITY);

    winterfell::verify::<SpendAir, Rp64_256, DefaultRandomCoin<Rp64_256>, MerkleTree<Rp64_256>>(
        stark_proof,
        pub_inputs.clone(),
        &acceptable,
    )
    .map_err(|e| StarkError::VerificationFailed(e.to_string()))?;

    Ok(pub_inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::stark::balance_prover::prove_balance;
    use crate::crypto::stark::convert::Felt;
    use crate::crypto::stark::rescue;
    use crate::crypto::stark::spend_prover::prove_spend;
    use crate::crypto::stark::types::{BalanceWitness, SpendWitness};
    use winterfell::math::FieldElement;

    fn test_proof_options() -> winterfell::ProofOptions {
        // Quadratic extension gives 128-bit field security (64 × 2).
        // 42 queries × log2(8) + 10 grinding bits → comfortably ≥ 128-bit conjectured.
        winterfell::ProofOptions::new(
            42, // num_queries
            8,  // blowup_factor
            10, // grinding_factor
            winterfell::FieldExtension::Quadratic,
            8,
            255,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        )
    }

    /// Helper: compute commitment and proof_link for a balance test input.
    fn make_input_proof_link(
        value: u64,
        blinding: &[Felt; 4],
        link_nonce: &[Felt; 4],
    ) -> [Felt; 4] {
        let commitment = rescue::hash_commitment(Felt::new(value), blinding);
        rescue::hash_proof_link(&commitment, link_nonce)
    }

    #[test]
    fn balance_prove_verify_roundtrip() {
        // 2 inputs, 2 outputs, fee = 5
        let input_values = vec![100u64, 200];
        let output_values = vec![150u64, 145];
        let fee = 5u64;

        let input_blindings = vec![
            [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)],
            [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)],
        ];
        let output_blindings = vec![
            [Felt::new(9), Felt::new(10), Felt::new(11), Felt::new(12)],
            [Felt::new(13), Felt::new(14), Felt::new(15), Felt::new(16)],
        ];

        let input_link_nonces = vec![
            [
                Felt::new(101),
                Felt::new(102),
                Felt::new(103),
                Felt::new(104),
            ],
            [
                Felt::new(201),
                Felt::new(202),
                Felt::new(203),
                Felt::new(204),
            ],
        ];

        // Compute proof_links
        let input_proof_links: Vec<[Felt; 4]> = input_values
            .iter()
            .zip(input_blindings.iter())
            .zip(input_link_nonces.iter())
            .map(|((v, b), n)| make_input_proof_link(*v, b, n))
            .collect();
        let output_commitments: Vec<[Felt; 4]> = output_values
            .iter()
            .zip(output_blindings.iter())
            .map(|(v, b)| rescue::hash_commitment(Felt::new(*v), b))
            .collect();

        let pub_inputs = BalancePublicInputs {
            input_proof_links,
            output_commitments,
            fee: Felt::new(fee),
            tx_content_hash: [Felt::ZERO; 4],
        };
        let witness = BalanceWitness {
            input_values,
            input_blindings,
            input_link_nonces,
            output_values,
            output_blindings,
        };

        let proof = prove_balance(&witness, &pub_inputs, test_proof_options())
            .expect("balance proving failed");

        assert!(!proof.proof_bytes.is_empty());

        let verified = verify_balance_proof(&proof).expect("balance verification failed");
        assert_eq!(verified.fee.as_int(), fee);
    }

    #[test]
    fn balance_proof_rejects_value_exceeding_range() {
        let over_limit = (1u64 << 59) + 1; // exceeds RANGE_BITS limit
        let output_val = over_limit - 5;

        let input_blindings = vec![[Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]];
        let output_blindings = vec![[Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]];
        let input_link_nonces = vec![[Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]];

        let input_proof_links = vec![make_input_proof_link(
            over_limit,
            &input_blindings[0],
            &input_link_nonces[0],
        )];
        let output_commitments = vec![rescue::hash_commitment(
            Felt::new(output_val),
            &output_blindings[0],
        )];

        let pub_inputs = BalancePublicInputs {
            input_proof_links,
            output_commitments,
            fee: Felt::new(5),
            tx_content_hash: [Felt::ZERO; 4],
        };
        let witness = BalanceWitness {
            input_values: vec![over_limit],
            input_blindings,
            input_link_nonces,
            output_values: vec![output_val],
            output_blindings,
        };

        let result = prove_balance(&witness, &pub_inputs, test_proof_options());
        assert!(result.is_err(), "should reject input value >= 2^59");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds range limit"),
            "error should mention range limit, got: {err}"
        );
    }

    #[test]
    fn balance_proof_accepts_max_range_value() {
        // 2^59 - 1 is the maximum allowed value
        let max_val = (1u64 << 59) - 1;
        let fee = 5u64;
        let output_val = max_val - fee;

        let input_blindings = vec![[Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]];
        let output_blindings = vec![[Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]];
        let input_link_nonces = vec![[Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]];

        let input_proof_links = vec![make_input_proof_link(
            max_val,
            &input_blindings[0],
            &input_link_nonces[0],
        )];
        let output_commitments = vec![rescue::hash_commitment(
            Felt::new(output_val),
            &output_blindings[0],
        )];

        let pub_inputs = BalancePublicInputs {
            input_proof_links,
            output_commitments,
            fee: Felt::new(fee),
            tx_content_hash: [Felt::ZERO; 4],
        };
        let witness = BalanceWitness {
            input_values: vec![max_val],
            input_blindings,
            input_link_nonces,
            output_values: vec![output_val],
            output_blindings,
        };

        // Should succeed — max_val is within range
        let proof = prove_balance(&witness, &pub_inputs, test_proof_options())
            .expect("max range value should be accepted");
        let verified = verify_balance_proof(&proof).expect("verification should succeed");
        assert_eq!(verified.fee.as_int(), fee);
    }

    #[test]
    fn balance_proof_transplant_rejected() {
        // Generate a valid proof for one set of commitments, then try to
        // verify it with different tx_content_hash — should fail verification.
        let input_values = vec![100u64];
        let output_values = vec![95u64];
        let fee = 5u64;

        let input_blindings = vec![[Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]];
        let output_blindings = vec![[Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]];
        let input_link_nonces = vec![[Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]];

        let input_proof_links: Vec<[Felt; 4]> = input_values
            .iter()
            .zip(input_blindings.iter())
            .zip(input_link_nonces.iter())
            .map(|((v, b), n)| make_input_proof_link(*v, b, n))
            .collect();
        let output_commitments: Vec<[Felt; 4]> = output_values
            .iter()
            .zip(output_blindings.iter())
            .map(|(v, b)| rescue::hash_commitment(Felt::new(*v), b))
            .collect();

        // Prove with tx_content_hash A
        let pub_inputs_a = BalancePublicInputs {
            input_proof_links: input_proof_links.clone(),
            output_commitments: output_commitments.clone(),
            fee: Felt::new(fee),
            tx_content_hash: [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)],
        };
        let witness = BalanceWitness {
            input_values,
            input_blindings,
            input_link_nonces,
            output_values,
            output_blindings,
        };

        let proof_a = prove_balance(&witness, &pub_inputs_a, test_proof_options())
            .expect("proving should succeed");

        // Tamper: replace the serialized public inputs with tx_content_hash B
        let pub_inputs_b = BalancePublicInputs {
            input_proof_links,
            output_commitments,
            fee: Felt::new(fee),
            tx_content_hash: [Felt::new(99), Felt::new(99), Felt::new(99), Felt::new(99)],
        };
        let tampered_proof = BalanceStarkProof {
            proof_bytes: proof_a.proof_bytes.clone(),
            public_inputs_bytes: pub_inputs_b.to_bytes(),
        };

        // Verification should fail: the proof was generated for hash A
        // but now claims hash B
        let result = verify_balance_proof(&tampered_proof);
        assert!(
            result.is_err(),
            "transplanted proof should fail verification"
        );
    }

    #[test]
    fn balance_proof_rejects_wrong_fee() {
        let input_values = vec![100u64];
        let output_values = vec![90u64];
        let fee = 5u64; // wrong: should be 10

        let input_blindings = vec![[Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]];
        let output_blindings = vec![[Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]];
        let input_link_nonces = vec![[Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]];

        let input_proof_links: Vec<[Felt; 4]> = input_values
            .iter()
            .zip(input_blindings.iter())
            .zip(input_link_nonces.iter())
            .map(|((v, b), n)| make_input_proof_link(*v, b, n))
            .collect();
        let output_commitments: Vec<[Felt; 4]> = output_values
            .iter()
            .zip(output_blindings.iter())
            .map(|(v, b)| rescue::hash_commitment(Felt::new(*v), b))
            .collect();

        let pub_inputs = BalancePublicInputs {
            input_proof_links,
            output_commitments,
            fee: Felt::new(fee),
            tx_content_hash: [Felt::ZERO; 4],
        };
        let witness = BalanceWitness {
            input_values,
            input_blindings,
            input_link_nonces,
            output_values,
            output_blindings,
        };

        // Should fail in witness validation (balance mismatch)
        let result = prove_balance(&witness, &pub_inputs, test_proof_options());
        assert!(result.is_err());
    }

    #[test]
    fn spend_prove_verify_roundtrip() {
        let spend_auth = [
            Felt::new(100),
            Felt::new(200),
            Felt::new(300),
            Felt::new(400),
        ];
        let commitment = [Felt::new(42), Felt::new(43), Felt::new(44), Felt::new(45)];
        let nullifier = rescue::hash_nullifier(&spend_auth, &commitment);
        let link_nonce = [
            Felt::new(500),
            Felt::new(600),
            Felt::new(700),
            Felt::new(800),
        ];
        let proof_link = rescue::hash_proof_link(&commitment, &link_nonce);

        // Build a fake Merkle tree of depth 20
        let mut current = commitment;
        let mut path = Vec::with_capacity(20);
        for level in 0..20 {
            let sibling = [
                Felt::new((level * 4 + 1000) as u64),
                Felt::new((level * 4 + 1001) as u64),
                Felt::new((level * 4 + 1002) as u64),
                Felt::new((level * 4 + 1003) as u64),
            ];
            let is_right = level % 2 == 0; // alternate sides
            path.push((sibling, is_right));
            if is_right {
                current = rescue::hash_merge(&sibling, &current);
            } else {
                current = rescue::hash_merge(&current, &sibling);
            }
        }
        let merkle_root = current;
        let first_path_bit = if path[0].1 { Felt::ONE } else { Felt::ZERO };

        let pub_inputs = SpendPublicInputs {
            merkle_root,
            nullifier,
            proof_link,
            first_path_bit,
        };
        let witness = SpendWitness {
            spend_auth,
            commitment,
            link_nonce,
            merkle_path: path,
        };

        let proof =
            prove_spend(&witness, &pub_inputs, test_proof_options()).expect("spend proving failed");

        assert!(!proof.proof_bytes.is_empty());

        let verified = verify_spend_proof(&proof).expect("spend verification failed");
        assert_eq!(verified.nullifier, nullifier);
        assert_eq!(verified.merkle_root, merkle_root);
        assert_eq!(verified.proof_link, proof_link);
    }
}
