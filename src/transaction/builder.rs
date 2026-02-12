//! Transaction builder for constructing valid Spectra transactions.
//!
//! Usage:
//! ```ignore
//! let tx = TransactionBuilder::new()
//!     .add_input(input_spec)
//!     .add_output(recipient_kem_pk, amount)
//!     .add_message(recipient_kem_pk, "hello from spectra!")
//!     .set_fee(100)
//!     .build()?;
//! ```

use rand::Rng;
use winterfell::math::FieldElement;

use crate::crypto::commitment::{BlindingFactor, Commitment};
use crate::crypto::encryption::EncryptedPayload;
use crate::crypto::keys::KemPublicKey;
use crate::crypto::nullifier::Nullifier;
use crate::crypto::proof::{pad_merkle_path, path_to_stark_witness, MerkleNode};
use crate::crypto::stark::convert::{felts_to_hash, hash_to_felts, Felt};
use crate::crypto::stark::rescue;
use crate::crypto::stark::spend_air::MERKLE_DEPTH;
use crate::crypto::stark::types::{
    BalancePublicInputs, BalanceWitness, SpendPublicInputs, SpendWitness,
};
use crate::crypto::stark::{default_proof_options, prove_balance, prove_spend};
use crate::crypto::stealth::StealthAddress;
use crate::transaction::*;
use crate::Hash;

/// An input to be spent, with its secret witness data.
pub struct InputSpec {
    pub value: u64,
    pub blinding: BlindingFactor,
    pub spend_auth: Hash,
    /// Merkle path from commitment leaf to root (variable depth, will be padded to 20)
    pub merkle_path: Vec<MerkleNode>,
}

/// An output to be created.
pub struct OutputSpec {
    pub recipient_kem_pk: KemPublicKey,
    pub value: u64,
}

/// A message to attach to the transaction.
///
/// Any routing tags should be included inside the plaintext (e.g., as a
/// prefix) so they remain encrypted and invisible to observers.
pub struct MessageSpec {
    pub recipient_kem_pk: KemPublicKey,
    pub plaintext: Vec<u8>,
}

/// Builder for constructing transactions.
pub struct TransactionBuilder {
    inputs: Vec<InputSpec>,
    outputs: Vec<OutputSpec>,
    messages: Vec<MessageSpec>,
    fee: u64,
    chain_id: Hash,
    expiry_epoch: u64,
    proof_options: Option<winterfell::ProofOptions>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        TransactionBuilder {
            inputs: Vec::new(),
            outputs: Vec::new(),
            messages: Vec::new(),
            fee: 0,
            chain_id: crate::constants::chain_id(),
            expiry_epoch: 0,
            proof_options: None,
        }
    }

    /// Add an input to spend.
    pub fn add_input(mut self, input: InputSpec) -> Self {
        self.inputs.push(input);
        self
    }

    /// Add an output (payment to a recipient).
    pub fn add_output(mut self, recipient_kem_pk: KemPublicKey, value: u64) -> Self {
        self.outputs.push(OutputSpec {
            recipient_kem_pk,
            value,
        });
        self
    }

    /// Add an encrypted message to the transaction.
    ///
    /// Any routing tags should be included inside the plaintext to keep
    /// them encrypted (e.g., prepend a tag string before the message body).
    pub fn add_message(mut self, recipient_kem_pk: KemPublicKey, plaintext: Vec<u8>) -> Self {
        self.messages.push(MessageSpec {
            recipient_kem_pk,
            plaintext,
        });
        self
    }

    /// Set the transaction fee.
    pub fn set_fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    /// Set the chain ID (defaults to mainnet).
    pub fn set_chain_id(mut self, chain_id: Hash) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Set the expiry epoch (0 = no expiry).
    pub fn set_expiry_epoch(mut self, expiry_epoch: u64) -> Self {
        self.expiry_epoch = expiry_epoch;
        self
    }

    /// Override proof options (for testing with lighter parameters).
    pub fn set_proof_options(mut self, opts: winterfell::ProofOptions) -> Self {
        self.proof_options = Some(opts);
        self
    }

    /// Build the transaction.
    ///
    /// Build order:
    /// 1. Validate balance (inputs == outputs + fee)
    /// 2. Build inputs (nullifiers + proof_links + STARK spend proofs)
    /// 3. Build outputs (commitments + stealth + encrypted notes)
    /// 4. Build messages
    /// 5. Compute tx_content_hash (binds all non-proof content)
    /// 6. Generate STARK balance proof (bound to tx_content_hash)
    /// 7. Set tx_binding = tx_content_hash
    pub fn build(self) -> Result<Transaction, TxBuildError> {
        let proof_opts = self.proof_options.unwrap_or_else(default_proof_options);

        // Validate balance with checked arithmetic
        let input_sum: u64 = self
            .inputs
            .iter()
            .try_fold(0u64, |acc, i| acc.checked_add(i.value))
            .ok_or(TxBuildError::ArithmeticOverflow)?;
        let output_sum: u64 = self
            .outputs
            .iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.value))
            .ok_or(TxBuildError::ArithmeticOverflow)?;
        let total_out = output_sum
            .checked_add(self.fee)
            .ok_or(TxBuildError::ArithmeticOverflow)?;
        if input_sum != total_out {
            return Err(TxBuildError::Imbalanced {
                inputs: input_sum,
                outputs: output_sum,
                fee: self.fee,
            });
        }

        // Build inputs: derive nullifiers, compute proof_links, generate STARK spend proofs
        let mut rng = rand::thread_rng();
        let mut tx_inputs = Vec::with_capacity(self.inputs.len());
        let mut input_values = Vec::with_capacity(self.inputs.len());
        let mut input_blindings_felts = Vec::with_capacity(self.inputs.len());
        let mut input_proof_links_felts = Vec::with_capacity(self.inputs.len());
        let mut input_link_nonces = Vec::with_capacity(self.inputs.len());

        for spec in &self.inputs {
            let commitment = Commitment::commit(spec.value, &spec.blinding);
            let nullifier = Nullifier::derive(&spec.spend_auth, &commitment.0);

            // Pad Merkle path to depth 20 for STARK
            let padded_path = pad_merkle_path(&spec.merkle_path, MERKLE_DEPTH);
            let stark_path = path_to_stark_witness(&padded_path);

            let commitment_felts = commitment.to_felts();
            let spend_auth_felts = hash_to_felts(&spec.spend_auth);
            let first_path_bit = if stark_path[0].1 {
                Felt::ONE
            } else {
                Felt::ZERO
            };

            // Generate random link_nonce and compute proof_link
            let link_nonce: [Felt; 4] = [
                Felt::new(rng.gen::<u64>()),
                Felt::new(rng.gen::<u64>()),
                Felt::new(rng.gen::<u64>()),
                Felt::new(rng.gen::<u64>()),
            ];
            let proof_link_felts = rescue::hash_proof_link(&commitment_felts, &link_nonce);
            let proof_link_hash = felts_to_hash(&proof_link_felts);

            // Compute Merkle root from the padded path
            let merkle_root_hash =
                crate::crypto::proof::compute_merkle_root(&commitment.0, &padded_path);
            let merkle_root_felts = hash_to_felts(&merkle_root_hash);

            let spend_pub = SpendPublicInputs {
                merkle_root: merkle_root_felts,
                nullifier: nullifier.to_felts(),
                proof_link: proof_link_felts,
                first_path_bit,
            };
            let spend_witness = SpendWitness {
                spend_auth: spend_auth_felts,
                commitment: commitment_felts,
                link_nonce,
                merkle_path: stark_path,
            };

            let spend_proof = prove_spend(&spend_witness, &spend_pub, proof_opts.clone()).map_err(
                |e: crate::crypto::stark::types::StarkError| {
                    TxBuildError::SpendProofFailed(e.to_string())
                },
            )?;

            tx_inputs.push(TxInput {
                nullifier,
                proof_link: proof_link_hash,
                spend_proof,
            });
            input_values.push(spec.value);
            input_blindings_felts.push(spec.blinding.to_felts());
            input_proof_links_felts.push(proof_link_felts);
            input_link_nonces.push(link_nonce);
        }

        // Build outputs: generate stealth addresses and encrypt note data
        let mut tx_outputs = Vec::with_capacity(self.outputs.len());
        let mut output_values = Vec::with_capacity(self.outputs.len());
        let mut output_blindings_felts = Vec::with_capacity(self.outputs.len());

        for (idx, spec) in self.outputs.iter().enumerate() {
            let blinding = BlindingFactor::random();
            let commitment = Commitment::commit(spec.value, &blinding);

            // Generate stealth address (returns shared secret for reuse)
            let stealth_result = StealthAddress::generate(&spec.recipient_kem_pk, idx as u32)
                .ok_or(TxBuildError::StealthAddressGeneration)?;
            let stealth_address = stealth_result.address;

            // Encrypt the note data reusing the stealth KEM shared secret
            // (avoids a second KEM encapsulation, reducing output size)
            let note_data = encode_note(spec.value, &blinding);
            let encrypted_note = EncryptedPayload::encrypt_with_shared_secret(
                &stealth_result.shared_secret,
                stealth_address.kem_ciphertext.clone(),
                &note_data,
            )
            .ok_or(TxBuildError::EncryptionFailed)?;

            tx_outputs.push(TxOutput {
                commitment,
                stealth_address,
                encrypted_note,
            });
            output_values.push(spec.value);
            output_blindings_felts.push(blinding.to_felts());
        }

        // Build messages
        let mut tx_messages = Vec::with_capacity(self.messages.len());
        for msg_spec in &self.messages {
            let payload =
                EncryptedPayload::encrypt(&msg_spec.recipient_kem_pk, &msg_spec.plaintext)
                    .ok_or(TxBuildError::EncryptionFailed)?;
            tx_messages.push(TxMessage { payload });
        }

        // Compute tx_content_hash over all non-proof content fields
        let tx_content_hash = compute_tx_content_hash(
            &tx_inputs,
            &tx_outputs,
            &tx_messages,
            self.fee,
            &self.chain_id,
            self.expiry_epoch,
        );

        // Generate STARK balance proof
        let output_commitments_felts: Vec<_> =
            tx_outputs.iter().map(|o| o.commitment.to_felts()).collect();

        let balance_pub = BalancePublicInputs {
            input_proof_links: input_proof_links_felts,
            output_commitments: output_commitments_felts,
            fee: Felt::new(self.fee),
            tx_content_hash: hash_to_felts(&tx_content_hash),
        };
        let balance_witness = BalanceWitness {
            input_values,
            input_blindings: input_blindings_felts,
            input_link_nonces,
            output_values,
            output_blindings: output_blindings_felts,
        };

        let balance_proof = prove_balance(&balance_witness, &balance_pub, proof_opts).map_err(
            |e: crate::crypto::stark::types::StarkError| {
                TxBuildError::BalanceProofFailed(e.to_string())
            },
        )?;

        Ok(Transaction {
            inputs: tx_inputs,
            outputs: tx_outputs,
            fee: self.fee,
            chain_id: self.chain_id,
            expiry_epoch: self.expiry_epoch,
            balance_proof,
            messages: tx_messages,
            tx_binding: tx_content_hash,
        })
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode note data (value + blinding) for encryption.
fn encode_note(value: u64, blinding: &BlindingFactor) -> Vec<u8> {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(&value.to_le_bytes());
    data.extend_from_slice(&blinding.0);
    data
}

/// Decode note data from decrypted bytes.
///
/// Expects exactly 40 bytes (8 bytes value + 32 bytes blinding factor).
/// Rejects payloads of any other length to prevent trailing-data confusion.
pub fn decode_note(data: &[u8]) -> Option<(u64, BlindingFactor)> {
    if data.len() != 40 {
        return None;
    }
    let value = u64::from_le_bytes(data[..8].try_into().ok()?);
    let mut blind_bytes = [0u8; 32];
    blind_bytes.copy_from_slice(&data[8..40]);
    Some((value, BlindingFactor::from_bytes(blind_bytes)))
}

/// Errors during transaction building.
#[derive(Clone, Debug, thiserror::Error)]
pub enum TxBuildError {
    #[error("transaction does not balance: {inputs} inputs != {outputs} outputs + {fee} fee")]
    Imbalanced { inputs: u64, outputs: u64, fee: u64 },
    #[error("failed to generate stealth address")]
    StealthAddressGeneration,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("arithmetic overflow in balance calculation")]
    ArithmeticOverflow,
    #[error("balance proof generation failed: {0}")]
    BalanceProofFailed(String),
    #[error("spend proof generation failed: {0}")]
    SpendProofFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::commitment::BlindingFactor;
    use crate::crypto::keys::FullKeypair;

    fn test_proof_options() -> winterfell::ProofOptions {
        winterfell::ProofOptions::new(
            42,
            8,
            10,
            winterfell::FieldExtension::Quadratic,
            8,
            255,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        )
    }

    #[test]
    fn build_simple_transaction() {
        let recipient = FullKeypair::generate();

        let input_blinding = BlindingFactor::random();
        let spend_auth = crate::hash_domain(b"test.spend_auth", b"sender_secret");

        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: input_blinding,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 900)
            .set_fee(100)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.fee, 100);
        assert_ne!(tx.chain_id, [0u8; 32]);
        assert_eq!(tx.expiry_epoch, 0);
        assert_eq!(tx.tx_binding, tx.tx_content_hash());
    }

    #[test]
    fn build_transaction_with_message() {
        let recipient = FullKeypair::generate();

        let input_blinding = BlindingFactor::random();
        let spend_auth = crate::hash_domain(b"test.spend_auth", b"secret");

        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 500,
                blinding: input_blinding,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 450)
            .add_message(
                recipient.kem.public.clone(),
                b"Hello from Spectra! This is a private message.".to_vec(),
            )
            .set_fee(50)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        assert_eq!(tx.messages.len(), 1);

        // Recipient can decrypt the message
        let decrypted = tx.messages[0].payload.decrypt(&recipient.kem).unwrap();
        assert_eq!(decrypted, b"Hello from Spectra! This is a private message.");
    }

    #[test]
    fn build_imbalanced_fails() {
        let recipient = FullKeypair::generate();

        let result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 100,
                blinding: BlindingFactor::random(),
                spend_auth: [0u8; 32],
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 200)
            .set_fee(10)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn note_encode_decode_roundtrip() {
        let value = 123456789u64;
        let blinding = BlindingFactor::random();
        let encoded = encode_note(value, &blinding);
        let (dec_value, dec_blinding) = decode_note(&encoded).unwrap();
        assert_eq!(dec_value, value);
        assert_eq!(dec_blinding.0, blinding.0);
    }
}
