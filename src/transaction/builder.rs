//! Transaction builder for constructing valid Umbra transactions.
//!
//! Usage:
//! ```ignore
//! let tx = TransactionBuilder::new()
//!     .add_input(input_spec)
//!     .add_output(recipient_kem_pk, amount)
//!     .add_message(recipient_kem_pk, "hello from umbra!")
//!     .build()?;
//! ```
//!
//! For Transfer transactions, the fee is auto-computed from the transaction shape:
//!   fee = FEE_BASE + num_inputs * FEE_PER_INPUT
//!         + ceil(message_bytes / 1024) * FEE_PER_MESSAGE_KB
//!
//! For validator transactions (register/deregister), call `.set_fee(amount)` explicitly.

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
use crate::transaction::{
    compute_tx_content_hash, Transaction, TxInput, TxMessage, TxOutput, TxType,
};
use crate::Hash;
use rand::RngExt;

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
    tx_type: TxType,
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
            tx_type: TxType::Transfer,
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

    /// Set the transaction type (validator register/deregister).
    pub fn set_tx_type(mut self, tx_type: TxType) -> Self {
        self.tx_type = tx_type;
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

        // Enforce MAX_TX_IO limits early to give clear errors
        if self.inputs.len() > crate::constants::MAX_TX_IO {
            return Err(TxBuildError::TooManyInputs);
        }
        if self.outputs.len() > crate::constants::MAX_TX_IO {
            return Err(TxBuildError::TooManyOutputs);
        }

        // Build encrypted messages early — needed to compute deterministic fee
        let mut tx_messages = Vec::with_capacity(self.messages.len());
        for msg_spec in &self.messages {
            let payload =
                EncryptedPayload::encrypt(&msg_spec.recipient_kem_pk, &msg_spec.plaintext)
                    .ok_or(TxBuildError::EncryptionFailed)?;
            tx_messages.push(TxMessage { payload });
        }

        // Compute the fee for this transaction
        let fee = match &self.tx_type {
            TxType::Transfer => {
                // Deterministic: computed from transaction shape
                let message_bytes: usize =
                    tx_messages.iter().map(|m| m.payload.ciphertext.len()).sum();
                crate::constants::compute_weight_fee(self.inputs.len(), message_bytes)
            }
            _ => {
                // Validator register/deregister: explicit fee required
                if self.fee == 0 {
                    return Err(TxBuildError::FeeRequired);
                }
                self.fee
            }
        };

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
            .checked_add(fee)
            .ok_or(TxBuildError::ArithmeticOverflow)?;
        if input_sum != total_out {
            return Err(TxBuildError::Imbalanced {
                inputs: input_sum,
                outputs: output_sum,
                fee,
            });
        }

        // Build inputs: derive nullifiers, compute proof_links, generate STARK spend proofs
        let mut rng = rand::rng();
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

            // Generate random link_nonce and compute proof_link
            let link_nonce: [Felt; 4] = [
                Felt::new(rng.random::<u64>()),
                Felt::new(rng.random::<u64>()),
                Felt::new(rng.random::<u64>()),
                Felt::new(rng.random::<u64>()),
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

        // Compute tx_content_hash over all non-proof content fields
        let tx_content_hash = compute_tx_content_hash(
            &tx_inputs,
            &tx_outputs,
            &tx_messages,
            fee,
            &self.chain_id,
            self.expiry_epoch,
            &self.tx_type,
        );

        // Generate STARK balance proof
        let output_commitments_felts: Vec<_> =
            tx_outputs.iter().map(|o| o.commitment.to_felts()).collect();

        let balance_pub = BalancePublicInputs {
            input_proof_links: input_proof_links_felts,
            output_commitments: output_commitments_felts,
            fee: Felt::new(fee),
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
            fee,
            chain_id: self.chain_id,
            expiry_epoch: self.expiry_epoch,
            balance_proof,
            messages: tx_messages,
            tx_binding: tx_content_hash,
            tx_type: self.tx_type,
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
    #[error("too many inputs (max {})", crate::constants::MAX_TX_IO)]
    TooManyInputs,
    #[error("too many outputs (max {})", crate::constants::MAX_TX_IO)]
    TooManyOutputs,
    #[error("fee must be set explicitly for validator transactions")]
    FeeRequired,
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
            winterfell::FieldExtension::Cubic,
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

        // 1 input, 1 output, no messages → fee = 100 + 100 = 200
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1100,
                blinding: input_blinding,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 900)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.fee, 200);
        assert_ne!(tx.chain_id, [0u8; 32]);
        assert_eq!(tx.expiry_epoch, 0);
        assert_eq!(tx.tx_binding, tx.tx_content_hash());
    }

    #[test]
    fn build_transaction_with_message() {
        let recipient = FullKeypair::generate();

        let input_blinding = BlindingFactor::random();
        let spend_auth = crate::hash_domain(b"test.spend_auth", b"secret");

        // 1 input, 1 output, 1 message (45 bytes plaintext → 64 bytes ciphertext)
        // fee = 100 + 100 + ceil(64/1024)*10 = 210
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 610,
                blinding: input_blinding,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 400)
            .add_message(
                recipient.kem.public.clone(),
                b"Hello from Umbra! This is a private message.".to_vec(),
            )
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        assert_eq!(tx.messages.len(), 1);

        // Recipient can decrypt the message
        let decrypted = tx.messages[0].payload.decrypt(&recipient.kem).unwrap();
        assert_eq!(decrypted, b"Hello from Umbra! This is a private message.");
    }

    #[test]
    fn build_imbalanced_fails() {
        let recipient = FullKeypair::generate();

        // 1 input, 1 output, no messages → auto fee = 200
        // input=100, output=200 → 100 != 200 + 200 → Imbalanced
        let result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 100,
                blinding: BlindingFactor::random(),
                spend_auth: [0u8; 32],
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 200)
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

    #[test]
    fn build_with_chain_id_and_expiry() {
        let recipient = FullKeypair::generate();
        let chain_id = crate::hash_domain(b"test.chain", b"my-chain");
        // 1 input, 1 output, no messages → fee = 200
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 600,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 400)
            .set_chain_id(chain_id)
            .set_expiry_epoch(42)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        assert_eq!(tx.chain_id, chain_id);
        assert_eq!(tx.expiry_epoch, 42);
    }

    #[test]
    fn build_multi_input_multi_output() {
        let r1 = FullKeypair::generate();
        let r2 = FullKeypair::generate();
        // 2 inputs, 2 outputs, no messages → fee = 100 + 200 = 300
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 800,
                blinding: BlindingFactor::from_bytes([1u8; 32]),
                spend_auth: crate::hash_domain(b"test", b"auth1"),
                merkle_path: vec![],
            })
            .add_input(InputSpec {
                value: 600,
                blinding: BlindingFactor::from_bytes([2u8; 32]),
                spend_auth: crate::hash_domain(b"test", b"auth2"),
                merkle_path: vec![],
            })
            .add_output(r1.kem.public.clone(), 600)
            .add_output(r2.kem.public.clone(), 500)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.fee, 300);
    }

    #[test]
    fn build_rejects_too_many_inputs() {
        let recipient = FullKeypair::generate();
        let mut builder = TransactionBuilder::new();
        let total_value = (crate::constants::MAX_TX_IO as u64 + 1) * 100;
        for i in 0..=crate::constants::MAX_TX_IO {
            builder = builder.add_input(InputSpec {
                value: 100,
                blinding: BlindingFactor::from_bytes([i as u8; 32]),
                spend_auth: crate::hash_domain(b"test", &[i as u8]),
                merkle_path: vec![],
            });
        }
        builder = builder
            .add_output(recipient.kem.public.clone(), total_value - 10)
            .set_proof_options(test_proof_options());
        let result = builder.build();
        assert!(matches!(result, Err(TxBuildError::TooManyInputs)));
    }

    #[test]
    fn build_rejects_too_many_outputs() {
        let mut builder = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 100_000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .set_proof_options(test_proof_options());
        let per_output = (100_000 - 10) / (crate::constants::MAX_TX_IO as u64 + 1);
        for _ in 0..=crate::constants::MAX_TX_IO {
            let r = FullKeypair::generate();
            builder = builder.add_output(r.kem.public.clone(), per_output);
        }
        let result = builder.build();
        assert!(matches!(result, Err(TxBuildError::TooManyOutputs)));
    }

    #[test]
    fn builder_auto_computes_fee() {
        // 1 input, 1 output, no messages → fee = 100 + 100 = 200
        let recipient = crate::crypto::keys::FullKeypair::generate();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"fee-auto"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 800)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        assert_eq!(tx.fee, 200);

        // 1 input, 2 outputs, no messages → fee still 200 (output count excluded)
        let recipient2 = crate::crypto::keys::FullKeypair::generate();
        let tx2 = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"fee-auto-2"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 400)
            .add_output(recipient2.kem.public.clone(), 400)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        assert_eq!(tx2.fee, 200);
    }

    #[test]
    fn build_rejects_input_sum_overflow() {
        let recipient = FullKeypair::generate();
        let result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: u64::MAX,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"overflow1"),
                merkle_path: vec![],
            })
            .add_input(InputSpec {
                value: 1,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"overflow2"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 100)
            .set_proof_options(test_proof_options())
            .build();
        assert!(
            matches!(result, Err(TxBuildError::ArithmeticOverflow)),
            "expected ArithmeticOverflow, got {:?}",
            result
        );
    }

    #[test]
    fn build_rejects_output_sum_overflow() {
        let r1 = FullKeypair::generate();
        let r2 = FullKeypair::generate();
        let result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 100,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"overflow-out"),
                merkle_path: vec![],
            })
            .add_output(r1.kem.public.clone(), u64::MAX)
            .add_output(r2.kem.public.clone(), 1)
            .set_proof_options(test_proof_options())
            .build();
        assert!(
            matches!(result, Err(TxBuildError::ArithmeticOverflow)),
            "expected ArithmeticOverflow, got {:?}",
            result
        );
    }

    #[test]
    fn encode_note_format() {
        let value = 0x0102030405060708u64;
        let blinding = BlindingFactor::from_bytes([0xAB; 32]);
        let encoded = encode_note(value, &blinding);
        assert_eq!(
            encoded.len(),
            40,
            "encode_note must produce exactly 40 bytes"
        );
        // First 8 bytes: value in little-endian
        assert_eq!(&encoded[..8], &value.to_le_bytes());
        // Next 32 bytes: blinding factor
        assert_eq!(&encoded[8..40], &[0xAB; 32]);
    }

    #[test]
    fn builder_set_tx_type_validator_register() {
        use crate::crypto::keys::{KemKeypair, SigningKeypair};
        use crate::transaction::TxType;

        let signing_kp = SigningKeypair::generate();
        let kem_kp = KemKeypair::generate();

        // fee = VALIDATOR_BASE_BOND + MIN_TX_FEE = 1_000_001
        // input = output + fee = 100 + 1_000_001 = 1_000_101
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1_000_101,
                blinding: crate::crypto::commitment::BlindingFactor::from_bytes([230; 32]),
                spend_auth: crate::hash_domain(b"test", &[230]),
                merkle_path: vec![],
            })
            .add_output(kem_kp.public.clone(), 100)
            .set_tx_type(TxType::ValidatorRegister {
                signing_key: signing_kp.public.clone(),
                kem_public_key: kem_kp.public.clone(),
            })
            .set_fee(1_000_001) // VALIDATOR_BASE_BOND + MIN_TX_FEE
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        assert!(matches!(tx.tx_type, TxType::ValidatorRegister { .. }));
    }

    #[test]
    fn builder_default_creates_transfer() {
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 300,
                blinding: crate::crypto::commitment::BlindingFactor::from_bytes([231; 32]),
                spend_auth: crate::hash_domain(b"test", &[231]),
                merkle_path: vec![],
            })
            .add_output(
                crate::crypto::keys::FullKeypair::generate()
                    .kem
                    .public
                    .clone(),
                100,
            )
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        assert!(matches!(tx.tx_type, crate::transaction::TxType::Transfer));
    }

    #[test]
    fn note_encode_decode_boundary_values() {
        use crate::crypto::commitment::BlindingFactor;

        // Max u64 value
        let blinding = BlindingFactor::from_bytes([0xFF; 32]);
        let encoded = encode_note(u64::MAX, &blinding);
        let (value, restored) = decode_note(&encoded).unwrap();
        assert_eq!(value, u64::MAX);
        assert_eq!(restored.0, blinding.0);

        // Zero value
        let blinding_zero = BlindingFactor::from_bytes([0; 32]);
        let encoded = encode_note(0, &blinding_zero);
        let (value, restored) = decode_note(&encoded).unwrap();
        assert_eq!(value, 0);
        assert_eq!(restored.0, blinding_zero.0);
    }
}
