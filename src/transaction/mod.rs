//! Transaction model for Umbra.
//!
//! Transactions consume inputs (via nullifiers) and produce outputs (via commitments).
//! All amounts are hidden behind commitments. Recipients are unlinkable via stealth
//! addresses.
//!
//! Privacy is enforced by zk-STARK proofs:
//! - **BalanceStarkProof**: proves all commitments open correctly and inputs = outputs + fee
//! - **SpendStarkProof**: proves Merkle membership and nullifier derivation (per input)
//! - No amounts, keys, or Merkle paths are revealed to validators
//!
//! Input commitments are never revealed publicly. Instead, each input publishes a
//! `proof_link = Rescue(commitment, random_nonce)` — a one-way hash that binds the
//! spend proof to the balance proof without revealing which output is being spent.

pub mod builder;

use serde::{Deserialize, Serialize};

use crate::crypto::commitment::Commitment;
use crate::crypto::encryption::EncryptedPayload;
use crate::crypto::keys::{KemPublicKey, Signature, SigningPublicKey};
use crate::crypto::nullifier::Nullifier;
use crate::crypto::stark::convert::hash_to_felts;
use crate::crypto::stark::types::{BalanceStarkProof, SpendStarkProof};
use crate::crypto::stark::verify::{verify_balance_proof, verify_spend_proof};
use crate::crypto::stealth::StealthAddress;
use crate::Hash;

/// A unique transaction identifier (hash of the serialized transaction).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxId(pub Hash);

/// A transaction input: reveals a nullifier and proves the right to spend.
///
/// The actual commitment being spent is a private witness inside the STARK proofs.
/// Only a `proof_link = Rescue(commitment, random_nonce)` is published, which
/// binds the spend proof to the balance proof without revealing which output
/// is being spent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    /// The nullifier marking the spent output
    pub nullifier: Nullifier,
    /// Proof link binding spend proof to balance proof (one-way; hides the commitment)
    pub proof_link: Hash,
    /// zk-STARK proof of valid spend (Merkle membership + nullifier derivation)
    pub spend_proof: SpendStarkProof,
}

/// A transaction output: a new spendable value hidden behind a commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    /// Commitment to the output value
    pub commitment: Commitment,
    /// Stealth address for the recipient
    pub stealth_address: StealthAddress,
    /// Encrypted note data (value + blinding, encrypted to recipient)
    pub encrypted_note: EncryptedPayload,
}

/// An encrypted message attached to a transaction.
///
/// All metadata (including any routing tags) is inside the encrypted payload.
/// No plaintext metadata is exposed to prevent traffic analysis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxMessage {
    /// Encrypted payload (to a specific recipient's KEM key).
    /// The plaintext may contain a tag prefix for application-level routing,
    /// but it is never exposed in cleartext on-chain.
    pub payload: EncryptedPayload,
}

/// Transaction type: regular transfer or validator lifecycle operation.
///
/// Validator operations are carried as regular transactions so the bond can be
/// paid through the fee field without modifying the zk-STARK balance proof.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum TxType {
    /// Regular private value transfer (default).
    #[default]
    Transfer,
    /// Register a new validator. The transaction fee must be at least
    /// `required_validator_bond(n) + MIN_TX_FEE`; the bond portion is escrowed.
    ValidatorRegister {
        /// The validator's Dilithium5 signing public key.
        signing_key: SigningPublicKey,
        /// The validator's Kyber1024 KEM public key (for receiving coinbase rewards).
        kem_public_key: KemPublicKey,
    },
    /// Deregister an active validator and return the bond.
    ValidatorDeregister {
        /// ID (fingerprint) of the validator being deregistered.
        validator_id: Hash,
        /// Signature proving ownership: signs `"umbra.validator.deregister" || chain_id || validator_id || tx_content_hash`.
        auth_signature: Signature,
        /// Output that receives the returned bond (added to commitment tree).
        bond_return_output: Box<TxOutput>,
        /// Blinding factor for the bond return commitment, so the chain can verify
        /// the commitment opens to exactly the escrowed bond amount.
        bond_blinding: [u8; 32],
    },
}

/// A complete Umbra transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction inputs (spent outputs)
    pub inputs: Vec<TxInput>,
    /// Transaction outputs (new spendable values)
    pub outputs: Vec<TxOutput>,
    /// Public fee paid to validators
    pub fee: u64,
    /// Chain identifier (replay protection across forks/chains)
    pub chain_id: Hash,
    /// Transaction expires after this epoch (0 = no expiry)
    pub expiry_epoch: u64,
    /// zk-STARK proof that inputs balance with outputs + fee
    pub balance_proof: BalanceStarkProof,
    /// Optional encrypted messages piggybacked on the transaction
    pub messages: Vec<TxMessage>,
    /// Binding hash over all non-proof fields (prevents tampering)
    pub tx_binding: Hash,
    /// Transaction type (transfer, validator register/deregister)
    #[serde(default)]
    pub tx_type: TxType,
}

impl Transaction {
    /// Compute the transaction ID (hash of all transaction data).
    ///
    /// Includes proof bytes to prevent malleability: replacing proofs with
    /// different valid proofs changes the tx_id, so nodes and mempools can
    /// distinguish the original from the modified version.
    pub fn tx_id(&self) -> TxId {
        let mut hasher = blake3::Hasher::new_derive_key("umbra.txid");
        // Hash all inputs (nullifiers, proof_links, and spend proof bytes)
        for input in &self.inputs {
            hasher.update(&input.nullifier.0);
            hasher.update(&input.proof_link);
            hasher.update(&(input.spend_proof.proof_bytes.len() as u64).to_le_bytes());
            hasher.update(&input.spend_proof.proof_bytes);
            hasher.update(&(input.spend_proof.public_inputs_bytes.len() as u64).to_le_bytes());
            hasher.update(&input.spend_proof.public_inputs_bytes);
        }
        // Hash all outputs
        for output in &self.outputs {
            hasher.update(&output.commitment.0);
            hasher.update(&output.stealth_address.one_time_key);
        }
        // Hash fee, chain_id, expiry
        hasher.update(&self.fee.to_le_bytes());
        hasher.update(&self.chain_id);
        hasher.update(&self.expiry_epoch.to_le_bytes());
        // Hash binding (covers all non-proof content)
        hasher.update(&self.tx_binding);
        // Hash balance proof bytes
        hasher.update(&(self.balance_proof.proof_bytes.len() as u64).to_le_bytes());
        hasher.update(&self.balance_proof.proof_bytes);
        hasher.update(&(self.balance_proof.public_inputs_bytes.len() as u64).to_le_bytes());
        hasher.update(&self.balance_proof.public_inputs_bytes);
        // Hash tx_type discriminant
        hash_tx_type_into(&self.tx_type, &mut hasher);
        TxId(*hasher.finalize().as_bytes())
    }

    /// Compute the content hash of all non-proof fields.
    ///
    /// This hash is included in proof challenges to bind proofs to the
    /// specific transaction content, preventing proof transplant attacks.
    pub fn tx_content_hash(&self) -> Hash {
        compute_tx_content_hash(
            &self.inputs,
            &self.outputs,
            &self.messages,
            self.fee,
            &self.chain_id,
            self.expiry_epoch,
            &self.tx_type,
        )
    }

    /// Validate transaction structure (not state-dependent checks).
    ///
    /// Verifies all zk-STARK proofs and checks consistency between proofs
    /// and transaction fields. Does NOT check Merkle root against state
    /// (that's done in state.rs).
    ///
    /// `current_epoch`: the current epoch for expiry checks. Pass 0 to skip
    /// expiry validation (e.g., when epoch is unknown during initial sync).
    pub fn validate_structure(&self, current_epoch: u64) -> Result<(), TxValidationError> {
        if self.inputs.is_empty() {
            return Err(TxValidationError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(TxValidationError::NoOutputs);
        }
        if self.inputs.len() > crate::constants::MAX_TX_IO {
            return Err(TxValidationError::TooManyInputs);
        }
        if self.outputs.len() > crate::constants::MAX_TX_IO {
            return Err(TxValidationError::TooManyOutputs);
        }
        if self.messages.len() > crate::constants::MAX_MESSAGES_PER_TX {
            return Err(TxValidationError::TooManyMessages);
        }

        // Enforce minimum fee to prevent zero-fee spam
        if self.fee < crate::constants::MIN_TX_FEE {
            return Err(TxValidationError::FeeTooLow);
        }
        // Enforce maximum fee to prevent fee-saturation attacks
        if self.fee > crate::constants::MAX_TX_FEE {
            return Err(TxValidationError::FeeTooHigh);
        }

        // Transaction-type-specific validation
        match &self.tx_type {
            TxType::Transfer => {}
            TxType::ValidatorRegister {
                signing_key,
                kem_public_key,
            } => {
                // Early check: fee must at least cover the base bond + MIN_TX_FEE.
                // The actual required bond (which scales with active validator count)
                // is checked in state validation (validate_transaction in state.rs).
                let min_fee = crate::constants::VALIDATOR_BASE_BOND
                    .saturating_add(crate::constants::MIN_TX_FEE);
                if self.fee < min_fee {
                    return Err(TxValidationError::InsufficientBond);
                }
                // Signing key must have the correct Dilithium5 size (2592 bytes)
                if !signing_key.is_valid_size() {
                    return Err(TxValidationError::InvalidValidatorKey);
                }
                // KEM key must have the correct Kyber1024 size (1568 bytes)
                if !kem_public_key.is_valid_size() {
                    return Err(TxValidationError::InvalidValidatorKey);
                }
            }
            TxType::ValidatorDeregister {
                bond_return_output, ..
            } => {
                // Bond return output must have a non-zero commitment
                if bond_return_output.commitment.0 == [0u8; 32] {
                    return Err(TxValidationError::InvalidBondReturn);
                }
            }
        }

        // Enforce transaction expiry
        if self.expiry_epoch > 0 && current_epoch > 0 && current_epoch > self.expiry_epoch {
            return Err(TxValidationError::Expired);
        }

        // Check for duplicate nullifiers within the transaction
        let mut seen_nullifiers = std::collections::HashSet::new();
        for input in &self.inputs {
            if !seen_nullifiers.insert(input.nullifier) {
                return Err(TxValidationError::DuplicateNullifier);
            }
        }

        // Check for duplicate output commitments within the transaction.
        // A malicious tx could include the same output commitment twice,
        // which would allow double-claiming in the commitment tree.
        let mut seen_commitments = std::collections::HashSet::new();
        for output in &self.outputs {
            if !seen_commitments.insert(output.commitment) {
                return Err(TxValidationError::DuplicateOutputCommitment);
            }
        }

        // Verify tx_binding matches the content hash
        let expected_binding = self.tx_content_hash();
        if !crate::constant_time_eq(&self.tx_binding, &expected_binding) {
            return Err(TxValidationError::InvalidBinding);
        }

        // Verify balance proof (zk-STARK)
        let balance_pub = verify_balance_proof(&self.balance_proof)
            .map_err(|e| TxValidationError::InvalidBalanceProof(e.to_string()))?;

        // Check balance proof public inputs match transaction
        let input_proof_links_felts: Vec<_> = self
            .inputs
            .iter()
            .map(|i| hash_to_felts(&i.proof_link))
            .collect();
        let output_commitments_felts: Vec<_> = self
            .outputs
            .iter()
            .map(|o| o.commitment.to_felts())
            .collect();

        if balance_pub.input_proof_links != input_proof_links_felts {
            return Err(TxValidationError::InvalidBalanceProof(
                "input proof_links mismatch".into(),
            ));
        }
        if balance_pub.output_commitments != output_commitments_felts {
            return Err(TxValidationError::InvalidBalanceProof(
                "output commitments mismatch".into(),
            ));
        }
        if balance_pub.fee.as_int() != self.fee {
            return Err(TxValidationError::InvalidBalanceProof(
                "fee mismatch".into(),
            ));
        }

        // Verify tx_content_hash in balance proof matches the transaction's actual content hash.
        // This prevents proof transplant attacks: a balance proof generated for transaction A
        // cannot be reused in transaction B (even if commitments and fee are identical).
        let expected_tx_hash = crate::crypto::stark::convert::hash_to_felts(&expected_binding);
        if balance_pub.tx_content_hash != expected_tx_hash {
            return Err(TxValidationError::InvalidBalanceProof(
                "tx_content_hash mismatch (proof transplant rejected)".into(),
            ));
        }

        // Verify each spend proof (zk-STARK)
        for (i, input) in self.inputs.iter().enumerate() {
            let spend_pub = verify_spend_proof(&input.spend_proof)
                .map_err(|e| TxValidationError::InvalidSpendProof(e.to_string()))?;

            // L5: Cross-check spend proof's proof_link against the transaction input
            if spend_pub.proof_link != hash_to_felts(&input.proof_link) {
                return Err(TxValidationError::InvalidSpendProof(
                    "proof_link mismatch".into(),
                ));
            }

            // L5: Cross-check spend proof's proof_link against the balance proof's
            // corresponding input_proof_link (defense-in-depth — ensures the spend
            // proof is bound to the same balance proof, not just to the tx field).
            if spend_pub.proof_link != balance_pub.input_proof_links[i] {
                return Err(TxValidationError::InvalidSpendProof(
                    "spend proof proof_link does not match balance proof input".into(),
                ));
            }

            let nullifier_felts = input.nullifier.to_felts();
            if spend_pub.nullifier != nullifier_felts {
                return Err(TxValidationError::InvalidSpendProof(
                    "nullifier mismatch".into(),
                ));
            }
            // merkle_root is checked in state.rs, not here
        }

        // Check message sizes
        for msg in &self.messages {
            if msg.payload.ciphertext.len() > crate::constants::MAX_MESSAGE_SIZE {
                return Err(TxValidationError::MessageTooLarge);
            }
        }

        Ok(())
    }

    /// Get total serialized size estimate.
    pub fn estimated_size(&self) -> usize {
        let base = 8 + 32 + 8; // fee + chain_id + expiry
        let balance =
            self.balance_proof.proof_bytes.len() + self.balance_proof.public_inputs_bytes.len();
        let inputs: usize = self
            .inputs
            .iter()
            .map(|i| {
                32 + 32 + i.spend_proof.proof_bytes.len() + i.spend_proof.public_inputs_bytes.len()
            })
            .sum();
        let outputs: usize = self
            .outputs
            .iter()
            .map(|o| 32 + 32 + o.encrypted_note.ciphertext.len() + 24 + 64)
            .sum();
        let messages: usize = self
            .messages
            .iter()
            .map(|m| m.payload.ciphertext.len() + 24 + 64)
            .sum();
        base + balance + inputs + outputs + messages + 32
    }
}

/// Compute tx_content_hash from transaction content fields.
pub fn compute_tx_content_hash(
    inputs: &[TxInput],
    outputs: &[TxOutput],
    messages: &[TxMessage],
    fee: u64,
    chain_id: &Hash,
    expiry_epoch: u64,
    tx_type: &TxType,
) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key("umbra.tx_content_hash");
    // Chain binding
    hasher.update(chain_id);
    hasher.update(&expiry_epoch.to_le_bytes());
    hasher.update(&fee.to_le_bytes());
    // Transaction type
    hash_tx_type_into(tx_type, &mut hasher);
    // Input count + nullifiers + proof_links
    hasher.update(&(inputs.len() as u32).to_le_bytes());
    for input in inputs {
        hasher.update(&input.nullifier.0);
        hasher.update(&input.proof_link);
    }
    // Output count + content
    hasher.update(&(outputs.len() as u32).to_le_bytes());
    for output in outputs {
        hasher.update(&output.commitment.0);
        hasher.update(&output.stealth_address.one_time_key);
        hasher.update(&(output.stealth_address.kem_ciphertext.0.len() as u32).to_le_bytes());
        hasher.update(&output.stealth_address.kem_ciphertext.0);
        hasher.update(&output.encrypted_note.nonce);
        hasher.update(&(output.encrypted_note.ciphertext.len() as u32).to_le_bytes());
        hasher.update(&output.encrypted_note.ciphertext);
        hasher.update(&output.encrypted_note.mac);
    }
    // Messages
    hasher.update(&(messages.len() as u32).to_le_bytes());
    for msg in messages {
        hasher.update(&(msg.payload.kem_ciphertext.0.len() as u32).to_le_bytes());
        hasher.update(&msg.payload.kem_ciphertext.0);
        hasher.update(&msg.payload.nonce);
        hasher.update(&(msg.payload.ciphertext.len() as u32).to_le_bytes());
        hasher.update(&msg.payload.ciphertext);
        hasher.update(&msg.payload.mac);
    }
    *hasher.finalize().as_bytes()
}

/// Hash the tx_type discriminant and relevant fields into a hasher.
fn hash_tx_type_into(tx_type: &TxType, hasher: &mut blake3::Hasher) {
    match tx_type {
        TxType::Transfer => {
            hasher.update(&[0u8]);
        }
        TxType::ValidatorRegister {
            signing_key,
            kem_public_key,
        } => {
            hasher.update(&[1u8]);
            hasher.update(&(signing_key.0.len() as u32).to_le_bytes());
            hasher.update(&signing_key.0);
            hasher.update(&(kem_public_key.0.len() as u32).to_le_bytes());
            hasher.update(&kem_public_key.0);
        }
        TxType::ValidatorDeregister {
            validator_id,
            auth_signature: _, // C1: excluded — auth_signature signs over tx_content_hash
            bond_return_output,
            bond_blinding,
        } => {
            hasher.update(&[2u8]);
            hasher.update(validator_id);
            hasher.update(&bond_return_output.commitment.0);
            hasher.update(&bond_return_output.stealth_address.one_time_key);
            hasher.update(bond_blinding);
        }
    }
}

/// Compute the deregistration auth sign data.
///
/// The validator signs: `"umbra.validator.deregister" || chain_id || validator_id || tx_content_hash`
pub fn deregister_sign_data(chain_id: &Hash, validator_id: &Hash, tx_content_hash: &Hash) -> Hash {
    crate::hash_concat(&[
        b"umbra.validator.deregister",
        chain_id,
        validator_id,
        tx_content_hash,
    ])
}

/// Transaction validation errors.
#[derive(Clone, Debug, thiserror::Error)]
pub enum TxValidationError {
    #[error("transaction has no inputs")]
    NoInputs,
    #[error("transaction has no outputs")]
    NoOutputs,
    #[error("too many inputs (max {})", crate::constants::MAX_TX_IO)]
    TooManyInputs,
    #[error("too many outputs (max {})", crate::constants::MAX_TX_IO)]
    TooManyOutputs,
    #[error("duplicate nullifier in transaction")]
    DuplicateNullifier,
    #[error("invalid balance proof: {0}")]
    InvalidBalanceProof(String),
    #[error("invalid spend proof: {0}")]
    InvalidSpendProof(String),
    #[error("message exceeds maximum size")]
    MessageTooLarge,
    #[error("too many messages (max {})", crate::constants::MAX_MESSAGES_PER_TX)]
    TooManyMessages,
    #[error("nullifier already spent")]
    NullifierAlreadySpent,
    #[error("invalid transaction binding hash")]
    InvalidBinding,
    #[error("transaction has expired")]
    Expired,
    #[error("fee below minimum ({} required)", crate::constants::MIN_TX_FEE)]
    FeeTooLow,
    #[error("fee exceeds maximum ({} allowed)", crate::constants::MAX_TX_FEE)]
    FeeTooHigh,
    #[error("validator registration fee too low (bond + fee required)")]
    InsufficientBond,
    #[error("invalid validator signing key")]
    InvalidValidatorKey,
    #[error("invalid bond return output")]
    InvalidBondReturn,
    #[error("duplicate output commitment in transaction")]
    DuplicateOutputCommitment,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::commitment::BlindingFactor;
    use crate::crypto::keys::FullKeypair;
    use crate::transaction::builder::{InputSpec, TransactionBuilder};

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

    fn make_test_tx() -> Transaction {
        let recipient = FullKeypair::generate();
        TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 900)
            .set_fee(100)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap()
    }

    #[test]
    fn tx_id_deterministic() {
        let tx = make_test_tx();
        assert_eq!(tx.tx_id(), tx.tx_id());
    }

    #[test]
    fn tx_id_includes_proof_bytes() {
        // tx_id must include proof bytes to prevent malleability.
        // Two transactions with identical content but different proof bytes
        // must produce different tx_ids.
        let mut tx = make_test_tx();
        let id1 = tx.tx_id();
        // Tamper with balance proof bytes (simulates proof replacement)
        tx.balance_proof.proof_bytes.push(0xFF);
        let id2 = tx.tx_id();
        assert_ne!(id1, id2, "tx_id should change when proof bytes change");

        // Also check spend proof bytes
        let mut tx2 = make_test_tx();
        let id3 = tx2.tx_id();
        tx2.inputs[0].spend_proof.proof_bytes.push(0xFF);
        let id4 = tx2.tx_id();
        assert_ne!(
            id3, id4,
            "tx_id should change when spend proof bytes change"
        );
    }

    #[test]
    fn tx_content_hash_deterministic() {
        let tx = make_test_tx();
        assert_eq!(tx.tx_content_hash(), tx.tx_content_hash());
        assert_eq!(tx.tx_content_hash(), tx.tx_binding);
    }

    #[test]
    fn validate_accepts_valid_tx() {
        let tx = make_test_tx();
        assert!(tx.validate_structure(0).is_ok());
    }

    #[test]
    fn validate_rejects_no_inputs() {
        let mut tx = make_test_tx();
        tx.inputs.clear();
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::NoInputs)
        ));
    }

    #[test]
    fn validate_rejects_no_outputs() {
        let mut tx = make_test_tx();
        tx.outputs.clear();
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::NoOutputs)
        ));
    }

    #[test]
    fn validate_rejects_too_many_inputs() {
        let mut tx = make_test_tx();
        let extra = tx.inputs[0].clone();
        while tx.inputs.len() <= crate::constants::MAX_TX_IO {
            tx.inputs.push(extra.clone());
        }
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::TooManyInputs)
        ));
    }

    #[test]
    fn validate_rejects_too_many_outputs() {
        let mut tx = make_test_tx();
        let extra = tx.outputs[0].clone();
        while tx.outputs.len() <= crate::constants::MAX_TX_IO {
            tx.outputs.push(extra.clone());
        }
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::TooManyOutputs)
        ));
    }

    #[test]
    fn validate_rejects_duplicate_nullifier() {
        let mut tx = make_test_tx();
        let dup = tx.inputs[0].clone();
        tx.inputs.push(dup);
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::DuplicateNullifier)
        ));
    }

    #[test]
    fn validate_rejects_expired() {
        let mut tx = make_test_tx();
        tx.expiry_epoch = 5;
        // current_epoch=10 > expiry_epoch=5 → expired
        assert!(matches!(
            tx.validate_structure(10),
            Err(TxValidationError::Expired)
        ));
    }

    #[test]
    fn validate_rejects_fee_too_low() {
        let mut tx = make_test_tx();
        tx.fee = 0;
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::FeeTooLow)
        ));
    }

    #[test]
    fn validate_rejects_invalid_binding() {
        let mut tx = make_test_tx();
        tx.tx_binding = [0u8; 32]; // tamper
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::InvalidBinding)
        ));
    }

    #[test]
    fn validate_rejects_too_many_messages() {
        let mut tx = make_test_tx();
        let msg = TxMessage {
            payload: crate::crypto::encryption::EncryptedPayload {
                ciphertext: vec![0u8; 10],
                nonce: [0u8; 24],
                mac: [0u8; 32],
                kem_ciphertext: crate::crypto::keys::KemCiphertext(vec![]),
            },
        };
        for _ in 0..=crate::constants::MAX_MESSAGES_PER_TX {
            tx.messages.push(msg.clone());
        }
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::TooManyMessages)
        ));
    }

    #[test]
    fn estimated_size_nonzero() {
        let tx = make_test_tx();
        assert!(tx.estimated_size() > 0);
    }

    #[test]
    fn compute_tx_content_hash_deterministic() {
        let tx = make_test_tx();
        let h1 = compute_tx_content_hash(
            &tx.inputs,
            &tx.outputs,
            &tx.messages,
            tx.fee,
            &tx.chain_id,
            tx.expiry_epoch,
            &tx.tx_type,
        );
        let h2 = compute_tx_content_hash(
            &tx.inputs,
            &tx.outputs,
            &tx.messages,
            tx.fee,
            &tx.chain_id,
            tx.expiry_epoch,
            &tx.tx_type,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn deregister_sign_data_deterministic() {
        let chain_id = [1u8; 32];
        let vid = [2u8; 32];
        let content = [3u8; 32];
        let a = deregister_sign_data(&chain_id, &vid, &content);
        let b = deregister_sign_data(&chain_id, &vid, &content);
        assert_eq!(a, b);
    }

    // ── New validation tests ──

    #[test]
    fn validate_rejects_register_insufficient_bond() {
        // Build a valid TX, then change its type to ValidatorRegister.
        // The fee (100) is far below VALIDATOR_BASE_BOND + MIN_TX_FEE (1_000_001).
        // The InsufficientBond check runs before the binding check,
        // so it will trigger first.
        let mut tx = make_test_tx();
        let kp = FullKeypair::generate();
        tx.tx_type = TxType::ValidatorRegister {
            signing_key: kp.signing.public.clone(),
            kem_public_key: kp.kem.public.clone(),
        };
        // tx.fee is 100, which is below VALIDATOR_BASE_BOND (1_000_000) + MIN_TX_FEE (1)
        assert!(tx.fee < crate::constants::VALIDATOR_BASE_BOND + crate::constants::MIN_TX_FEE);
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::InsufficientBond)
        ));
    }

    #[test]
    fn validate_rejects_register_invalid_signing_key_size() {
        // Regression test for the is_valid_size() fix.
        // A signing key of 100 bytes is not a valid Dilithium5 public key (2592 bytes).
        // The InvalidValidatorKey check runs before the binding check.
        let mut tx = make_test_tx();
        tx.fee = crate::constants::VALIDATOR_BASE_BOND + crate::constants::MIN_TX_FEE;
        let kp = FullKeypair::generate();
        tx.tx_type = TxType::ValidatorRegister {
            signing_key: SigningPublicKey(vec![0xAB; 100]), // wrong size: 100 != 2592
            kem_public_key: kp.kem.public.clone(),
        };
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::InvalidValidatorKey)
        ));
    }

    #[test]
    fn validate_rejects_register_invalid_kem_key_size() {
        // A KEM key of 200 bytes is not a valid Kyber1024 public key (1568 bytes).
        let mut tx = make_test_tx();
        tx.fee = crate::constants::VALIDATOR_BASE_BOND + crate::constants::MIN_TX_FEE;
        let kp = FullKeypair::generate();
        tx.tx_type = TxType::ValidatorRegister {
            signing_key: kp.signing.public.clone(),        // valid size
            kem_public_key: KemPublicKey(vec![0xCD; 200]), // wrong size: 200 != 1568
        };
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::InvalidValidatorKey)
        ));
    }

    #[test]
    fn validate_rejects_deregister_zero_commitment() {
        // A ValidatorDeregister with an all-zero bond_return_commitment triggers
        // InvalidBondReturn. This check runs before the binding check.
        let mut tx = make_test_tx();
        let kp = FullKeypair::generate();
        // Construct a TxOutput with a zero commitment
        let stealth_result =
            crate::crypto::stealth::StealthAddress::generate(&kp.kem.public, 0).unwrap();
        let encrypted_note =
            crate::crypto::encryption::EncryptedPayload::encrypt(&kp.kem.public, b"bond return")
                .unwrap();
        tx.tx_type = TxType::ValidatorDeregister {
            validator_id: [0x42; 32],
            auth_signature: Signature(vec![]),
            bond_return_output: Box::new(TxOutput {
                commitment: crate::crypto::commitment::Commitment([0u8; 32]), // all zeros
                stealth_address: stealth_result.address,
                encrypted_note,
            }),
            bond_blinding: [0u8; 32],
        };
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::InvalidBondReturn)
        ));
    }

    #[test]
    fn validate_rejects_message_too_large() {
        // Build a TX via the builder with a message whose plaintext is larger than
        // MAX_MESSAGE_SIZE (65536). The ciphertext will be the same size as the
        // plaintext (XOR cipher), so it will exceed the limit. The builder does
        // not enforce MAX_MESSAGE_SIZE, only MAX_ENCRYPT_PLAINTEXT (1 MiB).
        // validate_structure checks message size AFTER proof verification, so the
        // TX must have valid proofs — which the builder provides.
        let recipient = FullKeypair::generate();
        let oversized_plaintext = vec![0xAA; crate::constants::MAX_MESSAGE_SIZE + 1];
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 900)
            .add_message(recipient.kem.public.clone(), oversized_plaintext)
            .set_fee(100)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        assert!(tx.messages[0].payload.ciphertext.len() > crate::constants::MAX_MESSAGE_SIZE);
        assert!(matches!(
            tx.validate_structure(0),
            Err(TxValidationError::MessageTooLarge)
        ));
    }

    #[test]
    fn validate_rejects_proof_link_mismatch() {
        // This tests the L5 proof link cross-check between the spend proof's
        // proof_link and the transaction input's proof_link field (line 298).
        //
        // The cross-check code path at lines 297-310 verifies:
        //   1. spend_pub.proof_link == hash_to_felts(&input.proof_link)
        //      (spend proof's proof_link matches the transaction input field)
        //   2. spend_pub.proof_link == balance_pub.input_proof_links[i]
        //      (spend proof's proof_link matches the balance proof's entry)
        //
        // To trigger the mismatch, we build a valid TX and then tamper with the
        // input's proof_link field. This will cause the binding check to fail
        // first (since proof_link is part of tx_content_hash), so we also
        // recompute the binding to get past that check. The balance proof
        // verification will then succeed (it has the original proof_links
        // baked in), and when the cross-check compares the spend proof's
        // proof_link against the (now-tampered) balance_pub.input_proof_links,
        // it will find a mismatch.
        //
        // However, the balance proof cross-check at line 266 compares
        // balance_pub.input_proof_links against the tampered tx input
        // proof_links, which will also mismatch. So the actual error is
        // InvalidBalanceProof("input proof_links mismatch") rather than
        // InvalidSpendProof, because the balance cross-check runs first.
        //
        // This confirms the defense-in-depth: ANY proof_link tampering is
        // caught — either by the balance proof cross-check (line 266) or the
        // spend proof cross-check (line 298/307).
        let mut tx = make_test_tx();
        // Tamper with the input's proof_link
        tx.inputs[0].proof_link = [0xFF; 32];
        // Recompute binding so we get past the binding check
        tx.tx_binding = tx.tx_content_hash();

        let result = tx.validate_structure(0);
        assert!(result.is_err());
        // The error will be from the balance proof cross-check (proof_links mismatch)
        // because that check runs before the spend proof cross-check.
        match &result {
            Err(TxValidationError::InvalidBalanceProof(msg)) => {
                assert!(
                    msg.contains("proof_links mismatch")
                        || msg.contains("tx_content_hash mismatch"),
                    "expected proof_links or tx_content_hash mismatch, got: {msg}"
                );
            }
            Err(TxValidationError::InvalidSpendProof(msg)) => {
                assert!(
                    msg.contains("proof_link"),
                    "expected proof_link mismatch, got: {msg}"
                );
            }
            other => panic!("expected InvalidBalanceProof or InvalidSpendProof, got: {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_no_expiry() {
        // A TX with expiry_epoch=0 means "no expiry" and should pass validation
        // regardless of the current epoch. Build a valid TX (which has expiry_epoch=0
        // by default) and validate at a high epoch.
        let tx = make_test_tx();
        assert_eq!(tx.expiry_epoch, 0);
        // Validate at epoch 100 — should pass because 0 means no expiry
        assert!(tx.validate_structure(100).is_ok());
    }

    #[test]
    fn validate_expiry_boundary() {
        // Test the exact boundary of expiry: the condition is
        // `current_epoch > expiry_epoch` (strictly greater), so
        // current_epoch == expiry_epoch should PASS (not yet expired),
        // and current_epoch == expiry_epoch + 1 should FAIL.
        //
        // We set expiry_epoch=5 and rebuild the binding and proofs via
        // the builder so the TX is fully valid at the boundary.
        let recipient = FullKeypair::generate();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 900)
            .set_fee(100)
            .set_expiry_epoch(5)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        assert_eq!(tx.expiry_epoch, 5);
        // current_epoch=5 == expiry_epoch=5 → NOT expired (passes)
        assert!(
            tx.validate_structure(5).is_ok(),
            "TX should be valid when current_epoch == expiry_epoch"
        );
        // current_epoch=6 > expiry_epoch=5 → expired
        assert!(matches!(
            tx.validate_structure(6),
            Err(TxValidationError::Expired)
        ));
    }

    #[test]
    fn validate_rejects_duplicate_output_commitments() {
        // Build a transaction and manually duplicate an output commitment
        let recipient = FullKeypair::generate();
        let mut tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 450)
            .add_output(recipient.kem.public.clone(), 450)
            .set_fee(100)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        // Duplicate the first output's commitment into the second output
        tx.outputs[1].commitment = tx.outputs[0].commitment;

        // Recompute tx_binding to bypass the binding check
        tx.tx_binding = tx.tx_content_hash();

        let result = tx.validate_structure(0);
        assert!(
            matches!(result, Err(TxValidationError::DuplicateOutputCommitment)),
            "expected DuplicateOutputCommitment, got {:?}",
            result
        );
    }
}
