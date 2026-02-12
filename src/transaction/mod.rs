//! Transaction model for Spectra.
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

/// A complete Spectra transaction.
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
}

impl Transaction {
    /// Compute the transaction ID (hash of all transaction data).
    pub fn tx_id(&self) -> TxId {
        let mut hasher = blake3::Hasher::new_derive_key("spectra.txid");
        // Hash all inputs (only public data: nullifiers and proof_links)
        for input in &self.inputs {
            hasher.update(&input.nullifier.0);
            hasher.update(&input.proof_link);
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
        // Hash binding
        hasher.update(&self.tx_binding);
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
        for input in &self.inputs {
            let spend_pub = verify_spend_proof(&input.spend_proof)
                .map_err(|e| TxValidationError::InvalidSpendProof(e.to_string()))?;

            // Check spend proof public inputs match this input
            if spend_pub.proof_link != hash_to_felts(&input.proof_link) {
                return Err(TxValidationError::InvalidSpendProof(
                    "proof_link mismatch".into(),
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
) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key("spectra.tx_content_hash");
    // Chain binding
    hasher.update(chain_id);
    hasher.update(&expiry_epoch.to_le_bytes());
    hasher.update(&fee.to_le_bytes());
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
}
