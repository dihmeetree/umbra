//! Wallet for managing Spectra keys, scanning for outputs, and building transactions.
//!
//! The wallet:
//! - Generates and stores post-quantum key material
//! - Scans the DAG for outputs addressed to us (via stealth address detection)
//! - Decrypts note data (amounts, blinding factors) from our outputs
//! - Builds and signs transactions for spending

use crate::crypto::commitment::{BlindingFactor, Commitment};
use crate::crypto::keys::{FullKeypair, SharedSecret};
use crate::crypto::stealth::derive_spend_auth;
use crate::transaction::builder::{decode_note, InputSpec, TransactionBuilder};
use crate::transaction::{Transaction, TxOutput};
use crate::Hash;

/// Spend status of a wallet output.
#[derive(Clone, Debug, PartialEq)]
pub enum SpendStatus {
    /// Output is available for spending.
    Unspent,
    /// Output is used in a pending (unconfirmed) transaction.
    /// Contains the `tx_binding` of the pending transaction so
    /// it can be confirmed or cancelled.
    Pending { tx_binding: Hash },
    /// Output has been confirmed spent on-chain.
    Spent,
}

/// A spendable output owned by this wallet.
#[derive(Clone, Debug)]
pub struct OwnedOutput {
    /// The commitment for this output
    pub commitment: Commitment,
    /// The decrypted value
    pub value: u64,
    /// The blinding factor
    pub blinding: BlindingFactor,
    /// The spend authorization key
    pub spend_auth: Hash,
    /// Spend status (unspent / pending / spent)
    pub status: SpendStatus,
    /// Index in the global commitment tree
    pub commitment_index: Option<usize>,
}

/// A decrypted message received by this wallet.
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// The transaction that contained this message
    pub tx_hash: Hash,
    /// The decrypted message content (may contain application-level routing tags)
    pub content: Vec<u8>,
}

/// The Spectra wallet.
pub struct Wallet {
    /// Our identity keypair
    keypair: FullKeypair,
    /// Outputs we own
    outputs: Vec<OwnedOutput>,
    /// Messages received
    messages: Vec<ReceivedMessage>,
}

impl Wallet {
    /// Create a new wallet with a fresh keypair.
    pub fn new() -> Self {
        Wallet {
            keypair: FullKeypair::generate(),
            outputs: Vec::new(),
            messages: Vec::new(),
        }
    }

    /// Create a wallet from an existing keypair.
    pub fn from_keypair(keypair: FullKeypair) -> Self {
        Wallet {
            keypair,
            outputs: Vec::new(),
            messages: Vec::new(),
        }
    }

    /// Get our public address (for receiving payments).
    pub fn address(&self) -> crate::crypto::keys::PublicAddress {
        self.keypair.public_address()
    }

    /// Get the KEM public key (for sending to us).
    pub fn kem_public_key(&self) -> &crate::crypto::keys::KemPublicKey {
        &self.keypair.kem.public
    }

    /// Scan a transaction for outputs and messages addressed to us.
    pub fn scan_transaction(&mut self, tx: &Transaction) {
        let tx_id = tx.tx_id();

        // Scan outputs
        for (idx, output) in tx.outputs.iter().enumerate() {
            if let Some(owned) = self.try_claim_output(output, idx as u32) {
                self.outputs.push(owned);
            }
        }

        // Scan messages
        for msg in &tx.messages {
            if let Some(plaintext) = msg.payload.decrypt(&self.keypair.kem) {
                self.messages.push(ReceivedMessage {
                    tx_hash: tx_id.0,
                    content: plaintext,
                });
            }
        }
    }

    /// Try to claim an output as ours by detecting the stealth address.
    fn try_claim_output(&self, output: &TxOutput, output_index: u32) -> Option<OwnedOutput> {
        // Try to detect the stealth address
        let stealth_info = output
            .stealth_address
            .try_detect_at_index(&self.keypair.kem, output_index)?;

        // Derive spend authorization
        let signing_fingerprint = self.keypair.signing.public.fingerprint();
        let spend_auth = derive_spend_auth(&stealth_info.shared_secret, &signing_fingerprint);

        // Decrypt the note data reusing the shared secret from stealth detection,
        // avoiding a redundant second KEM decapsulation and reducing side-channel
        // exposure of the KEM secret key.
        let shared_secret = SharedSecret(stealth_info.shared_secret);
        let note_data = output
            .encrypted_note
            .decrypt_with_shared_secret(&shared_secret)?;
        let (value, blinding) = decode_note(&note_data)?;

        // Verify the commitment matches
        let expected_commitment = Commitment::commit(value, &blinding);
        if expected_commitment != output.commitment {
            return None;
        }

        Some(OwnedOutput {
            commitment: output.commitment,
            value,
            blinding,
            spend_auth,
            status: SpendStatus::Unspent,
            commitment_index: None,
        })
    }

    /// Get our spendable balance (only fully unspent outputs, not pending).
    ///
    /// Uses checked arithmetic to prevent silent overflow when many outputs
    /// are held simultaneously.
    pub fn balance(&self) -> u64 {
        self.outputs
            .iter()
            .filter(|o| o.status == SpendStatus::Unspent)
            .try_fold(0u64, |acc, o| acc.checked_add(o.value))
            .unwrap_or(u64::MAX)
    }

    /// Get unspent outputs (excludes pending and spent).
    pub fn unspent_outputs(&self) -> Vec<&OwnedOutput> {
        self.outputs
            .iter()
            .filter(|o| o.status == SpendStatus::Unspent)
            .collect()
    }

    /// Get all received messages.
    pub fn received_messages(&self) -> &[ReceivedMessage] {
        &self.messages
    }

    /// Build a transaction sending `amount` to a recipient, with optional message.
    pub fn build_transaction(
        &mut self,
        recipient_kem_pk: &crate::crypto::keys::KemPublicKey,
        amount: u64,
        fee: u64,
        message: Option<Vec<u8>>,
    ) -> Result<Transaction, WalletError> {
        self.build_transaction_with_state(recipient_kem_pk, amount, fee, message, None)
    }

    /// Build a transaction with access to chain state for Merkle path resolution.
    pub fn build_transaction_with_state(
        &mut self,
        recipient_kem_pk: &crate::crypto::keys::KemPublicKey,
        amount: u64,
        fee: u64,
        message: Option<Vec<u8>>,
        state: Option<&crate::state::ChainState>,
    ) -> Result<Transaction, WalletError> {
        let total_needed = amount
            .checked_add(fee)
            .ok_or(WalletError::ArithmeticOverflow)?;

        // Select outputs to spend (simple greedy, only fully unspent)
        let mut selected: Vec<usize> = Vec::new();
        let mut selected_total = 0u64;

        for (i, output) in self.outputs.iter().enumerate() {
            if output.status != SpendStatus::Unspent {
                continue;
            }
            selected.push(i);
            selected_total = selected_total
                .checked_add(output.value)
                .ok_or(WalletError::ArithmeticOverflow)?;
            if selected_total >= total_needed {
                break;
            }
        }

        if selected_total < total_needed {
            return Err(WalletError::InsufficientFunds {
                available: selected_total,
                needed: total_needed,
            });
        }

        // Build inputs with Merkle paths from state
        let mut builder = TransactionBuilder::new();
        for &idx in &selected {
            let output = &self.outputs[idx];
            let merkle_path = if let (Some(st), Some(ci)) = (state, output.commitment_index) {
                st.commitment_path(ci).unwrap_or_default()
            } else {
                vec![]
            };
            builder = builder.add_input(InputSpec {
                value: output.value,
                blinding: output.blinding.clone(),
                spend_auth: output.spend_auth,
                merkle_path,
            });
        }

        // Build outputs
        builder = builder.add_output(recipient_kem_pk.clone(), amount);

        // Change output (back to ourselves)
        let change = selected_total - total_needed;
        if change > 0 {
            builder = builder.add_output(self.keypair.kem.public.clone(), change);
        }

        // Add message if provided
        if let Some(msg_data) = message {
            builder = builder.add_message(recipient_kem_pk.clone(), msg_data);
        }

        builder = builder.set_fee(fee);

        let tx = builder.build().map_err(WalletError::Build)?;

        // Mark outputs as pending (not fully spent until confirmed on-chain).
        // Use `confirm_transaction` after the tx is finalized, or
        // `cancel_transaction` if it fails to be included.
        let tx_binding = tx.tx_binding;
        for &idx in &selected {
            self.outputs[idx].status = SpendStatus::Pending { tx_binding };
        }

        Ok(tx)
    }

    /// Confirm that a pending transaction was included on-chain.
    /// Moves all outputs with matching `tx_binding` from `Pending` to `Spent`.
    pub fn confirm_transaction(&mut self, tx_binding: &Hash) {
        for output in &mut self.outputs {
            if output.status
                == (SpendStatus::Pending {
                    tx_binding: *tx_binding,
                })
            {
                output.status = SpendStatus::Spent;
            }
        }
    }

    /// Cancel a pending transaction (e.g., it was not included before expiry).
    /// Moves all outputs with matching `tx_binding` from `Pending` back to `Unspent`.
    pub fn cancel_transaction(&mut self, tx_binding: &Hash) {
        for output in &mut self.outputs {
            if output.status
                == (SpendStatus::Pending {
                    tx_binding: *tx_binding,
                })
            {
                output.status = SpendStatus::Unspent;
            }
        }
    }

    /// Get the number of owned outputs.
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

/// Wallet errors.
#[derive(Clone, Debug, thiserror::Error)]
pub enum WalletError {
    #[error("insufficient funds: have {available}, need {needed}")]
    InsufficientFunds { available: u64, needed: u64 },
    #[error("transaction build failed: {0}")]
    Build(#[from] crate::transaction::builder::TxBuildError),
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::commitment::BlindingFactor;
    use crate::crypto::keys::FullKeypair;
    use crate::transaction::builder::InputSpec;

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
    fn wallet_scan_and_receive() {
        let mut receiver_wallet = Wallet::new();

        // Build a transaction paying the receiver
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(receiver_wallet.kem_public_key().clone(), 900)
            .set_fee(100)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        // Receiver scans and finds the output
        receiver_wallet.scan_transaction(&tx);
        assert_eq!(receiver_wallet.balance(), 900);
        assert_eq!(receiver_wallet.unspent_outputs().len(), 1);
    }

    #[test]
    fn wallet_scan_message() {
        let mut receiver_wallet = Wallet::new();

        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 100,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(receiver_wallet.kem_public_key().clone(), 50)
            .add_message(
                receiver_wallet.kem_public_key().clone(),
                b"secret message from sender".to_vec(),
            )
            .set_fee(50)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        receiver_wallet.scan_transaction(&tx);

        assert_eq!(receiver_wallet.received_messages().len(), 1);
        assert_eq!(
            receiver_wallet.received_messages()[0].content,
            b"secret message from sender"
        );
    }

    #[test]
    fn wallet_wrong_recipient_no_detect() {
        let recipient = FullKeypair::generate();
        let mut bystander = Wallet::new();

        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 100,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 50)
            .set_fee(50)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        bystander.scan_transaction(&tx);
        assert_eq!(bystander.balance(), 0);
    }

    #[test]
    fn wallet_spend_and_change() {
        let mut alice = Wallet::new();
        let bob = Wallet::new();

        // Give Alice some funds (coinbase — bypasses min-fee via direct build)
        let funding_tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 10001,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(alice.kem_public_key().clone(), 10000)
            .set_fee(1)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        alice.scan_transaction(&funding_tx);
        assert_eq!(alice.balance(), 10000);

        // Alice sends 3000 to Bob with fee 100
        let tx = alice
            .build_transaction(bob.kem_public_key(), 3000, 100, None)
            .unwrap();

        assert_eq!(tx.fee, 100);
        assert_eq!(tx.outputs.len(), 2); // Payment + change
        assert_eq!(alice.balance(), 0); // All outputs now pending

        // Confirm the transaction
        alice.confirm_transaction(&tx.tx_binding);

        // Alice scans her own transaction to pick up change
        alice.scan_transaction(&tx);
        assert_eq!(alice.balance(), 6900); // 10000 - 3000 - 100
    }

    #[test]
    fn wallet_cancel_pending_transaction() {
        let mut alice = Wallet::new();
        let bob = Wallet::new();

        let funding_tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 10001,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(alice.kem_public_key().clone(), 10000)
            .set_fee(1)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        alice.scan_transaction(&funding_tx);
        assert_eq!(alice.balance(), 10000);

        // Build a transaction — outputs become pending
        let tx = alice
            .build_transaction(bob.kem_public_key(), 3000, 100, None)
            .unwrap();
        assert_eq!(alice.balance(), 0); // All pending

        // Cancel the transaction — outputs return to unspent
        alice.cancel_transaction(&tx.tx_binding);
        assert_eq!(alice.balance(), 10000); // Restored
    }
}
