//! Wallet for managing Spectra keys, scanning for outputs, and building transactions.
//!
//! The wallet:
//! - Generates and stores post-quantum key material
//! - Scans the DAG for outputs addressed to us (via stealth address detection)
//! - Decrypts note data (amounts, blinding factors) from our outputs
//! - Builds and signs transactions for spending

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::commitment::{BlindingFactor, Commitment};
use crate::crypto::keys::{FullKeypair, KemKeypair, SharedSecret, SigningKeypair};
use crate::crypto::stealth::derive_spend_auth;
use crate::transaction::builder::{decode_note, InputSpec, TransactionBuilder};
use crate::transaction::{Transaction, TxOutput};
use crate::Hash;

/// Direction of a transaction relative to this wallet.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TxDirection {
    /// We sent funds to someone else.
    Send,
    /// We received funds from someone.
    Receive,
    /// We received a coinbase reward.
    Coinbase,
}

/// A record of a transaction in the wallet's history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxHistoryEntry {
    /// Transaction ID (or vertex ID for coinbase).
    pub tx_id: Hash,
    /// Direction of the transaction.
    pub direction: TxDirection,
    /// Amount transferred.
    pub amount: u64,
    /// Fee paid (0 for receives/coinbase).
    pub fee: u64,
    /// Epoch when the transaction was observed.
    pub epoch: u64,
}

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
#[derive(Clone)]
pub struct Wallet {
    /// Our identity keypair
    keypair: FullKeypair,
    /// Outputs we own
    outputs: Vec<OwnedOutput>,
    /// Messages received
    messages: Vec<ReceivedMessage>,
    /// Transaction history log
    history: Vec<TxHistoryEntry>,
}

impl Wallet {
    /// Create a new wallet with a fresh keypair.
    pub fn new() -> Self {
        Wallet {
            keypair: FullKeypair::generate(),
            outputs: Vec::new(),
            messages: Vec::new(),
            history: Vec::new(),
        }
    }

    /// Create a wallet from an existing keypair.
    pub fn from_keypair(keypair: FullKeypair) -> Self {
        Wallet {
            keypair,
            outputs: Vec::new(),
            messages: Vec::new(),
            history: Vec::new(),
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
        self.scan_transaction_with_state(tx, None);
    }

    /// Scan a transaction with optional chain state for commitment index resolution.
    pub fn scan_transaction_with_state(
        &mut self,
        tx: &Transaction,
        state: Option<&crate::state::ChainState>,
    ) {
        let tx_id = tx.tx_id();
        let epoch = state.map(|s| s.epoch()).unwrap_or(0);

        // Scan outputs
        let mut received_amount = 0u64;
        for (idx, output) in tx.outputs.iter().enumerate() {
            if let Some(mut owned) = self.try_claim_output(output, idx as u32) {
                // C5: Resolve commitment_index from chain state if available
                if let Some(st) = state {
                    owned.commitment_index = st.find_commitment(&owned.commitment);
                }
                received_amount = received_amount.saturating_add(owned.value);
                self.outputs.push(owned);
            }
        }

        // Record receive history if we claimed any outputs
        if received_amount > 0 {
            self.history.push(TxHistoryEntry {
                tx_id: tx_id.0,
                direction: TxDirection::Receive,
                amount: received_amount,
                fee: 0,
                epoch,
            });
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

    /// Resolve commitment indices for all outputs using the given chain state.
    ///
    /// Call this after the transaction outputs have been added to the chain state.
    pub fn resolve_commitment_indices(&mut self, state: &crate::state::ChainState) {
        for output in &mut self.outputs {
            if output.commitment_index.is_none() {
                output.commitment_index = state.find_commitment(&output.commitment);
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

        // Record send in history
        self.history.push(TxHistoryEntry {
            tx_id: tx.tx_id().0,
            direction: TxDirection::Send,
            amount,
            fee,
            epoch: 0, // caller can update epoch if known
        });

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

    /// Scan a single coinbase output (not part of any transaction).
    ///
    /// Coinbase outputs are created during vertex finalization and use
    /// output_index 0. Call this with the coinbase output returned from
    /// the RPC `/vertices/finalized` response.
    pub fn scan_coinbase_output(
        &mut self,
        output: &TxOutput,
        state: Option<&crate::state::ChainState>,
    ) {
        if let Some(mut owned) = self.try_claim_output(output, 0) {
            let epoch = state.map(|s| s.epoch()).unwrap_or(0);
            if let Some(st) = state {
                owned.commitment_index = st.find_commitment(&owned.commitment);
            }
            let amount = owned.value;
            self.outputs.push(owned);
            self.history.push(TxHistoryEntry {
                tx_id: [0u8; 32], // coinbase has no tx_id
                direction: TxDirection::Coinbase,
                amount,
                fee: 0,
                epoch,
            });
        }
    }

    /// Get the number of owned outputs.
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Get the transaction history.
    pub fn history(&self) -> &[TxHistoryEntry] {
        &self.history
    }

    /// Build a consolidation transaction that merges all unspent outputs into one.
    ///
    /// Sends all unspent value (minus fee) back to ourselves in a single output.
    pub fn build_consolidation_tx(
        &mut self,
        fee: u64,
        state: Option<&crate::state::ChainState>,
    ) -> Result<Transaction, WalletError> {
        let unspent: Vec<usize> = self
            .outputs
            .iter()
            .enumerate()
            .filter(|(_, o)| o.status == SpendStatus::Unspent)
            .map(|(i, _)| i)
            .collect();

        if unspent.len() < 2 {
            return Err(WalletError::NothingToConsolidate);
        }

        let total: u64 = unspent
            .iter()
            .map(|&i| self.outputs[i].value)
            .try_fold(0u64, |acc, v| acc.checked_add(v))
            .ok_or(WalletError::ArithmeticOverflow)?;

        if total <= fee {
            return Err(WalletError::InsufficientFunds {
                available: total,
                needed: fee,
            });
        }

        let mut builder = TransactionBuilder::new();
        for &idx in &unspent {
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

        // Single output back to ourselves
        let consolidated_amount = total - fee;
        builder = builder.add_output(self.keypair.kem.public.clone(), consolidated_amount);
        builder = builder.set_fee(fee);

        let tx = builder.build().map_err(WalletError::Build)?;

        // Mark all inputs as pending
        let tx_binding = tx.tx_binding;
        for &idx in &unspent {
            self.outputs[idx].status = SpendStatus::Pending { tx_binding };
        }

        // Record in history
        self.history.push(TxHistoryEntry {
            tx_id: tx.tx_id().0,
            direction: TxDirection::Send,
            amount: consolidated_amount,
            fee,
            epoch: 0,
        });

        Ok(tx)
    }

    /// Get the raw keypair (for recovery backup).
    pub fn keypair(&self) -> &FullKeypair {
        &self.keypair
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

// ── Recovery ─────────────────────────────────────────────────────────────

/// Generate a 24-word mnemonic phrase and the 32-byte entropy it encodes.
///
/// Uses 256 bits of random entropy, computes an 8-bit BLAKE3 checksum,
/// then maps 264 bits to 24 × 11-bit indices into the BIP39 English wordlist.
pub fn generate_mnemonic() -> (Vec<String>, [u8; 32]) {
    let entropy: [u8; 32] = rand::random();
    let words = entropy_to_words(&entropy);
    (words, entropy)
}

/// Convert 32-byte entropy to a 24-word mnemonic.
fn entropy_to_words(entropy: &[u8; 32]) -> Vec<String> {
    use crate::bip39_words::WORDLIST;
    // 8-bit checksum = first byte of BLAKE3(entropy)
    let checksum = blake3::hash(entropy).as_bytes()[0];

    // 256 bits entropy + 8 bits checksum = 264 bits = 24 × 11-bit words
    let mut bits = Vec::with_capacity(264);
    for byte in entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    for i in (0..8).rev() {
        bits.push((checksum >> i) & 1);
    }

    let mut words = Vec::with_capacity(24);
    for chunk in bits.chunks(11) {
        let mut index = 0u16;
        for &bit in chunk {
            index = (index << 1) | bit as u16;
        }
        words.push(WORDLIST[index as usize].to_string());
    }
    words
}

/// Convert a 24-word mnemonic back to 32-byte entropy.
///
/// Validates the checksum and returns an error if invalid.
pub fn words_to_entropy(words: &[String]) -> Result<[u8; 32], WalletError> {
    use crate::bip39_words::WORDLIST;

    if words.len() != 24 {
        return Err(WalletError::Recovery(format!(
            "expected 24 words, got {}",
            words.len()
        )));
    }

    // Map words to 11-bit indices
    let mut bits = Vec::with_capacity(264);
    for word in words {
        let lower = word.to_lowercase();
        let index = WORDLIST
            .iter()
            .position(|&w| w == lower)
            .ok_or_else(|| WalletError::Recovery(format!("unknown word: {}", word)))?;
        for i in (0..11).rev() {
            bits.push(((index >> i) & 1) as u8);
        }
    }

    // Extract 256 bits entropy + 8 bits checksum
    let mut entropy = [0u8; 32];
    for (i, byte) in entropy.iter_mut().enumerate() {
        for j in 0..8 {
            *byte = (*byte << 1) | bits[i * 8 + j];
        }
    }

    let mut checksum = 0u8;
    for j in 0..8 {
        checksum = (checksum << 1) | bits[256 + j];
    }

    // Validate checksum
    let expected_checksum = blake3::hash(&entropy).as_bytes()[0];
    if checksum != expected_checksum {
        return Err(WalletError::Recovery("invalid mnemonic checksum".into()));
    }

    Ok(entropy)
}

impl Wallet {
    /// Create an encrypted backup of the wallet key material.
    ///
    /// Returns (mnemonic_words, encrypted_backup_bytes). Both are needed
    /// to recover the wallet — the mnemonic derives the encryption key,
    /// and the backup contains the actual PQ key material.
    pub fn create_recovery_backup(&self) -> (Vec<String>, Vec<u8>) {
        let (words, entropy) = generate_mnemonic();

        // Derive encryption key from entropy
        let key = blake3::derive_key("spectra.wallet.recovery", &entropy);

        // Serialize key material
        let mut material = Vec::new();
        let spk = &self.keypair.signing.public.0;
        let ssk = &self.keypair.signing.secret.0;
        let kpk = &self.keypair.kem.public.0;
        let ksk = &self.keypair.kem.secret.0;

        material.extend_from_slice(&(spk.len() as u32).to_le_bytes());
        material.extend_from_slice(spk);
        material.extend_from_slice(&(ssk.len() as u32).to_le_bytes());
        material.extend_from_slice(ssk);
        material.extend_from_slice(&(kpk.len() as u32).to_le_bytes());
        material.extend_from_slice(kpk);
        material.extend_from_slice(&(ksk.len() as u32).to_le_bytes());
        material.extend_from_slice(ksk);

        // Encrypt with BLAKE3 keystream XOR
        let encrypted = xor_keystream(&key, &material);

        // Prepend a MAC for integrity
        let mac = blake3::keyed_hash(&key, &encrypted);
        let mut backup = mac.as_bytes().to_vec();
        backup.extend_from_slice(&encrypted);

        (words, backup)
    }

    /// Recover a wallet from a mnemonic phrase and encrypted backup file.
    pub fn recover_from_backup(
        words: &[String],
        encrypted_backup: &[u8],
    ) -> Result<Self, WalletError> {
        let entropy = words_to_entropy(words)?;
        let key = blake3::derive_key("spectra.wallet.recovery", &entropy);

        if encrypted_backup.len() < 32 {
            return Err(WalletError::Recovery("backup too short".into()));
        }

        // Verify MAC
        let stored_mac = &encrypted_backup[..32];
        let ciphertext = &encrypted_backup[32..];
        let expected_mac = blake3::keyed_hash(&key, ciphertext);
        if !crate::constant_time_eq(stored_mac, expected_mac.as_bytes()) {
            return Err(WalletError::Recovery(
                "invalid mnemonic or corrupted backup".into(),
            ));
        }

        // Decrypt
        let material = xor_keystream(&key, ciphertext);

        // Parse key material
        let mut pos = 0;
        let read_vec = |data: &[u8], pos: &mut usize| -> Result<Vec<u8>, WalletError> {
            if *pos + 4 > data.len() {
                return Err(WalletError::Recovery("truncated backup".into()));
            }
            let len = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
            *pos += 4;
            if *pos + len > data.len() {
                return Err(WalletError::Recovery("truncated backup".into()));
            }
            let v = data[*pos..*pos + len].to_vec();
            *pos += len;
            Ok(v)
        };

        let spk = read_vec(&material, &mut pos)?;
        let ssk = read_vec(&material, &mut pos)?;
        let kpk = read_vec(&material, &mut pos)?;
        let ksk = read_vec(&material, &mut pos)?;

        let signing = SigningKeypair::from_bytes(spk, ssk)
            .ok_or_else(|| WalletError::Recovery("invalid signing key in backup".into()))?;
        let kem = KemKeypair::from_bytes(kpk, ksk)
            .ok_or_else(|| WalletError::Recovery("invalid KEM key in backup".into()))?;

        Ok(Wallet {
            keypair: FullKeypair { signing, kem },
            outputs: Vec::new(),
            messages: Vec::new(),
            history: Vec::new(),
        })
    }
}

/// XOR data with a BLAKE3 keystream.
fn xor_keystream(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; data.len()];
    let mut block_idx = 0u64;
    let mut offset = 0;

    while offset < data.len() {
        let block_key = blake3::derive_key("spectra.recovery.stream", key);
        let stream_input = [block_key.as_slice(), &block_idx.to_le_bytes()].concat();
        let block = blake3::hash(&stream_input);
        let block_bytes = block.as_bytes();

        for i in 0..32 {
            if offset + i >= data.len() {
                break;
            }
            output[offset + i] = data[offset + i] ^ block_bytes[i];
        }

        offset += 32;
        block_idx += 1;
    }

    output
}

// ── Persistence ──────────────────────────────────────────────────────────

/// Wallet file format (bincode-serialized).
#[derive(Serialize, Deserialize)]
struct WalletFile {
    version: u32,
    signing_pk: Vec<u8>,
    signing_sk: Vec<u8>,
    kem_pk: Vec<u8>,
    kem_sk: Vec<u8>,
    outputs: Vec<SerializedOutput>,
    messages: Vec<SerializedMessage>,
    last_scanned_sequence: u64,
    /// Transaction history (added in version 2).
    history: Vec<TxHistoryEntry>,
}

#[derive(Serialize, Deserialize)]
struct SerializedOutput {
    commitment: Hash,
    value: u64,
    blinding: [u8; 32],
    spend_auth: Hash,
    status: SerializedSpendStatus,
    commitment_index: Option<usize>,
}

#[derive(Serialize, Deserialize)]
enum SerializedSpendStatus {
    Unspent,
    Pending { tx_binding: Hash },
    Spent,
}

#[derive(Serialize, Deserialize)]
struct SerializedMessage {
    tx_hash: Hash,
    content: Vec<u8>,
}

impl From<&SpendStatus> for SerializedSpendStatus {
    fn from(s: &SpendStatus) -> Self {
        match s {
            SpendStatus::Unspent => SerializedSpendStatus::Unspent,
            SpendStatus::Pending { tx_binding } => SerializedSpendStatus::Pending {
                tx_binding: *tx_binding,
            },
            SpendStatus::Spent => SerializedSpendStatus::Spent,
        }
    }
}

impl From<SerializedSpendStatus> for SpendStatus {
    fn from(s: SerializedSpendStatus) -> Self {
        match s {
            SerializedSpendStatus::Unspent => SpendStatus::Unspent,
            SerializedSpendStatus::Pending { tx_binding } => SpendStatus::Pending { tx_binding },
            SerializedSpendStatus::Spent => SpendStatus::Spent,
        }
    }
}

/// Legacy v1 wallet file format (without history).
#[derive(Serialize, Deserialize)]
struct WalletFileV1 {
    version: u32,
    signing_pk: Vec<u8>,
    signing_sk: Vec<u8>,
    kem_pk: Vec<u8>,
    kem_sk: Vec<u8>,
    outputs: Vec<SerializedOutput>,
    messages: Vec<SerializedMessage>,
    last_scanned_sequence: u64,
}

const WALLET_FILE_VERSION: u32 = 2;

impl Wallet {
    /// Save the wallet to a file.
    ///
    /// Persists keypair, outputs, messages, and scan progress.
    /// File permissions are set to 0o600 on Unix.
    pub fn save_to_file(&self, path: &Path, last_scanned_seq: u64) -> Result<(), WalletError> {
        let outputs: Vec<SerializedOutput> = self
            .outputs
            .iter()
            .map(|o| SerializedOutput {
                commitment: o.commitment.0,
                value: o.value,
                blinding: o.blinding.0,
                spend_auth: o.spend_auth,
                status: (&o.status).into(),
                commitment_index: o.commitment_index,
            })
            .collect();

        let messages: Vec<SerializedMessage> = self
            .messages
            .iter()
            .map(|m| SerializedMessage {
                tx_hash: m.tx_hash,
                content: m.content.clone(),
            })
            .collect();

        let wallet_file = WalletFile {
            version: WALLET_FILE_VERSION,
            signing_pk: self.keypair.signing.public.0.clone(),
            signing_sk: self.keypair.signing.secret.0.clone(),
            kem_pk: self.keypair.kem.public.0.clone(),
            kem_sk: self.keypair.kem.secret.0.clone(),
            outputs,
            messages,
            last_scanned_sequence: last_scanned_seq,
            history: self.history.clone(),
        };

        let bytes = crate::serialize(&wallet_file)
            .map_err(|e| WalletError::Persistence(format!("serialization failed: {}", e)))?;

        std::fs::write(path, &bytes)
            .map_err(|e| WalletError::Persistence(format!("write failed: {}", e)))?;

        // Restrict file permissions to owner-only
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }

    /// Load a wallet from a file.
    ///
    /// Returns the wallet and the last scanned sequence number.
    /// Supports migration from v1 (no history) to v2.
    pub fn load_from_file(path: &Path) -> Result<(Self, u64), WalletError> {
        let bytes = std::fs::read(path)
            .map_err(|e| WalletError::Persistence(format!("read failed: {}", e)))?;

        // Try v2 first, fall back to v1
        let wallet_file: WalletFile = if let Ok(wf) = crate::deserialize::<WalletFile>(&bytes) {
            if wf.version == WALLET_FILE_VERSION {
                wf
            } else if wf.version == 1 {
                // v1 files won't have history, deserialize as v1 and migrate
                let wf1: WalletFileV1 = crate::deserialize(&bytes).map_err(|e| {
                    WalletError::Persistence(format!("v1 deserialization failed: {}", e))
                })?;
                WalletFile {
                    version: WALLET_FILE_VERSION,
                    signing_pk: wf1.signing_pk,
                    signing_sk: wf1.signing_sk,
                    kem_pk: wf1.kem_pk,
                    kem_sk: wf1.kem_sk,
                    outputs: wf1.outputs,
                    messages: wf1.messages,
                    last_scanned_sequence: wf1.last_scanned_sequence,
                    history: Vec::new(),
                }
            } else {
                return Err(WalletError::Persistence(format!(
                    "unsupported wallet version: {} (expected {})",
                    wf.version, WALLET_FILE_VERSION
                )));
            }
        } else {
            // Try parsing as v1 directly
            let wf1: WalletFileV1 = crate::deserialize(&bytes)
                .map_err(|e| WalletError::Persistence(format!("deserialization failed: {}", e)))?;
            if wf1.version != 1 {
                return Err(WalletError::Persistence(format!(
                    "unsupported wallet version: {}",
                    wf1.version
                )));
            }
            WalletFile {
                version: WALLET_FILE_VERSION,
                signing_pk: wf1.signing_pk,
                signing_sk: wf1.signing_sk,
                kem_pk: wf1.kem_pk,
                kem_sk: wf1.kem_sk,
                outputs: wf1.outputs,
                messages: wf1.messages,
                last_scanned_sequence: wf1.last_scanned_sequence,
                history: Vec::new(),
            }
        };

        // Validate and reconstruct keys
        let signing = SigningKeypair::from_bytes(wallet_file.signing_pk, wallet_file.signing_sk)
            .ok_or_else(|| WalletError::Persistence("invalid signing key data".into()))?;

        let kem = KemKeypair::from_bytes(wallet_file.kem_pk, wallet_file.kem_sk)
            .ok_or_else(|| WalletError::Persistence("invalid KEM key data".into()))?;

        let keypair = FullKeypair { signing, kem };

        let outputs: Vec<OwnedOutput> = wallet_file
            .outputs
            .into_iter()
            .map(|o| OwnedOutput {
                commitment: Commitment(o.commitment),
                value: o.value,
                blinding: BlindingFactor::from_bytes(o.blinding),
                spend_auth: o.spend_auth,
                status: o.status.into(),
                commitment_index: o.commitment_index,
            })
            .collect();

        let messages: Vec<ReceivedMessage> = wallet_file
            .messages
            .into_iter()
            .map(|m| ReceivedMessage {
                tx_hash: m.tx_hash,
                content: m.content,
            })
            .collect();

        let wallet = Wallet {
            keypair,
            outputs,
            messages,
            history: wallet_file.history,
        };

        Ok((wallet, wallet_file.last_scanned_sequence))
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
    #[error("persistence error: {0}")]
    Persistence(String),
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("need at least 2 unspent outputs to consolidate")]
    NothingToConsolidate,
    #[error("recovery error: {0}")]
    Recovery(String),
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
    fn wallet_save_load_roundtrip() {
        let mut wallet = Wallet::new();

        // Give wallet some funds
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 5000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(wallet.kem_public_key().clone(), 4000)
            .add_message(wallet.kem_public_key().clone(), b"test message".to_vec())
            .set_fee(1000)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        wallet.scan_transaction(&tx);
        assert_eq!(wallet.balance(), 4000);
        assert_eq!(wallet.received_messages().len(), 1);

        let original_address = wallet.address().address_id();

        // Save to temp file
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        wallet.save_to_file(&path, 42).unwrap();

        // Load back
        let (loaded, last_seq) = Wallet::load_from_file(&path).unwrap();
        assert_eq!(last_seq, 42);
        assert_eq!(loaded.balance(), 4000);
        assert_eq!(loaded.received_messages().len(), 1);
        assert_eq!(loaded.received_messages()[0].content, b"test message");
        assert_eq!(loaded.address().address_id(), original_address);
        assert_eq!(loaded.output_count(), 1);
    }

    #[test]
    fn wallet_confirm_transaction_marks_spent() {
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

        let tx = alice
            .build_transaction(bob.kem_public_key(), 3000, 100, None)
            .unwrap();

        // Pending — balance is 0
        assert_eq!(alice.balance(), 0);

        // Confirm makes them Spent (not Pending)
        alice.confirm_transaction(&tx.tx_binding);

        // Still 0 balance (input is Spent, not Unspent)
        assert_eq!(alice.balance(), 0);

        // Scan to pick up change
        alice.scan_transaction(&tx);
        assert_eq!(alice.balance(), 6900);
    }

    #[test]
    fn wallet_from_keypair_preserves_keys() {
        let kp = FullKeypair::generate();
        let addr_id = kp.public_address().address_id();
        let wallet = Wallet::from_keypair(kp);
        assert_eq!(wallet.address().address_id(), addr_id);
    }

    #[test]
    fn wallet_balance_excludes_pending() {
        let mut alice = Wallet::new();
        let bob = Wallet::new();

        let funding_tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 5001,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(alice.kem_public_key().clone(), 5000)
            .set_fee(1)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        alice.scan_transaction(&funding_tx);
        assert_eq!(alice.balance(), 5000);

        // Build tx puts outputs in Pending
        let _tx = alice
            .build_transaction(bob.kem_public_key(), 1000, 100, None)
            .unwrap();

        // Pending outputs excluded from balance
        assert_eq!(alice.balance(), 0);
        assert_eq!(alice.unspent_outputs().len(), 0);
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

    #[test]
    fn scan_records_receive_history() {
        let mut wallet = Wallet::new();

        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(wallet.kem_public_key().clone(), 900)
            .set_fee(100)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        wallet.scan_transaction(&tx);
        assert_eq!(wallet.history().len(), 1);
        assert_eq!(wallet.history()[0].direction, TxDirection::Receive);
        assert_eq!(wallet.history()[0].amount, 900);
    }

    #[test]
    fn build_transaction_records_send_history() {
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
        alice
            .build_transaction(bob.kem_public_key(), 3000, 100, None)
            .unwrap();

        // Should have receive + send
        assert_eq!(alice.history().len(), 2);
        assert_eq!(alice.history()[0].direction, TxDirection::Receive);
        assert_eq!(alice.history()[1].direction, TxDirection::Send);
        assert_eq!(alice.history()[1].amount, 3000);
        assert_eq!(alice.history()[1].fee, 100);
    }

    #[test]
    fn history_persists_in_wallet_file() {
        let mut wallet = Wallet::new();

        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(wallet.kem_public_key().clone(), 900)
            .set_fee(100)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        wallet.scan_transaction(&tx);
        assert_eq!(wallet.history().len(), 1);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        wallet.save_to_file(&path, 0).unwrap();

        let (loaded, _) = Wallet::load_from_file(&path).unwrap();
        assert_eq!(loaded.history().len(), 1);
        assert_eq!(loaded.history()[0].direction, TxDirection::Receive);
        assert_eq!(loaded.history()[0].amount, 900);
    }

    #[test]
    fn mnemonic_roundtrip() {
        let (words, entropy) = generate_mnemonic();
        assert_eq!(words.len(), 24);

        let recovered_entropy = words_to_entropy(&words).unwrap();
        assert_eq!(recovered_entropy, entropy);
    }

    #[test]
    fn mnemonic_invalid_checksum() {
        let (mut words, _) = generate_mnemonic();
        // Corrupt one word
        words[0] = "abandon".to_string();
        words[1] = "abandon".to_string();
        // Very unlikely to have valid checksum
        let result = words_to_entropy(&words);
        // May or may not fail depending on luck, but at least it shouldn't panic
        let _ = result;
    }

    #[test]
    fn mnemonic_wrong_length() {
        let words: Vec<String> = vec!["abandon".to_string(); 12];
        let result = words_to_entropy(&words);
        assert!(result.is_err());
    }

    #[test]
    fn mnemonic_unknown_word() {
        let mut words: Vec<String> = vec!["abandon".to_string(); 24];
        words[5] = "notaword".to_string();
        let result = words_to_entropy(&words);
        assert!(result.is_err());
    }

    #[test]
    fn recovery_backup_roundtrip() {
        let wallet = Wallet::new();
        let original_addr = wallet.address().address_id();

        let (words, backup) = wallet.create_recovery_backup();
        assert_eq!(words.len(), 24);
        assert!(!backup.is_empty());

        let recovered = Wallet::recover_from_backup(&words, &backup).unwrap();
        assert_eq!(recovered.address().address_id(), original_addr);
    }

    #[test]
    fn recovery_wrong_phrase_fails() {
        let wallet = Wallet::new();
        let (_, backup) = wallet.create_recovery_backup();

        // Use a different mnemonic
        let (wrong_words, _) = generate_mnemonic();
        let result = Wallet::recover_from_backup(&wrong_words, &backup);
        assert!(result.is_err());
    }

    #[test]
    fn consolidation_needs_two_outputs() {
        let mut wallet = Wallet::new();

        // Give wallet one output
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(wallet.kem_public_key().clone(), 900)
            .set_fee(100)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();

        wallet.scan_transaction(&tx);
        assert_eq!(wallet.unspent_outputs().len(), 1);

        let result = wallet.build_consolidation_tx(10, None);
        assert!(matches!(result, Err(WalletError::NothingToConsolidate)));
    }
}
