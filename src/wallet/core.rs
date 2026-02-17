//! Wallet for managing Umbra keys, scanning for outputs, and building transactions.
//!
//! The wallet:
//! - Generates and stores post-quantum key material
//! - Scans the DAG for outputs addressed to us (via stealth address detection)
//! - Decrypts note data (amounts, blinding factors) from our outputs
//! - Builds and signs transactions for spending

use std::path::Path;

use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::commitment::{BlindingFactor, Commitment};
use crate::crypto::keys::{FullKeypair, KemKeypair, SharedSecret, SigningKeypair};
use crate::crypto::stealth::derive_spend_auth;
use crate::transaction::builder::{decode_note, InputSpec, TransactionBuilder};
use crate::transaction::{Transaction, TxOutput};
use crate::Hash;

const MAX_HISTORY_ENTRIES: usize = 10_000;

pub const PENDING_EXPIRY_EPOCHS: u64 = 10;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TxDirection {
    Send,
    Receive,
    Coinbase,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxHistoryEntry {
    pub tx_id: Hash,
    pub direction: TxDirection,
    pub amount: u64,
    pub fee: u64,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SpendStatus {
    Unspent,
    Pending {
        tx_binding: Hash,
        created_epoch: u64,
    },
    Spent,
}

#[derive(Clone, Debug)]
pub struct OwnedOutput {
    pub commitment: Commitment,
    pub value: u64,
    pub blinding: BlindingFactor,
    pub spend_auth: Hash,
    pub status: SpendStatus,
    pub commitment_index: Option<usize>,
}

impl Drop for OwnedOutput {
    fn drop(&mut self) {
        self.value.zeroize();
        self.spend_auth.zeroize();
        // blinding: BlindingFactor already implements ZeroizeOnDrop
    }
}

#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    pub tx_hash: Hash,
    pub content: Vec<u8>,
}

#[derive(Clone)]
pub struct Wallet {
    keypair: FullKeypair,
    outputs: Vec<OwnedOutput>,
    messages: Vec<ReceivedMessage>,
    history: Vec<TxHistoryEntry>,
    /// Sequence number of the last finalized vertex scanned by `sync()`.
    /// Initialized to `u64::MAX` (sentinel for "start from the beginning").
    last_scanned_sequence: u64,
}

impl Wallet {
    pub fn new() -> Self {
        Wallet {
            keypair: FullKeypair::generate(),
            outputs: Vec::new(),
            messages: Vec::new(),
            history: Vec::new(),
            last_scanned_sequence: u64::MAX,
        }
    }

    pub fn from_keypair(keypair: FullKeypair) -> Self {
        Wallet {
            keypair,
            outputs: Vec::new(),
            messages: Vec::new(),
            history: Vec::new(),
            last_scanned_sequence: u64::MAX,
        }
    }

    pub fn address(&self) -> crate::crypto::keys::PublicAddress {
        self.keypair.public_address()
    }

    pub fn kem_public_key(&self) -> &crate::crypto::keys::KemPublicKey {
        &self.keypair.kem.public
    }

    pub fn scan_transaction(&mut self, tx: &Transaction) {
        self.scan_transaction_with_state(tx, None);
    }

    pub fn scan_transaction_with_state(
        &mut self,
        tx: &Transaction,
        state: Option<&crate::state::ChainState>,
    ) {
        let tx_id = tx.tx_id();
        let epoch = state.map(|s| s.epoch()).unwrap_or(0);
        let mut received_amount = 0u64;
        for (idx, output) in tx.outputs.iter().enumerate() {
            if let Some(mut owned) = self.try_claim_output(output, idx as u32) {
                if let Some(st) = state {
                    owned.commitment_index = st.find_commitment(&owned.commitment);
                }
                if self
                    .outputs
                    .iter()
                    .any(|o| o.commitment == owned.commitment)
                {
                    continue;
                }
                received_amount = received_amount.saturating_add(owned.value);
                self.outputs.push(owned);
            }
        }
        if received_amount > 0 {
            self.push_history(TxHistoryEntry {
                tx_id: tx_id.0,
                direction: TxDirection::Receive,
                amount: received_amount,
                fee: 0,
                epoch,
            });
        }
        for msg in &tx.messages {
            if let Some(plaintext) = msg.payload.decrypt(&self.keypair.kem) {
                self.messages.push(ReceivedMessage {
                    tx_hash: tx_id.0,
                    content: plaintext,
                });
            }
        }
    }

    pub fn resolve_commitment_indices(&mut self, state: &crate::state::ChainState) {
        for output in &mut self.outputs {
            if output.commitment_index.is_none() {
                output.commitment_index = state.find_commitment(&output.commitment);
            }
        }
    }

    fn try_claim_output(&self, output: &TxOutput, output_index: u32) -> Option<OwnedOutput> {
        let stealth_info = output
            .stealth_address
            .try_detect_at_index(&self.keypair.kem, output_index)?;
        let signing_fingerprint = self.keypair.signing.public.fingerprint();
        let spend_auth = derive_spend_auth(
            &stealth_info.shared_secret,
            &signing_fingerprint,
            output_index,
        );
        let shared_secret = SharedSecret(stealth_info.shared_secret);
        let note_data = output
            .encrypted_note
            .decrypt_with_shared_secret(&shared_secret)?;
        let (value, blinding) = decode_note(&note_data)?;
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

    pub fn balance(&self) -> u64 {
        self.outputs
            .iter()
            .filter(|o| o.status == SpendStatus::Unspent)
            .fold(0u64, |acc, o| acc.saturating_add(o.value))
    }

    pub fn unspent_outputs(&self) -> Vec<&OwnedOutput> {
        self.outputs
            .iter()
            .filter(|o| o.status == SpendStatus::Unspent)
            .collect()
    }

    pub fn received_messages(&self) -> &[ReceivedMessage] {
        &self.messages
    }

    pub fn build_transaction(
        &mut self,
        recipient_kem_pk: &crate::crypto::keys::KemPublicKey,
        amount: u64,
        message: Option<Vec<u8>>,
    ) -> Result<Transaction, WalletError> {
        self.build_transaction_with_state(recipient_kem_pk, amount, message, None)
    }

    /// Select coins to cover `amount` + fee, minimizing input count.
    ///
    /// Returns (selected_indices, input_sum, num_outputs, fee). The algorithm:
    /// 1. Sort unspent UTXOs by value descending (prefer fewer, larger inputs)
    /// 2. Try single-UTXO solutions first (1 STARK proof = cheapest)
    /// 3. Fall back to multi-UTXO combinations, starting from 2 inputs
    ///
    /// Because fee does not depend on output count, there is no circular
    /// dependency and no "dead zone": for a given input count, the fee is
    /// fixed, and we simply check input_sum >= amount + fee.
    fn select_coins(
        &self,
        amount: u64,
        msg_bytes: usize,
    ) -> Result<(Vec<usize>, u64, usize, u64), WalletError> {
        // Early overflow check: if amount + minimum possible fee overflows, bail.
        let min_fee = crate::constants::compute_weight_fee(1, msg_bytes);
        amount
            .checked_add(min_fee)
            .ok_or(WalletError::ArithmeticOverflow)?;

        // Collect unspent UTXOs as (original_index, value), sorted by value descending.
        let mut candidates: Vec<(usize, u64)> = self
            .outputs
            .iter()
            .enumerate()
            .filter(|(_, o)| o.status == SpendStatus::Unspent)
            .map(|(i, o)| (i, o.value))
            .collect();
        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        let total_available: u64 = candidates.iter().map(|(_, v)| *v).sum();

        // Phase 1: Try single-UTXO solutions (1 input = 1 STARK proof, cheapest).
        if let Some(result) = Self::try_single_utxo(&candidates, amount, msg_bytes) {
            return Ok(result);
        }

        // Phase 2: Try multi-UTXO combinations for k = 2..MAX_TX_IO inputs.
        let max_inputs = candidates.len().min(crate::constants::MAX_TX_IO);
        for k in 2..=max_inputs {
            if let Some(result) = Self::try_multi_utxo(&candidates, amount, msg_bytes, k) {
                return Ok(result);
            }
        }

        // No feasible combination found.
        Err(WalletError::InsufficientFunds {
            available: total_available,
            needed: amount.saturating_add(min_fee),
        })
    }

    /// Phase 1: Find a single UTXO that can fund the transaction.
    /// Picks the smallest UTXO where value >= amount + fee(1), preferring
    /// exact matches (no change output needed).
    fn try_single_utxo(
        candidates: &[(usize, u64)],
        amount: u64,
        msg_bytes: usize,
    ) -> Option<(Vec<usize>, u64, usize, u64)> {
        let fee = crate::constants::compute_weight_fee(1, msg_bytes);
        let needed = amount.checked_add(fee)?;
        // Candidates are sorted descending. Find the smallest that covers needed.
        let mut best: Option<(usize, u64)> = None;
        for &(idx, value) in candidates {
            if value >= needed {
                best = Some((idx, value));
            }
        }
        let (idx, value) = best?;
        let num_outputs = if value == needed { 1 } else { 2 };
        Some((vec![idx], value, num_outputs, fee))
    }

    /// Phase 2: Find a combination of exactly `k` UTXOs that funds the transaction.
    ///
    /// Strategy: take the (k-1) smallest candidates as a fixed base, then find
    /// the smallest remaining UTXO that pushes the total past the threshold.
    fn try_multi_utxo(
        candidates: &[(usize, u64)],
        amount: u64,
        msg_bytes: usize,
        k: usize,
    ) -> Option<(Vec<usize>, u64, usize, u64)> {
        if candidates.len() < k {
            return None;
        }
        let fee = crate::constants::compute_weight_fee(k, msg_bytes);
        let needed = amount.checked_add(fee)?;

        // candidates is sorted descending. The (k-1) smallest are the last (k-1).
        let base_start = candidates.len() - (k - 1);
        let base = &candidates[base_start..];
        let base_sum: u64 = base.iter().map(|(_, v)| *v).sum();
        let base_indices: Vec<usize> = base.iter().map(|(idx, _)| *idx).collect();

        // Try each remaining candidate (ascending = reverse of descending slice).
        // Pick the smallest that pushes total past needed.
        let remaining = &candidates[..base_start];
        for &(idx, value) in remaining.iter().rev() {
            let total = base_sum.saturating_add(value);
            if total >= needed {
                let mut indices = base_indices.clone();
                indices.push(idx);
                let num_outputs = if total == needed { 1 } else { 2 };
                return Some((indices, total, num_outputs, fee));
            }
        }
        None
    }

    pub fn build_transaction_with_state(
        &mut self,
        recipient_kem_pk: &crate::crypto::keys::KemPublicKey,
        amount: u64,
        message: Option<Vec<u8>>,
        state: Option<&crate::state::ChainState>,
    ) -> Result<Transaction, WalletError> {
        // Estimate the encrypted ciphertext size: the builder uses ciphertext.len()
        // which is the padded symmetric ciphertext (4-byte length prefix + plaintext,
        // rounded up to ENCRYPT_PADDING_BUCKET=64). KEM ciphertext is a separate field
        // not counted in message_bytes for fee computation.
        let msg_bytes_estimate: usize = message
            .as_ref()
            .map(|m| m.len().saturating_add(4).div_ceil(64).saturating_mul(64))
            .unwrap_or(0);

        let (selected, selected_total, num_outputs, fee) =
            self.select_coins(amount, msg_bytes_estimate)?;

        let total_needed = amount
            .checked_add(fee)
            .ok_or(WalletError::ArithmeticOverflow)?;
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
        builder = builder.add_output(recipient_kem_pk.clone(), amount);
        if num_outputs == 2 {
            let change = selected_total - total_needed;
            builder = builder.add_output(self.keypair.kem.public.clone(), change);
        }
        if let Some(msg_data) = message {
            builder = builder.add_message(recipient_kem_pk.clone(), msg_data);
        }
        let tx = builder.build().map_err(WalletError::Build)?;
        let tx_binding = tx.tx_binding;
        let epoch = state.map(|s| s.epoch()).unwrap_or(0);
        for &idx in &selected {
            self.outputs[idx].status = SpendStatus::Pending {
                tx_binding,
                created_epoch: epoch,
            };
        }
        self.push_history(TxHistoryEntry {
            tx_id: tx.tx_id().0,
            direction: TxDirection::Send,
            amount,
            fee: tx.fee,
            epoch,
        });
        Ok(tx)
    }

    pub fn confirm_transaction(&mut self, tx_binding: &Hash) {
        for output in &mut self.outputs {
            if let SpendStatus::Pending {
                tx_binding: ref tb, ..
            } = output.status
            {
                if tb == tx_binding {
                    output.status = SpendStatus::Spent;
                    output.spend_auth.zeroize();
                    output.blinding.zeroize();
                }
            }
        }
    }

    /// Sync wallet against finalized chain state.
    ///
    /// Scans all finalized vertices since the last sync, discovers outputs
    /// addressed to this wallet, auto-confirms pending transactions, and
    /// resolves commitment indices.
    pub fn sync(&mut self, node_state: &crate::node::NodeState) -> Result<(), WalletError> {
        // On first sync, scan the genesis coinbase (seq 0) which is not stored
        // as a regular vertex in the vertices tree but has a coinbase output.
        if self.last_scanned_sequence == u64::MAX {
            if let Ok(Some(cb)) = node_state.get_coinbase_output(0) {
                self.scan_coinbase_output(&cb, None);
            }
        }

        let batch_size = 100u32;
        loop {
            let vertices = node_state
                .get_finalized_vertices_after(self.last_scanned_sequence, batch_size)
                .map_err(|e| WalletError::Rpc(format!("storage: {}", e)))?;
            if vertices.is_empty() {
                break;
            }
            for (seq, vertex) in &vertices {
                for tx in &vertex.transactions {
                    self.scan_transaction(tx);
                    self.confirm_transaction(&tx.tx_binding);
                }
                if let Ok(Some(cb)) = node_state.get_coinbase_output(*seq) {
                    self.scan_coinbase_output(&cb, None);
                }
                self.last_scanned_sequence = *seq;
            }
            if vertices.len() < batch_size as usize {
                break;
            }
        }
        node_state.with_chain_state(|cs| self.resolve_commitment_indices(cs));
        Ok(())
    }

    /// Build, submit, and track a transaction in one call.
    ///
    /// Resolves commitment indices, builds the transaction with chain state,
    /// submits to the mempool, scans the transaction for change outputs,
    /// and confirms the spend.
    pub fn send(
        &mut self,
        recipient: &crate::crypto::keys::KemPublicKey,
        amount: u64,
        message: Option<Vec<u8>>,
        node_state: &mut crate::node::NodeState,
    ) -> Result<Transaction, WalletError> {
        node_state.with_chain_state(|cs| self.resolve_commitment_indices(cs));
        let tx = node_state.with_chain_state(|cs| {
            self.build_transaction_with_state(recipient, amount, message, Some(cs))
        })?;
        node_state
            .submit_transaction(tx.clone())
            .map_err(|e| WalletError::Rpc(e.to_string()))?;
        self.scan_transaction(&tx);
        self.confirm_transaction(&tx.tx_binding);
        Ok(tx)
    }

    pub fn cancel_transaction(&mut self, tx_binding: &Hash) {
        for output in &mut self.outputs {
            if let SpendStatus::Pending {
                tx_binding: ref tb, ..
            } = output.status
            {
                if tb == tx_binding {
                    output.status = SpendStatus::Unspent;
                }
            }
        }
    }

    pub fn expire_pending(&mut self, current_epoch: u64, max_age_epochs: u64) -> usize {
        let mut count = 0;
        for output in &mut self.outputs {
            if let SpendStatus::Pending { created_epoch, .. } = output.status {
                if current_epoch > created_epoch + max_age_epochs {
                    output.status = SpendStatus::Unspent;
                    count += 1;
                }
            }
        }
        count
    }

    pub fn scan_coinbase_output(
        &mut self,
        output: &TxOutput,
        state: Option<&crate::state::ChainState>,
    ) {
        if let Some(mut owned) = self.try_claim_output(output, 0) {
            if self
                .outputs
                .iter()
                .any(|o| o.commitment == owned.commitment)
            {
                return;
            }
            let epoch = state.map(|s| s.epoch()).unwrap_or(0);
            if let Some(st) = state {
                owned.commitment_index = st.find_commitment(&owned.commitment);
            }
            let amount = owned.value;
            self.outputs.push(owned);
            self.push_history(TxHistoryEntry {
                tx_id: [0u8; 32],
                direction: TxDirection::Coinbase,
                amount,
                fee: 0,
                epoch,
            });
        }
    }

    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }
    pub fn history(&self) -> &[TxHistoryEntry] {
        &self.history
    }

    fn push_history(&mut self, entry: TxHistoryEntry) {
        self.history.push(entry);
        if self.history.len() > MAX_HISTORY_ENTRIES {
            self.history
                .drain(..self.history.len() - MAX_HISTORY_ENTRIES);
        }
    }

    pub fn build_consolidation_tx(
        &mut self,
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
        let fee = crate::constants::compute_weight_fee(unspent.len(), 0);
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
        let consolidated_amount = total - fee;
        builder = builder.add_output(self.keypair.kem.public.clone(), consolidated_amount);
        let tx = builder.build().map_err(WalletError::Build)?;
        let tx_binding = tx.tx_binding;
        let epoch = state.map(|s| s.epoch()).unwrap_or(0);
        for &idx in &unspent {
            self.outputs[idx].status = SpendStatus::Pending {
                tx_binding,
                created_epoch: epoch,
            };
        }
        self.push_history(TxHistoryEntry {
            tx_id: tx.tx_id().0,
            direction: TxDirection::Send,
            amount: consolidated_amount,
            fee,
            epoch,
        });
        Ok(tx)
    }

    pub fn keypair(&self) -> &FullKeypair {
        &self.keypair
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

// -- Recovery -----------------------------------------------------------------

pub fn generate_mnemonic() -> (Vec<String>, [u8; 32]) {
    let entropy: [u8; 32] = rand::random();
    let words = entropy_to_words(&entropy);
    (words, entropy)
}

fn entropy_to_words(entropy: &[u8; 32]) -> Vec<String> {
    use super::bip39_words::WORDLIST;
    let checksum = blake3::hash(entropy).as_bytes()[0];
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

pub fn words_to_entropy(words: &[String]) -> Result<[u8; 32], WalletError> {
    use super::bip39_words::WORDLIST;
    if words.len() != 24 {
        return Err(WalletError::Recovery(format!(
            "expected 24 words, got {}",
            words.len()
        )));
    }
    let mut bits = Vec::with_capacity(264);
    for word in words {
        let lower = word.to_lowercase();
        let index = WORDLIST
            .binary_search(&lower.as_str())
            .map_err(|_| WalletError::Recovery(format!("unknown word: {}", word)))?;
        for i in (0..11).rev() {
            bits.push(((index >> i) & 1) as u8);
        }
    }
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
    bits.zeroize();
    let expected_checksum = blake3::hash(&entropy).as_bytes()[0];
    if checksum != expected_checksum {
        entropy.zeroize();
        return Err(WalletError::Recovery("invalid mnemonic checksum".into()));
    }
    Ok(entropy)
}

impl Wallet {
    pub fn create_recovery_backup(&self) -> (Vec<String>, Vec<u8>) {
        let (words, mut entropy) = generate_mnemonic();
        let mut key = blake3::derive_key("umbra.wallet.recovery", &entropy);
        entropy.zeroize();
        let mut material = zeroize::Zeroizing::new(Vec::new());
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
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
        let mut nonce = [0u8; RECOVERY_NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let encrypted = cipher
            .encrypt(XNonce::from_slice(&nonce), material.as_ref())
            .expect("recovery backup encryption failed");
        key.zeroize();
        let mut backup = Vec::with_capacity(RECOVERY_NONCE_SIZE + encrypted.len());
        backup.extend_from_slice(&nonce);
        backup.extend_from_slice(&encrypted);
        (words, backup)
    }

    pub fn recover_from_backup(
        words: &[String],
        encrypted_backup: &[u8],
    ) -> Result<Self, WalletError> {
        let mut entropy = words_to_entropy(words)?;
        let mut key = blake3::derive_key("umbra.wallet.recovery", &entropy);
        entropy.zeroize();
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
        // Minimum: nonce(24) + tag(16)
        let min_len = RECOVERY_NONCE_SIZE + 16;
        if encrypted_backup.len() < min_len {
            key.zeroize();
            return Err(WalletError::Recovery("backup too short".into()));
        }
        let nonce: [u8; RECOVERY_NONCE_SIZE] =
            encrypted_backup[..RECOVERY_NONCE_SIZE]
                .try_into()
                .map_err(|_| WalletError::Recovery("truncated backup".into()))?;
        let ciphertext = &encrypted_backup[RECOVERY_NONCE_SIZE..];
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let material = zeroize::Zeroizing::new(
            cipher
                .decrypt(XNonce::from_slice(&nonce), ciphertext)
                .map_err(|_| {
                    WalletError::Recovery("invalid mnemonic or corrupted backup".into())
                })?,
        );
        key.zeroize();
        let mut pos = 0;
        let read_vec = |data: &[u8], pos: &mut usize| -> Result<Vec<u8>, WalletError> {
            if *pos + 4 > data.len() {
                return Err(WalletError::Recovery("truncated backup".into()));
            }
            let len = u32::from_le_bytes(
                data[*pos..*pos + 4]
                    .try_into()
                    .map_err(|_| WalletError::Recovery("truncated backup".into()))?,
            ) as usize;
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
        drop(material);
        let signing = SigningKeypair::from_bytes(spk, ssk)
            .ok_or_else(|| WalletError::Recovery("invalid signing key in backup".into()))?;
        let kem = KemKeypair::from_bytes(kpk, ksk)
            .ok_or_else(|| WalletError::Recovery("invalid KEM key in backup".into()))?;
        Ok(Wallet {
            keypair: FullKeypair { signing, kem },
            outputs: Vec::new(),
            messages: Vec::new(),
            history: Vec::new(),
            last_scanned_sequence: u64::MAX,
        })
    }
}

const RECOVERY_NONCE_SIZE: usize = 24;

// -- Persistence --------------------------------------------------------------

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
    Pending {
        tx_binding: Hash,
        created_epoch: u64,
    },
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
            SpendStatus::Pending {
                tx_binding,
                created_epoch,
            } => SerializedSpendStatus::Pending {
                tx_binding: *tx_binding,
                created_epoch: *created_epoch,
            },
            SpendStatus::Spent => SerializedSpendStatus::Spent,
        }
    }
}

impl From<SerializedSpendStatus> for SpendStatus {
    fn from(s: SerializedSpendStatus) -> Self {
        match s {
            SerializedSpendStatus::Unspent => SpendStatus::Unspent,
            SerializedSpendStatus::Pending {
                tx_binding,
                created_epoch,
            } => SpendStatus::Pending {
                tx_binding,
                created_epoch,
            },
            SerializedSpendStatus::Spent => SpendStatus::Spent,
        }
    }
}

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
const ENCRYPTED_MAGIC: [u8; 4] = [0x55, 0x4D, 0x42, 0x33]; // "UMB3" (Argon2id + XChaCha20-Poly1305)
const WALLET_SALT_SIZE: usize = 32;
const WALLET_NONCE_SIZE: usize = 24;

/// Argon2id parameters for wallet key derivation.
/// 64 MiB memory, 3 iterations, 4 lanes - balances security vs. unlock time.
/// Parallelism increased from 1 to 4 for improved GPU/ASIC resistance.
fn derive_wallet_key_argon2(password: &str, salt: &[u8; WALLET_SALT_SIZE]) -> [u8; 32] {
    use argon2::Argon2;
    let params = argon2::Params::new(65536, 3, 4, Some(32)).expect("valid Argon2 params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2 hash_password_into failed");
    key
}

impl Wallet {
    pub fn save_to_file(
        &self,
        path: &Path,
        last_scanned_seq_override: u64,
        password: Option<&str>,
    ) -> Result<(), WalletError> {
        let last_scanned_seq = if last_scanned_seq_override != u64::MAX {
            last_scanned_seq_override
        } else {
            self.last_scanned_sequence
        };
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
        let plaintext = crate::serialize(&wallet_file)
            .map_err(|e| WalletError::Persistence(format!("serialize failed: {}", e)))?;
        let bytes = if let Some(pw) = password {
            use chacha20poly1305::aead::{Aead, KeyInit};
            use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
            let salt: [u8; WALLET_SALT_SIZE] = rand::random();
            let mut nonce = [0u8; WALLET_NONCE_SIZE];
            rand::rng().fill_bytes(&mut nonce);
            let mut enc_key = derive_wallet_key_argon2(pw, &salt);
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&enc_key));
            let ciphertext = cipher
                .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
                .map_err(|_| WalletError::Persistence("encryption failed".into()))?;
            enc_key.zeroize();
            let mut out =
                Vec::with_capacity(4 + WALLET_SALT_SIZE + WALLET_NONCE_SIZE + ciphertext.len());
            out.extend_from_slice(&ENCRYPTED_MAGIC);
            out.extend_from_slice(&salt);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);
            out
        } else {
            plaintext
        };
        let tmp_path = path.with_extension("dat.tmp");
        {
            let mut file = std::fs::File::create(&tmp_path)
                .map_err(|e| WalletError::Persistence(format!("create failed: {}", e)))?;
            std::io::Write::write_all(&mut file, &bytes)
                .map_err(|e| WalletError::Persistence(format!("write failed: {}", e)))?;
            file.sync_all()
                .map_err(|e| WalletError::Persistence(format!("fsync failed: {}", e)))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| WalletError::Persistence(format!("chmod failed: {}", e)))?;
        }
        std::fs::rename(&tmp_path, path)
            .map_err(|e| WalletError::Persistence(format!("rename failed: {}", e)))?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    pub fn load_from_file(path: &Path, password: Option<&str>) -> Result<(Self, u64), WalletError> {
        let raw = std::fs::read(path)
            .map_err(|e| WalletError::Persistence(format!("read failed: {}", e)))?;
        let is_encrypted = raw.len() >= 4 && raw[..4] == ENCRYPTED_MAGIC;
        let bytes = if is_encrypted {
            use chacha20poly1305::aead::{Aead, KeyInit};
            use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
            // Minimum: magic(4) + salt(32) + nonce(24) + tag(16)
            let min_len = 4 + WALLET_SALT_SIZE + WALLET_NONCE_SIZE + 16;
            if raw.len() < min_len {
                return Err(WalletError::Persistence(
                    "encrypted wallet file truncated".into(),
                ));
            }
            let pw = password.ok_or_else(|| {
                WalletError::Persistence("wallet file is encrypted; password required".into())
            })?;
            let salt: [u8; WALLET_SALT_SIZE] = raw[4..4 + WALLET_SALT_SIZE]
                .try_into()
                .map_err(|_| WalletError::Persistence("truncated salt".into()))?;
            let nonce: [u8; WALLET_NONCE_SIZE] = raw
                [4 + WALLET_SALT_SIZE..4 + WALLET_SALT_SIZE + WALLET_NONCE_SIZE]
                .try_into()
                .map_err(|_| WalletError::Persistence("truncated nonce".into()))?;
            let ciphertext = &raw[4 + WALLET_SALT_SIZE + WALLET_NONCE_SIZE..];
            let mut enc_key = derive_wallet_key_argon2(pw, &salt);
            let cipher = XChaCha20Poly1305::new(Key::from_slice(&enc_key));
            let plaintext = cipher
                .decrypt(XNonce::from_slice(&nonce), ciphertext)
                .map_err(|_| {
                    WalletError::Persistence(
                        "decryption failed: wrong password or corrupted file".into(),
                    )
                })?;
            enc_key.zeroize();
            plaintext
        } else {
            raw
        };
        let wallet_file: WalletFile = if let Ok(wf) = crate::deserialize::<WalletFile>(&bytes) {
            if wf.version == WALLET_FILE_VERSION {
                wf
            } else if wf.version == 1 {
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
            last_scanned_sequence: wallet_file.last_scanned_sequence,
        };
        Ok((wallet, wallet_file.last_scanned_sequence))
    }
}

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
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1100,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(receiver_wallet.kem_public_key().clone(), 900)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        receiver_wallet.scan_transaction(&tx);
        assert_eq!(receiver_wallet.balance(), 900);
        assert_eq!(receiver_wallet.unspent_outputs().len(), 1);
    }

    #[test]
    fn wallet_scan_message() {
        let mut receiver_wallet = Wallet::new();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 300,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(receiver_wallet.kem_public_key().clone(), 90)
            .add_message(
                receiver_wallet.kem_public_key().clone(),
                b"secret message from sender".to_vec(),
            )
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
                value: 290,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 90)
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
        let funding_tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 10200,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(alice.kem_public_key().clone(), 10000)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        alice.scan_transaction(&funding_tx);
        assert_eq!(alice.balance(), 10000);
        let tx = alice
            .build_transaction(bob.kem_public_key(), 3000, None)
            .unwrap();
        assert_eq!(tx.fee, 200);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(alice.balance(), 0);
        alice.confirm_transaction(&tx.tx_binding);
        alice.scan_transaction(&tx);
        assert_eq!(alice.balance(), 6800);
    }

    #[test]
    fn wallet_save_load_roundtrip() {
        let mut wallet = Wallet::new();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 4210,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(wallet.kem_public_key().clone(), 4000)
            .add_message(wallet.kem_public_key().clone(), b"test message".to_vec())
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        wallet.scan_transaction(&tx);
        assert_eq!(wallet.balance(), 4000);
        assert_eq!(wallet.received_messages().len(), 1);
        let original_address = wallet.address().address_id();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        wallet.save_to_file(&path, 42, None).unwrap();
        let (loaded, last_seq) = Wallet::load_from_file(&path, None).unwrap();
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
                value: 10200,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(alice.kem_public_key().clone(), 10000)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        alice.scan_transaction(&funding_tx);
        assert_eq!(alice.balance(), 10000);
        let tx = alice
            .build_transaction(bob.kem_public_key(), 3000, None)
            .unwrap();
        assert_eq!(alice.balance(), 0);
        alice.confirm_transaction(&tx.tx_binding);
        assert_eq!(alice.balance(), 0);
        alice.scan_transaction(&tx);
        assert_eq!(alice.balance(), 6800);
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
                value: 5200,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(alice.kem_public_key().clone(), 5000)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        alice.scan_transaction(&funding_tx);
        assert_eq!(alice.balance(), 5000);
        let _tx = alice
            .build_transaction(bob.kem_public_key(), 1000, None)
            .unwrap();
        assert_eq!(alice.balance(), 0);
        assert_eq!(alice.unspent_outputs().len(), 0);
    }

    #[test]
    fn wallet_cancel_pending_transaction() {
        let mut alice = Wallet::new();
        let bob = Wallet::new();
        let funding_tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 10200,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(alice.kem_public_key().clone(), 10000)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        alice.scan_transaction(&funding_tx);
        assert_eq!(alice.balance(), 10000);
        let tx = alice
            .build_transaction(bob.kem_public_key(), 3000, None)
            .unwrap();
        assert_eq!(alice.balance(), 0);
        alice.cancel_transaction(&tx.tx_binding);
        assert_eq!(alice.balance(), 10000);
    }

    #[test]
    fn scan_records_receive_history() {
        let mut wallet = Wallet::new();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1100,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(wallet.kem_public_key().clone(), 900)
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
                value: 10200,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(alice.kem_public_key().clone(), 10000)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        alice.scan_transaction(&funding_tx);
        alice
            .build_transaction(bob.kem_public_key(), 3000, None)
            .unwrap();
        assert_eq!(alice.history().len(), 2);
        assert_eq!(alice.history()[0].direction, TxDirection::Receive);
        assert_eq!(alice.history()[1].direction, TxDirection::Send);
        assert_eq!(alice.history()[1].amount, 3000);
        assert_eq!(alice.history()[1].fee, 200);
    }

    #[test]
    fn history_persists_in_wallet_file() {
        let mut wallet = Wallet::new();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1100,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(wallet.kem_public_key().clone(), 900)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        wallet.scan_transaction(&tx);
        assert_eq!(wallet.history().len(), 1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        wallet.save_to_file(&path, 0, None).unwrap();
        let (loaded, _) = Wallet::load_from_file(&path, None).unwrap();
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
        words[0] = "abandon".to_string();
        words[1] = "abandon".to_string();
        let _ = words_to_entropy(&words);
    }
    #[test]
    fn mnemonic_wrong_length() {
        let words: Vec<String> = vec!["abandon".to_string(); 12];
        assert!(words_to_entropy(&words).is_err());
    }
    #[test]
    fn mnemonic_unknown_word() {
        let mut words: Vec<String> = vec!["abandon".to_string(); 24];
        words[5] = "notaword".to_string();
        assert!(words_to_entropy(&words).is_err());
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
    fn recovery_backup_different_nonces() {
        let wallet = Wallet::new();
        let (_, backup1) = wallet.create_recovery_backup();
        let (_, backup2) = wallet.create_recovery_backup();
        assert_ne!(backup1, backup2);
        assert_ne!(&backup1[..24], &backup2[..24]);
    }
    #[test]
    fn recovery_wrong_phrase_fails() {
        let wallet = Wallet::new();
        let (_, backup) = wallet.create_recovery_backup();
        let (wrong_words, _) = generate_mnemonic();
        assert!(Wallet::recover_from_backup(&wrong_words, &backup).is_err());
    }

    #[test]
    fn consolidation_needs_two_outputs() {
        let mut wallet = Wallet::new();
        let tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1100,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(wallet.kem_public_key().clone(), 900)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        wallet.scan_transaction(&tx);
        assert_eq!(wallet.unspent_outputs().len(), 1);
        assert!(matches!(
            wallet.build_consolidation_tx(None),
            Err(WalletError::NothingToConsolidate)
        ));
    }

    fn funded_wallet(amount: u64) -> Wallet {
        let mut wallet = Wallet::new();
        let funding_tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: amount + 200,
                blinding: BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(wallet.kem_public_key().clone(), amount)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        wallet.scan_transaction(&funding_tx);
        wallet
    }

    #[test]
    fn expire_pending_returns_outputs() {
        let mut alice = funded_wallet(10000);
        let bob = Wallet::new();
        let _tx = alice
            .build_transaction(bob.kem_public_key(), 3000, None)
            .unwrap();
        assert_eq!(alice.balance(), 0);
        for output in &mut alice.outputs {
            if let SpendStatus::Pending {
                ref mut created_epoch,
                ..
            } = output.status
            {
                *created_epoch = 5;
            }
        }
        assert_eq!(
            alice.expire_pending(5 + PENDING_EXPIRY_EPOCHS + 1, PENDING_EXPIRY_EPOCHS),
            1
        );
        assert_eq!(alice.balance(), 10000);
    }

    #[test]
    fn expire_pending_not_yet_expired() {
        let mut alice = funded_wallet(10000);
        let bob = Wallet::new();
        let _tx = alice
            .build_transaction(bob.kem_public_key(), 3000, None)
            .unwrap();
        for output in &mut alice.outputs {
            if let SpendStatus::Pending {
                ref mut created_epoch,
                ..
            } = output.status
            {
                *created_epoch = 5;
            }
        }
        assert_eq!(alice.expire_pending(10, PENDING_EXPIRY_EPOCHS), 0);
        assert_eq!(alice.balance(), 0);
    }

    #[test]
    fn expire_pending_boundary_epoch() {
        let mut alice = funded_wallet(10000);
        let bob = Wallet::new();
        let _tx = alice
            .build_transaction(bob.kem_public_key(), 3000, None)
            .unwrap();
        for output in &mut alice.outputs {
            if let SpendStatus::Pending {
                ref mut created_epoch,
                ..
            } = output.status
            {
                *created_epoch = 5;
            }
        }
        assert_eq!(alice.expire_pending(15, PENDING_EXPIRY_EPOCHS), 0);
        assert_eq!(alice.balance(), 0);
        assert_eq!(alice.expire_pending(16, PENDING_EXPIRY_EPOCHS), 1);
        assert_eq!(alice.balance(), 10000);
    }

    #[test]
    fn build_transaction_insufficient_funds() {
        let mut alice = funded_wallet(5000);
        let bob = Wallet::new();
        // Minimum fee is F(1)=200, so sending 5000 from a 5000 UTXO is insufficient.
        let min_fee = crate::constants::compute_weight_fee(1, 0);
        assert!(matches!(
            alice.build_transaction(bob.kem_public_key(), 5000, None),
            Err(WalletError::InsufficientFunds {
                available: 5000,
                ..
            })
        ));
        if let Err(WalletError::InsufficientFunds { needed, .. }) =
            alice.build_transaction(bob.kem_public_key(), 5000, None)
        {
            assert_eq!(needed, 5000 + min_fee);
        }
    }
    #[test]
    fn build_transaction_arithmetic_overflow() {
        let mut alice = funded_wallet(5000);
        let bob = Wallet::new();
        assert!(matches!(
            alice.build_transaction(bob.kem_public_key(), u64::MAX, None),
            Err(WalletError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn balance_saturating_add() {
        let mut wallet = Wallet::new();
        let val1 = u64::MAX / 2 + 1;
        let val2 = u64::MAX / 2 + 1;
        let blinding1 = BlindingFactor::random();
        let blinding2 = BlindingFactor::random();
        wallet.outputs.push(OwnedOutput {
            commitment: Commitment::commit(val1, &blinding1),
            value: val1,
            blinding: blinding1,
            spend_auth: crate::hash_domain(b"test", b"auth1"),
            status: SpendStatus::Unspent,
            commitment_index: None,
        });
        wallet.outputs.push(OwnedOutput {
            commitment: Commitment::commit(val2, &blinding2),
            value: val2,
            blinding: blinding2,
            spend_auth: crate::hash_domain(b"test", b"auth2"),
            status: SpendStatus::Unspent,
            commitment_index: None,
        });
        assert_eq!(wallet.balance(), u64::MAX);
    }

    #[test]
    fn build_consolidation_tx_success() {
        let mut wallet = Wallet::new();
        for i in 0..3 {
            let funding_tx = TransactionBuilder::new()
                .add_input(InputSpec {
                    value: 1200,
                    blinding: BlindingFactor::from_bytes([i + 10; 32]),
                    spend_auth: crate::hash_domain(b"test", &[i]),
                    merkle_path: vec![],
                })
                .add_output(wallet.kem_public_key().clone(), 1000)
                .set_proof_options(test_proof_options())
                .build()
                .unwrap();
            wallet.scan_transaction(&funding_tx);
        }
        assert_eq!(wallet.unspent_outputs().len(), 3);
        assert_eq!(wallet.balance(), 3000);
        let history_before = wallet.history().len();
        let tx = wallet.build_consolidation_tx(None).unwrap();
        let expected_fee = crate::constants::compute_weight_fee(3, 0);
        assert_eq!(tx.fee, expected_fee);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(
            wallet
                .outputs
                .iter()
                .filter(|o| matches!(o.status, SpendStatus::Pending { .. }))
                .count(),
            3
        );
        assert_eq!(wallet.balance(), 0);
        assert_eq!(wallet.history().len(), history_before + 1);
        let last_entry = wallet.history().last().unwrap();
        assert_eq!(last_entry.direction, TxDirection::Send);
        assert_eq!(last_entry.amount, 3000 - expected_fee);
        assert_eq!(last_entry.fee, expected_fee);
    }

    #[test]
    fn build_consolidation_tx_fee_exceeds_total() {
        let mut wallet = Wallet::new();
        for i in 0..2 {
            let funding_tx = TransactionBuilder::new()
                .add_input(InputSpec {
                    value: 300,
                    blinding: BlindingFactor::from_bytes([i + 20; 32]),
                    spend_auth: crate::hash_domain(b"test", &[i + 20]),
                    merkle_path: vec![],
                })
                .add_output(wallet.kem_public_key().clone(), 100)
                .set_proof_options(test_proof_options())
                .build()
                .unwrap();
            wallet.scan_transaction(&funding_tx);
        }
        assert_eq!(wallet.balance(), 200);
        let expected_fee = crate::constants::compute_weight_fee(2, 0);
        let result = wallet.build_consolidation_tx(None);
        assert!(matches!(
            result,
            Err(WalletError::InsufficientFunds { available: 200, .. })
        ));
        if let Err(WalletError::InsufficientFunds { needed, .. }) = result {
            assert_eq!(needed, expected_fee);
        }
    }

    #[test]
    fn push_history_cap() {
        let mut wallet = Wallet::new();
        for i in 0..=MAX_HISTORY_ENTRIES {
            wallet.push_history(TxHistoryEntry {
                tx_id: [i as u8; 32],
                direction: TxDirection::Receive,
                amount: i as u64,
                fee: 0,
                epoch: 0,
            });
        }
        assert_eq!(wallet.history().len(), MAX_HISTORY_ENTRIES);
        assert_eq!(wallet.history()[0].amount, 1);
        assert_eq!(
            wallet.history().last().unwrap().amount,
            MAX_HISTORY_ENTRIES as u64
        );
    }

    #[test]
    fn scan_coinbase_output() {
        let mut wallet = Wallet::new();
        let state = crate::state::ChainState::new();
        let amount = 50_000u64;
        let blinding = BlindingFactor::random();
        let commitment = Commitment::commit(amount, &blinding);
        let stealth_result =
            crate::crypto::stealth::StealthAddress::generate(wallet.kem_public_key(), 0).unwrap();
        let stealth_address = stealth_result.address;
        let mut note_data = Vec::with_capacity(40);
        note_data.extend_from_slice(&amount.to_le_bytes());
        note_data.extend_from_slice(&blinding.0);
        let encrypted_note =
            crate::crypto::encryption::EncryptedPayload::encrypt_with_shared_secret(
                &stealth_result.shared_secret,
                stealth_address.kem_ciphertext.clone(),
                &note_data,
            )
            .unwrap();
        let coinbase_output = crate::transaction::TxOutput {
            commitment,
            stealth_address,
            encrypted_note,
        };
        assert_eq!(wallet.balance(), 0);
        assert_eq!(wallet.history().len(), 0);
        wallet.scan_coinbase_output(&coinbase_output, Some(&state));
        assert_eq!(wallet.balance(), amount);
        assert_eq!(wallet.output_count(), 1);
        assert_eq!(wallet.history().len(), 1);
        assert_eq!(wallet.history()[0].direction, TxDirection::Coinbase);
        assert_eq!(wallet.history()[0].amount, amount);
        assert_eq!(wallet.history()[0].fee, 0);
    }

    #[test]
    fn wallet_encrypted_save_load_roundtrip() {
        let wallet = Wallet::new();
        let original_addr = wallet.address().address_id();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        wallet.save_to_file(&path, 99, Some("hunter2")).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(&raw[..4], &ENCRYPTED_MAGIC);
        let (loaded, seq) = Wallet::load_from_file(&path, Some("hunter2")).unwrap();
        assert_eq!(seq, 99);
        assert_eq!(loaded.address().address_id(), original_addr);
    }

    #[test]
    fn wallet_encrypted_wrong_password_fails() {
        let wallet = Wallet::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        wallet.save_to_file(&path, 0, Some("correct")).unwrap();
        let result = Wallet::load_from_file(&path, Some("wrong"));
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("wrong password"), "got: {}", e),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn wallet_encrypted_no_password_fails() {
        let wallet = Wallet::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        wallet.save_to_file(&path, 0, Some("secret")).unwrap();
        let result = Wallet::load_from_file(&path, None);
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("password required"), "got: {}", e),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn wallet_encrypted_tampered_ciphertext_fails() {
        let wallet = Wallet::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        wallet.save_to_file(&path, 0, Some("pass")).unwrap();
        let mut raw = std::fs::read(&path).unwrap();
        // Corrupt a byte in the ciphertext region (after magic + salt + nonce = 4+32+24 = 60)
        if raw.len() > 61 {
            raw[61] ^= 0xFF;
        }
        std::fs::write(&path, &raw).unwrap();
        let result = Wallet::load_from_file(&path, Some("pass"));
        assert!(result.is_err(), "tampered wallet file should fail to load");
    }

    #[test]
    fn recovery_backup_tampered_fails() {
        let wallet = Wallet::new();
        let (words, mut backup) = wallet.create_recovery_backup();
        // Corrupt a byte in the ciphertext region (after 24-byte nonce)
        if backup.len() > 25 {
            backup[25] ^= 0xFF;
        }
        let result = Wallet::recover_from_backup(&words, &backup);
        assert!(result.is_err(), "tampered backup should fail to recover");
    }

    /// Create a wallet with specific UTXO values for coin selection testing.
    fn wallet_with_utxos(values: &[u64]) -> Wallet {
        let mut wallet = Wallet::new();
        for &value in values {
            let blinding = BlindingFactor::random();
            wallet.outputs.push(OwnedOutput {
                commitment: Commitment::commit(value, &blinding),
                value,
                blinding,
                spend_auth: crate::hash_domain(b"test", &value.to_le_bytes()),
                status: SpendStatus::Unspent,
                commitment_index: None,
            });
        }
        wallet
    }

    #[test]
    fn coin_selection_exact_match_no_change() {
        // UTXO value == amount + F(1) → 1 output, no change.
        // F(1) = 100 + 100 = 200
        let wallet = wallet_with_utxos(&[1200]);
        let (indices, sum, num_outputs, fee) = wallet.select_coins(1000, 0).unwrap();
        assert_eq!(indices.len(), 1);
        assert_eq!(sum, 1200);
        assert_eq!(num_outputs, 1);
        assert_eq!(fee, 200);
    }

    #[test]
    fn coin_selection_with_change() {
        // UTXO value > amount + F(1) → 2 outputs (recipient + change).
        // F(1) = 200. 2000 > 1200 → change = 800.
        let wallet = wallet_with_utxos(&[2000]);
        let (indices, sum, num_outputs, fee) = wallet.select_coins(1000, 0).unwrap();
        assert_eq!(indices.len(), 1);
        assert_eq!(sum, 2000);
        assert_eq!(num_outputs, 2);
        assert_eq!(fee, 200);
    }

    #[test]
    fn coin_selection_no_dead_zone() {
        // With output-independent fees, there is no dead zone. Any UTXO >= amount + fee works.
        // F(1)=200. A 1350 UTXO covers 1000+200=1200 with change=150.
        let wallet = wallet_with_utxos(&[1350]);
        let (indices, sum, num_outputs, fee) = wallet.select_coins(1000, 0).unwrap();
        assert_eq!(indices.len(), 1);
        assert_eq!(sum, 1350);
        assert_eq!(num_outputs, 2);
        assert_eq!(fee, 200);
    }

    #[test]
    fn coin_selection_multi_input_fallback() {
        // Single UTXO too small, but two together work.
        // F(1)=200. 1100 < 1200 needed. But 1100 + 200 = 1300.
        // F(2)=300. needed=1300. 1300 >= 1300 → exact match, 1 output.
        let wallet = wallet_with_utxos(&[1100, 200]);
        let (indices, sum, num_outputs, fee) = wallet.select_coins(1000, 0).unwrap();
        assert_eq!(indices.len(), 2);
        assert_eq!(sum, 1300);
        assert_eq!(num_outputs, 1);
        assert_eq!(fee, 300);
    }

    #[test]
    fn coin_selection_minimizes_inputs() {
        // Prefers 1 large UTXO over 2 small ones (fewer STARK proofs).
        let wallet = wallet_with_utxos(&[800, 800, 2000]);
        let (indices, _sum, _num_outputs, _fee) = wallet.select_coins(1000, 0).unwrap();
        assert_eq!(indices.len(), 1, "should pick 1 UTXO, not 2");
    }

    #[test]
    fn coin_selection_multi_input_accumulation() {
        // No single UTXO is sufficient; must combine.
        // F(2)=300. 600+600=1200. needed=1300. Not enough.
        // F(3)=400. 600+600+600=1800. needed=1400. 1800 >= 1400. Works with change=400.
        let wallet = wallet_with_utxos(&[600, 600, 600]);
        let (indices, sum, num_outputs, fee) = wallet.select_coins(1000, 0).unwrap();
        assert_eq!(indices.len(), 3);
        assert_eq!(sum, 1800);
        assert_eq!(num_outputs, 2);
        assert_eq!(fee, 400);
    }

    #[test]
    fn coin_selection_fee_matches_builder() {
        // End-to-end: the predicted fee from coin selection must match what
        // TransactionBuilder actually computes.
        let mut wallet = wallet_with_utxos(&[5000]);
        let bob = Wallet::new();
        let tx = wallet
            .build_transaction(bob.kem_public_key(), 1000, None)
            .unwrap();
        // F(1)=200, change=5000-1000-200=3800
        assert_eq!(tx.fee, 200);
        assert_eq!(tx.outputs.len(), 2);
    }

    #[test]
    fn coin_selection_with_message_fee() {
        // Message bytes factor into fee. A 100-byte message → padded to 128 bytes
        // (4+100=104, ceil to 128). 128 bytes → ceil(128/1024)=1 KB. F(1,128)=210.
        let wallet = wallet_with_utxos(&[2000]);
        let msg_bytes = (100 + 4_usize).div_ceil(64) * 64; // 128
        let (_, _, _num_outputs, fee) = wallet.select_coins(1000, msg_bytes).unwrap();
        let expected_fee = crate::constants::compute_weight_fee(1, msg_bytes);
        assert_eq!(fee, expected_fee);
    }

    #[test]
    fn coin_selection_simulator_scenario() {
        // The scenario that previously caused an infinite loop: Alice has a 500-value
        // UTXO and sends 100. F(1)=200. needed=300. 500 >= 300 → works, change=200.
        // No dead zone with output-independent fees.
        let wallet = wallet_with_utxos(&[500, 10000]);
        let (_indices, sum, num_outputs, fee) = wallet.select_coins(100, 0).unwrap();
        // Should pick 500 (smallest sufficient UTXO)
        assert_eq!(sum, 500);
        assert_eq!(num_outputs, 2);
        assert_eq!(fee, 200);
        assert_eq!(sum - 100 - fee, 200);
    }

    #[test]
    fn coin_selection_exact_and_change_boundary() {
        // F(1)=200. For amount=100: needed=300.
        // UTXO=300 → exact match (1 output).
        let wallet = wallet_with_utxos(&[300]);
        let (_, _, num_out, fee) = wallet.select_coins(100, 0).unwrap();
        assert_eq!(num_out, 1);
        assert_eq!(fee, 200);

        // UTXO=301 → change=1 (2 outputs).
        let wallet2 = wallet_with_utxos(&[301]);
        let (_, _, num_out, fee) = wallet2.select_coins(100, 0).unwrap();
        assert_eq!(num_out, 2);
        assert_eq!(fee, 200);

        // UTXO=299 → insufficient.
        let wallet3 = wallet_with_utxos(&[299]);
        assert!(wallet3.select_coins(100, 0).is_err());
    }

    #[test]
    fn wallet_unencrypted_backward_compat() {
        let wallet = Wallet::new();
        let original_addr = wallet.address().address_id();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.dat");
        wallet.save_to_file(&path, 7, None).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert_ne!(&raw[..4], &ENCRYPTED_MAGIC);
        let (loaded, seq) = Wallet::load_from_file(&path, None).unwrap();
        assert_eq!(seq, 7);
        assert_eq!(loaded.address().address_id(), original_addr);
        let (loaded2, seq2) = Wallet::load_from_file(&path, Some("ignored")).unwrap();
        assert_eq!(seq2, 7);
        assert_eq!(loaded2.address().address_id(), original_addr);
    }

    #[test]
    fn wallet_new_has_zero_balance() {
        let wallet = Wallet::new();
        assert_eq!(wallet.balance(), 0);
        assert_eq!(wallet.output_count(), 0);
        assert!(wallet.received_messages().is_empty());
        assert!(wallet.history().is_empty());
    }

    #[test]
    fn wallet_address_deterministic() {
        let wallet = Wallet::new();
        let a1 = wallet.address().address_id();
        let a2 = wallet.address().address_id();
        assert_eq!(a1, a2);
    }

    #[test]
    fn wallet_different_instances_different_addresses() {
        let w1 = Wallet::new();
        let w2 = Wallet::new();
        assert_ne!(w1.address().address_id(), w2.address().address_id());
    }

    #[test]
    fn wallet_kem_public_key_available() {
        let wallet = Wallet::new();
        let pk = wallet.kem_public_key();
        assert!(!pk.as_bytes().is_empty());
    }

    #[test]
    fn wallet_keypair_accessible() {
        let wallet = Wallet::new();
        let kp = wallet.keypair();
        let fp = kp.signing.public.fingerprint();
        assert_ne!(fp, [0u8; 32]);
    }

    #[test]
    fn wallet_scan_unrelated_transaction_adds_nothing() {
        let mut alice = Wallet::new();
        let bob = Wallet::new();
        let charlie = Wallet::new();

        // Fund alice
        let coinbase_blind = BlindingFactor::random();
        let coinbase_auth = crate::hash_domain(b"coinbase", b"genesis-auth");
        let funding_tx = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 10_000,
                blinding: coinbase_blind,
                spend_auth: coinbase_auth,
                merkle_path: vec![],
            })
            .add_output(alice.kem_public_key().clone(), 9_800)
            .build()
            .unwrap();
        alice.scan_transaction(&funding_tx);

        // Alice sends to bob
        let tx = alice
            .build_transaction(bob.kem_public_key(), 5_000, None)
            .unwrap();

        // Charlie scans — should find nothing
        let mut charlie_wallet = charlie;
        let before_count = charlie_wallet.output_count();
        charlie_wallet.scan_transaction(&tx);
        assert_eq!(charlie_wallet.output_count(), before_count);
        assert_eq!(charlie_wallet.balance(), 0);
    }

    #[test]
    fn select_coins_insufficient_funds() {
        let wallet = wallet_with_utxos(&[100]);
        // 100 is not enough to send 100 + any fee
        assert!(wallet.select_coins(100, 0).is_err());
    }

    #[test]
    fn select_coins_empty_wallet() {
        let wallet = Wallet::new();
        assert!(wallet.select_coins(1, 0).is_err());
    }
}
