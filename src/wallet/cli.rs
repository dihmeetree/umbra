//! Wallet CLI command handlers.
//!
//! Implements the wallet subcommands: init, address, balance, send, scan, messages.
//! Communicates with the node via HTTP RPC for chain data.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{TxDirection, Wallet, WalletError};
use crate::config::WalletTlsConfig;
use crate::crypto::keys::PublicAddress;

/// Default wallet file name within data_dir.
const WALLET_FILENAME: &str = "wallet.dat";

/// Default address export file name.
const ADDRESS_FILENAME: &str = "wallet.umbra-address";

/// Simple RPC client for communicating with a Umbra node.
pub struct RpcClient {
    base_url: String,
    client: reqwest::Client,
}

impl RpcClient {
    pub fn new(rpc_addr: SocketAddr) -> Self {
        RpcClient {
            base_url: format!("http://{}", rpc_addr),
            client: reqwest::Client::new(),
        }
    }

    /// Create an mTLS-enabled RPC client.
    pub fn new_mtls(
        rpc_addr: SocketAddr,
        tls_config: &WalletTlsConfig,
    ) -> Result<Self, WalletError> {
        // Load CA certificate
        let ca_pem = std::fs::read(&tls_config.ca_cert_file)
            .map_err(|e| WalletError::Rpc(format!("failed to read CA cert: {}", e)))?;
        let ca_cert = reqwest::tls::Certificate::from_pem(&ca_pem)
            .map_err(|e| WalletError::Rpc(format!("invalid CA cert: {}", e)))?;

        // Load client identity (cert + key concatenated)
        let client_cert = std::fs::read(&tls_config.client_cert_file)
            .map_err(|e| WalletError::Rpc(format!("failed to read client cert: {}", e)))?;
        let client_key = std::fs::read(&tls_config.client_key_file)
            .map_err(|e| WalletError::Rpc(format!("failed to read client key: {}", e)))?;
        let mut identity_pem = client_cert;
        identity_pem.extend_from_slice(&client_key);
        let identity = reqwest::tls::Identity::from_pem(&identity_pem)
            .map_err(|e| WalletError::Rpc(format!("invalid client identity: {}", e)))?;

        let client = reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .identity(identity)
            .build()
            .map_err(|e| WalletError::Rpc(format!("failed to build TLS client: {}", e)))?;

        Ok(RpcClient {
            base_url: format!("https://{}", rpc_addr),
            client,
        })
    }

    /// Create a client, using mTLS if TLS config is provided.
    pub fn new_maybe_tls(
        rpc_addr: SocketAddr,
        tls: Option<&WalletTlsConfig>,
    ) -> Result<Self, WalletError> {
        match tls {
            Some(tls_config) => Self::new_mtls(rpc_addr, tls_config),
            None => Ok(Self::new(rpc_addr)),
        }
    }

    pub async fn get_state(&self) -> Result<ChainStateInfo, WalletError> {
        let url = format!("{}/state", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| WalletError::Rpc(format!("request failed: {}", e)))?;
        resp.json()
            .await
            .map_err(|e| WalletError::Rpc(format!("invalid response: {}", e)))
    }

    pub async fn submit_tx(&self, tx_hex: &str) -> Result<SubmitTxResult, WalletError> {
        let url = format!("{}/tx", self.base_url);
        let body = serde_json::json!({ "tx_hex": tx_hex });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| WalletError::Rpc(format!("request failed: {}", e)))?;
        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(WalletError::Rpc(format!("tx rejected: {}", text)));
        }
        resp.json()
            .await
            .map_err(|e| WalletError::Rpc(format!("invalid response: {}", e)))
    }

    async fn get_finalized_vertices(
        &self,
        after: u64,
        limit: u32,
    ) -> Result<FinalizedVerticesResult, WalletError> {
        let url = format!(
            "{}/vertices/finalized?after={}&limit={}",
            self.base_url, after, limit
        );
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| WalletError::Rpc(format!("request failed: {}", e)))?;
        resp.json()
            .await
            .map_err(|e| WalletError::Rpc(format!("invalid response: {}", e)))
    }
}

#[derive(Deserialize)]
pub struct ChainStateInfo {
    pub epoch: u64,
    pub commitment_count: usize,
    pub nullifier_count: usize,
    pub state_root: String,
}

#[derive(Deserialize)]
pub struct SubmitTxResult {
    pub tx_id: String,
}

#[derive(Deserialize)]
struct FinalizedVerticesResult {
    vertices: Vec<FinalizedVertexEntry>,
    has_more: bool,
    #[allow(dead_code)]
    total: u64,
}

#[derive(Deserialize)]
struct FinalizedVertexEntry {
    sequence: u64,
    vertex_hex: String,
    coinbase_hex: Option<String>,
}

pub fn wallet_path(data_dir: &Path) -> PathBuf {
    data_dir.join(WALLET_FILENAME)
}

pub fn address_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ADDRESS_FILENAME)
}

/// Initialize a new wallet.
pub fn cmd_init(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    if path.exists() {
        return Err("wallet already exists at this location".into());
    }
    std::fs::create_dir_all(data_dir)?;

    let wallet = Wallet::new();
    wallet.save_to_file(&path, 0, None)?;

    // Also export address file
    let addr = wallet.address();
    let addr_bytes = crate::serialize(&addr)?;
    let addr_hex = hex::encode(&addr_bytes);
    std::fs::write(address_path(data_dir), &addr_hex)?;

    println!("Wallet created: {}", path.display());
    println!("Address ID: {}", hex::encode(&addr.address_id()[..16]));
    println!("Address file: {}", address_path(data_dir).display());
    Ok(())
}

/// Show wallet address.
pub fn cmd_address(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    let (wallet, _) = Wallet::load_from_file(&path, None)?;
    let addr = wallet.address();
    println!("Address ID: {}", hex::encode(&addr.address_id()[..16]));
    println!(
        "Signing key: {} + {} bytes (Dilithium5 + SPHINCS+)",
        addr.signing.dilithium.len(),
        addr.signing.sphincs.len()
    );
    println!("KEM key: {} bytes", addr.kem.0.len());

    // Re-export address file
    let addr_bytes = crate::serialize(&addr)?;
    let addr_hex = hex::encode(&addr_bytes);
    std::fs::write(address_path(data_dir), &addr_hex)?;
    println!("Address file: {}", address_path(data_dir).display());
    Ok(())
}

/// Scan the chain and show balance.
pub async fn cmd_balance(
    data_dir: &Path,
    rpc_addr: SocketAddr,
    wallet_tls: Option<&WalletTlsConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    let (mut wallet, last_seq) = Wallet::load_from_file(&path, None)?;

    // Scan for new vertices
    let scanned_to = scan_chain(&mut wallet, last_seq, rpc_addr, wallet_tls).await?;

    // Save updated wallet
    wallet.save_to_file(&path, scanned_to, None)?;

    println!("Balance: {} units", wallet.balance());
    println!(
        "Outputs: {} total ({} unspent)",
        wallet.output_count(),
        wallet.unspent_outputs().len()
    );
    println!("Scanned to sequence: {}", scanned_to);
    Ok(())
}

/// Scan the chain for new outputs.
pub async fn cmd_scan(
    data_dir: &Path,
    rpc_addr: SocketAddr,
    wallet_tls: Option<&WalletTlsConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    let (mut wallet, last_seq) = Wallet::load_from_file(&path, None)?;

    let scanned_to = scan_chain(&mut wallet, last_seq, rpc_addr, wallet_tls).await?;

    wallet.save_to_file(&path, scanned_to, None)?;

    println!("Scan complete. Scanned to sequence: {}", scanned_to);
    println!("Balance: {} units", wallet.balance());
    println!(
        "Outputs: {} total ({} unspent)",
        wallet.output_count(),
        wallet.unspent_outputs().len()
    );
    Ok(())
}

/// Send a transaction.
///
/// The fee is computed deterministically from the transaction shape.
pub async fn cmd_send(
    data_dir: &Path,
    rpc_addr: SocketAddr,
    to_file: &Path,
    amount: u64,
    message: Option<String>,
    wallet_tls: Option<&WalletTlsConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    let (mut wallet, last_seq) = Wallet::load_from_file(&path, None)?;

    // Scan chain first to have latest balance
    let scanned_to = scan_chain(&mut wallet, last_seq, rpc_addr, wallet_tls).await?;

    // Load recipient address
    let addr_hex = std::fs::read_to_string(to_file).map_err(|e| {
        tracing::error!("Failed to read address file {}: {}", to_file.display(), e);
        "failed to read recipient address file".to_string()
    })?;
    let addr_bytes =
        hex::decode(addr_hex.trim()).map_err(|e| format!("invalid address hex: {}", e))?;
    let recipient: PublicAddress =
        crate::deserialize(&addr_bytes).map_err(|e| format!("invalid address: {}", e))?;

    // Build transaction (fee is auto-computed)
    let msg_bytes = message.map(|m| m.into_bytes());
    let tx = wallet.build_transaction(&recipient.kem, amount, msg_bytes)?;
    let fee = tx.fee;
    let tx_id = tx.tx_id();

    // Submit to node
    let tx_bytes = crate::serialize(&tx)?;
    let tx_hex = hex::encode(&tx_bytes);

    let client = RpcClient::new_maybe_tls(rpc_addr, wallet_tls)?;
    let result = client.submit_tx(&tx_hex).await?;

    // Save wallet (outputs now pending)
    wallet.save_to_file(&path, scanned_to, None)?;

    println!("Transaction submitted!");
    println!("TX ID: {}", result.tx_id);
    println!("Amount: {} units", amount);
    println!("Fee: {} units (deterministic)", fee);
    println!(
        "Remaining balance: {} units (pending outputs excluded)",
        wallet.balance()
    );
    let _ = tx_id; // suppress unused
    Ok(())
}

/// Show received messages.
pub fn cmd_messages(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    let (wallet, _) = Wallet::load_from_file(&path, None)?;

    let messages = wallet.received_messages();
    if messages.is_empty() {
        println!("No messages received.");
        return Ok(());
    }

    println!("{} message(s):", messages.len());
    for (i, msg) in messages.iter().enumerate() {
        println!("\n  [{}] TX: {}", i + 1, hex::encode(&msg.tx_hash[..16]));
        match std::str::from_utf8(&msg.content) {
            Ok(text) => println!("      Content: {}", text),
            Err(_) => println!("      Content: {} bytes (binary)", msg.content.len()),
        }
    }
    Ok(())
}

/// Show transaction history.
pub fn cmd_history(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    let (wallet, _) = Wallet::load_from_file(&path, None)?;

    let history = wallet.history();
    if history.is_empty() {
        println!("No transaction history.");
        return Ok(());
    }

    println!("{} transaction(s):", history.len());
    for (i, entry) in history.iter().enumerate() {
        let dir = match entry.direction {
            TxDirection::Send => "SEND",
            TxDirection::Receive => "RECV",
            TxDirection::Coinbase => "MINE",
        };
        let tx_short = hex::encode(&entry.tx_id[..8]);
        println!(
            "  [{}] {} {} units (fee: {}) tx:{} epoch:{}",
            i + 1,
            dir,
            entry.amount,
            entry.fee,
            tx_short,
            entry.epoch
        );
    }
    Ok(())
}

/// Consolidate all unspent outputs into a single output.
///
/// The fee is computed deterministically from the transaction shape.
pub async fn cmd_consolidate(
    data_dir: &Path,
    rpc_addr: SocketAddr,
    wallet_tls: Option<&WalletTlsConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    let (mut wallet, last_seq) = Wallet::load_from_file(&path, None)?;

    // Scan chain first
    let scanned_to = scan_chain(&mut wallet, last_seq, rpc_addr, wallet_tls).await?;

    let unspent_count = wallet.unspent_outputs().len();
    if unspent_count < 2 {
        println!(
            "Only {} unspent output(s), nothing to consolidate.",
            unspent_count
        );
        return Ok(());
    }

    println!("Consolidating {} unspent outputs...", unspent_count);
    let tx = wallet.build_consolidation_tx(None)?;
    let fee = tx.fee;
    let tx_id = tx.tx_id();

    // Submit
    let tx_bytes = crate::serialize(&tx)?;
    let tx_hex = hex::encode(&tx_bytes);
    let client = RpcClient::new_maybe_tls(rpc_addr, wallet_tls)?;
    let result = client.submit_tx(&tx_hex).await?;

    wallet.save_to_file(&path, scanned_to, None)?;

    println!("Consolidation submitted!");
    println!("TX ID: {}", result.tx_id);
    println!("Fee: {} units (deterministic)", fee);
    println!("Remaining balance: {} units", wallet.balance());
    let _ = tx_id;
    Ok(())
}

/// Initialize a wallet and display recovery phrase.
pub fn cmd_init_with_recovery(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    if path.exists() {
        return Err("wallet already exists at this location".into());
    }
    std::fs::create_dir_all(data_dir)?;

    let wallet = Wallet::new();

    // Create recovery backup
    let (mut words, backup) = wallet.create_recovery_backup();
    let recovery_path = data_dir.join("wallet.recovery");
    std::fs::write(&recovery_path, &backup)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&recovery_path, std::fs::Permissions::from_mode(0o600));
    }

    wallet.save_to_file(&path, 0, None)?;

    // Export address
    let addr = wallet.address();
    let addr_bytes = crate::serialize(&addr)?;
    let addr_hex = hex::encode(&addr_bytes);
    std::fs::write(address_path(data_dir), &addr_hex)?;

    println!("Wallet created: {}", path.display());
    println!("Address ID: {}", hex::encode(&addr.address_id()[..16]));
    println!("Recovery backup: {}", recovery_path.display());
    println!();
    println!("=== RECOVERY PHRASE (write down and store safely!) ===");
    println!("{}", words.join(" "));
    println!("=====================================================");
    println!();
    println!("WARNING: This phrase will NOT be shown again.");
    println!("Both the phrase AND the wallet.recovery file are needed to recover.");
    println!();

    // Prompt user to confirm they have written down the phrase before
    // clearing it from the terminal. This reduces the risk of the phrase
    // being lost if the user did not notice or save it.
    println!("Have you written down the recovery phrase? (type 'yes' to confirm)");
    let mut confirmation = String::new();
    let _ = std::io::stdin().read_line(&mut confirmation);
    if confirmation.trim().to_lowercase() != "yes" {
        println!("WARNING: You did not confirm. Make sure to save the phrase above!");
    }

    // Push the recovery phrase off the visible terminal to reduce shoulder-surfing risk
    for _ in 0..50 {
        println!();
    }

    // Zeroize mnemonic words
    use zeroize::Zeroize;
    for word in &mut words {
        word.zeroize();
    }
    drop(words);

    Ok(())
}

/// Recover a wallet from a mnemonic phrase and backup file.
pub fn cmd_recover(data_dir: &Path, phrase: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    if path.exists() {
        return Err("wallet already exists — move or delete it first".into());
    }

    let recovery_path = data_dir.join("wallet.recovery");
    if !recovery_path.exists() {
        tracing::error!("Recovery backup not found at {}", recovery_path.display());
        return Err("recovery backup file not found".into());
    }

    let words: Vec<String> = phrase.split_whitespace().map(|s| s.to_string()).collect();
    let backup = std::fs::read(&recovery_path).map_err(|e| {
        tracing::error!(
            "Failed to read recovery backup at {}: {}",
            recovery_path.display(),
            e
        );
        "failed to read recovery backup file"
    })?;

    let wallet = Wallet::recover_from_backup(&words, &backup)?;
    std::fs::create_dir_all(data_dir)?;
    wallet.save_to_file(&path, 0, None)?;

    // Export address
    let addr = wallet.address();
    let addr_bytes = crate::serialize(&addr)?;
    let addr_hex = hex::encode(&addr_bytes);
    std::fs::write(address_path(data_dir), &addr_hex)?;

    println!("Wallet recovered successfully!");
    println!("Address ID: {}", hex::encode(&addr.address_id()[..16]));
    println!("Note: run 'wallet scan' to resync outputs from the chain.");
    Ok(())
}

/// Export wallet address to a file for sharing.
pub fn cmd_export(data_dir: &Path, file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let wp = wallet_path(data_dir);
    let (wallet, _) = Wallet::load_from_file(&wp, None)?;
    let addr = wallet.address();
    let addr_bytes = crate::serialize(&addr)?;
    let addr_hex = hex::encode(&addr_bytes);
    std::fs::write(file, &addr_hex)?;
    println!("Address exported to: {}", file.display());
    println!("Address ID: {}", hex::encode(&addr.address_id()[..16]));
    Ok(())
}

/// Scan the chain for outputs addressed to us.
///
/// Downloads finalized vertices in batches from the node's RPC and scans
/// each transaction client-side. The node never learns which outputs belong
/// to this wallet.
pub async fn scan_chain(
    wallet: &mut Wallet,
    last_seq: u64,
    rpc_addr: SocketAddr,
    wallet_tls: Option<&WalletTlsConfig>,
) -> Result<u64, WalletError> {
    let client = RpcClient::new_maybe_tls(rpc_addr, wallet_tls)?;

    // Get chain state to know if we need to scan
    let state = client.get_state().await?;
    println!(
        "Node state: epoch={}, commitments={}, nullifiers={}, root={}...",
        state.epoch,
        state.commitment_count,
        state.nullifier_count,
        &state.state_root[..std::cmp::min(16, state.state_root.len())]
    );

    let mut current_after = last_seq;
    let mut total_scanned = 0u64;
    let mut total_found = 0u64;
    let batch_size = crate::constants::SYNC_BATCH_SIZE;

    loop {
        let result = client
            .get_finalized_vertices(current_after, batch_size)
            .await?;

        if result.vertices.is_empty() {
            break;
        }

        for entry in &result.vertices {
            // Check sequence contiguity -- each vertex should have
            // sequence == previous + 1. A gap may indicate the node skipped
            // vertices or data was lost.
            let expected_seq = current_after + 1;
            if entry.sequence != expected_seq {
                tracing::warn!(
                    expected = expected_seq,
                    actual = entry.sequence,
                    "sequence gap detected during wallet scan; \
                     some finalized vertices may have been skipped"
                );
            }

            // Deserialize vertex from hex
            let vertex_bytes = hex::decode(&entry.vertex_hex)
                .map_err(|e| WalletError::Rpc(format!("invalid vertex hex: {}", e)))?;
            let vertex: crate::consensus::dag::Vertex = crate::deserialize(&vertex_bytes)
                .map_err(|e| WalletError::Rpc(format!("invalid vertex: {}", e)))?;

            // Scan each transaction
            let old_count = wallet.output_count();
            for tx in &vertex.transactions {
                wallet.scan_transaction(tx);
            }

            // Scan coinbase output if present
            if let Some(ref cb_hex) = entry.coinbase_hex {
                if let Ok(cb_bytes) = hex::decode(cb_hex) {
                    if let Ok(cb_output) =
                        crate::deserialize::<crate::transaction::TxOutput>(&cb_bytes)
                    {
                        wallet.scan_coinbase_output(&cb_output, None);
                    }
                }
            }

            let new_outputs = wallet.output_count() - old_count;
            if new_outputs > 0 {
                total_found += new_outputs as u64;
            }
            total_scanned += 1;
            current_after = entry.sequence;
        }

        if !result.has_more {
            break;
        }
    }

    if total_scanned > 0 {
        println!(
            "Scanned {} vertices, found {} new outputs",
            total_scanned, total_found
        );
    }

    Ok(current_after)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_init_creates_wallet_and_address() {
        let dir = tempfile::tempdir().unwrap();
        cmd_init(dir.path()).unwrap();

        assert!(wallet_path(dir.path()).exists());
        assert!(address_path(dir.path()).exists());
    }

    #[test]
    fn cmd_init_rejects_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        cmd_init(dir.path()).unwrap();

        // Second init should fail
        let result = cmd_init(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn cmd_address_shows_info() {
        let dir = tempfile::tempdir().unwrap();
        cmd_init(dir.path()).unwrap();

        // address should succeed after init
        cmd_address(dir.path()).unwrap();
    }

    #[test]
    fn cmd_export_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        cmd_init(dir.path()).unwrap();

        let export_path = dir.path().join("exported.umbra-address");
        cmd_export(dir.path(), &export_path).unwrap();
        assert!(export_path.exists());

        // Exported file should be valid hex that deserializes to PublicAddress
        let hex_content = std::fs::read_to_string(&export_path).unwrap();
        let bytes = hex::decode(hex_content.trim()).unwrap();
        let _addr: PublicAddress = crate::deserialize(&bytes).unwrap();
    }

    #[test]
    fn cmd_messages_empty_wallet() {
        let dir = tempfile::tempdir().unwrap();
        cmd_init(dir.path()).unwrap();

        // messages on a fresh wallet should succeed (just print "No messages")
        cmd_messages(dir.path()).unwrap();
    }

    #[test]
    fn cmd_init_with_recovery_creates_backup() {
        let dir = tempfile::tempdir().unwrap();
        cmd_init_with_recovery(dir.path()).unwrap();

        assert!(wallet_path(dir.path()).exists());
        assert!(address_path(dir.path()).exists());
        assert!(dir.path().join("wallet.recovery").exists());
    }

    #[test]
    fn cmd_recover_restores_wallet() {
        let dir = tempfile::tempdir().unwrap();
        // Create wallet with recovery
        cmd_init_with_recovery(dir.path()).unwrap();

        // Load the original wallet to get its address
        let (original_wallet, _) = Wallet::load_from_file(&wallet_path(dir.path()), None).unwrap();
        let original_addr = original_wallet.address().address_id();

        // Read the recovery backup (exists from init)
        let _backup = std::fs::read(dir.path().join("wallet.recovery")).unwrap();

        // Need the mnemonic — recreate it from the wallet's keys
        let (words, _backup_bytes) = original_wallet.create_recovery_backup();

        // Delete the wallet file
        std::fs::remove_file(wallet_path(dir.path())).unwrap();
        std::fs::remove_file(address_path(dir.path())).unwrap();

        // Write the new backup (since create_recovery_backup generates fresh mnemonic)
        std::fs::write(dir.path().join("wallet.recovery"), &_backup_bytes).unwrap();

        // Recover
        let phrase = words.join(" ");
        cmd_recover(dir.path(), &phrase).unwrap();

        // Verify recovered wallet has same address
        let (recovered, _) = Wallet::load_from_file(&wallet_path(dir.path()), None).unwrap();
        assert_eq!(recovered.address().address_id(), original_addr);
    }

    #[test]
    fn cmd_history_empty_wallet() {
        let dir = tempfile::tempdir().unwrap();
        cmd_init(dir.path()).unwrap();

        // history on a fresh wallet should succeed
        cmd_history(dir.path()).unwrap();
    }

    #[test]
    fn rpc_client_new_uses_http() {
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();
        let client = RpcClient::new(addr);
        assert_eq!(client.base_url, "http://127.0.0.1:9733");
    }

    #[test]
    fn rpc_client_new_maybe_tls_none_uses_http() {
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();
        let client = RpcClient::new_maybe_tls(addr, None).unwrap();
        assert_eq!(client.base_url, "http://127.0.0.1:9733");
    }

    #[test]
    fn rpc_client_new_mtls_missing_files() {
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();
        let tls_config = WalletTlsConfig {
            client_cert_file: "/nonexistent/client.crt".into(),
            client_key_file: "/nonexistent/client.key".into(),
            ca_cert_file: "/nonexistent/ca.crt".into(),
        };
        let result = RpcClient::new_mtls(addr, &tls_config);
        assert!(result.is_err());
    }

    #[test]
    fn wallet_path_and_address_path() {
        let dir = std::path::Path::new("/tmp/test-wallet");
        assert_eq!(wallet_path(dir), dir.join(WALLET_FILENAME));
        assert_eq!(address_path(dir), dir.join(ADDRESS_FILENAME));
    }

    #[test]
    fn load_wallet_from_nonexistent_path() {
        let dir = tempfile::tempdir().unwrap();
        // Without init, load should fail
        let result = Wallet::load_from_file(&wallet_path(dir.path()), None);
        assert!(result.is_err());
    }

    #[test]
    fn cmd_export_fails_without_init() {
        let dir = tempfile::tempdir().unwrap();
        let export_path = dir.path().join("exported.umbra-address");
        let result = cmd_export(dir.path(), &export_path);
        assert!(result.is_err());
    }
}
