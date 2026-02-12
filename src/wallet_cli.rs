//! Wallet CLI command handlers.
//!
//! Implements the wallet subcommands: init, address, balance, send, scan, messages.
//! Communicates with the node via HTTP RPC for chain data.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::crypto::keys::PublicAddress;
use crate::wallet::{Wallet, WalletError};

/// Default wallet file name within data_dir.
const WALLET_FILENAME: &str = "wallet.dat";

/// Default address export file name.
const ADDRESS_FILENAME: &str = "wallet.spectra-address";

/// Simple RPC client for communicating with a Spectra node.
struct RpcClient {
    base_url: String,
    client: reqwest::Client,
}

impl RpcClient {
    fn new(rpc_addr: SocketAddr) -> Self {
        RpcClient {
            base_url: format!("http://{}", rpc_addr),
            client: reqwest::Client::new(),
        }
    }

    async fn get_state(&self) -> Result<ChainStateInfo, WalletError> {
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

    async fn submit_tx(&self, tx_hex: &str) -> Result<SubmitTxResult, WalletError> {
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
struct ChainStateInfo {
    epoch: u64,
    commitment_count: usize,
    nullifier_count: usize,
    state_root: String,
}

#[derive(Deserialize)]
struct SubmitTxResult {
    tx_id: String,
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
}

fn wallet_path(data_dir: &Path) -> PathBuf {
    data_dir.join(WALLET_FILENAME)
}

fn address_path(data_dir: &Path) -> PathBuf {
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
    wallet.save_to_file(&path, 0)?;

    // Also export address file
    let addr = wallet.address();
    let addr_bytes = bincode::serialize(&addr)?;
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
    let (wallet, _) = Wallet::load_from_file(&path)?;
    let addr = wallet.address();
    println!("Address ID: {}", hex::encode(&addr.address_id()[..16]));
    println!("Signing key: {} bytes", addr.signing.0.len());
    println!("KEM key: {} bytes", addr.kem.0.len());

    // Re-export address file
    let addr_bytes = bincode::serialize(&addr)?;
    let addr_hex = hex::encode(&addr_bytes);
    std::fs::write(address_path(data_dir), &addr_hex)?;
    println!("Address file: {}", address_path(data_dir).display());
    Ok(())
}

/// Scan the chain and show balance.
pub async fn cmd_balance(
    data_dir: &Path,
    rpc_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    let (mut wallet, last_seq) = Wallet::load_from_file(&path)?;

    // Scan for new vertices
    let scanned_to = scan_chain(&mut wallet, last_seq, rpc_addr).await?;

    // Save updated wallet
    wallet.save_to_file(&path, scanned_to)?;

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
) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    let (mut wallet, last_seq) = Wallet::load_from_file(&path)?;

    let scanned_to = scan_chain(&mut wallet, last_seq, rpc_addr).await?;

    wallet.save_to_file(&path, scanned_to)?;

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
pub async fn cmd_send(
    data_dir: &Path,
    rpc_addr: SocketAddr,
    to_file: &Path,
    amount: u64,
    fee: u64,
    message: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_path(data_dir);
    let (mut wallet, last_seq) = Wallet::load_from_file(&path)?;

    // Scan chain first to have latest balance
    let scanned_to = scan_chain(&mut wallet, last_seq, rpc_addr).await?;

    // Load recipient address
    let addr_hex = std::fs::read_to_string(to_file)
        .map_err(|e| format!("failed to read address file: {}", e))?;
    let addr_bytes =
        hex::decode(addr_hex.trim()).map_err(|e| format!("invalid address hex: {}", e))?;
    let recipient: PublicAddress =
        bincode::deserialize(&addr_bytes).map_err(|e| format!("invalid address: {}", e))?;

    // Build transaction
    let msg_bytes = message.map(|m| m.into_bytes());
    let tx = wallet.build_transaction(&recipient.kem, amount, fee, msg_bytes)?;
    let tx_id = tx.tx_id();

    // Submit to node
    let tx_bytes = bincode::serialize(&tx)?;
    let tx_hex = hex::encode(&tx_bytes);

    let client = RpcClient::new(rpc_addr);
    let result = client.submit_tx(&tx_hex).await?;

    // Save wallet (outputs now pending)
    wallet.save_to_file(&path, scanned_to)?;

    println!("Transaction submitted!");
    println!("TX ID: {}", result.tx_id);
    println!("Amount: {} units", amount);
    println!("Fee: {} units", fee);
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
    let (wallet, _) = Wallet::load_from_file(&path)?;

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

/// Export wallet address to a file for sharing.
pub fn cmd_export(data_dir: &Path, file: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let wp = wallet_path(data_dir);
    let (wallet, _) = Wallet::load_from_file(&wp)?;
    let addr = wallet.address();
    let addr_bytes = bincode::serialize(&addr)?;
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
async fn scan_chain(
    wallet: &mut Wallet,
    last_seq: u64,
    rpc_addr: SocketAddr,
) -> Result<u64, WalletError> {
    let client = RpcClient::new(rpc_addr);

    // Get chain state to know if we need to scan
    let state = client.get_state().await?;
    println!(
        "Node state: epoch={}, commitments={}, nullifiers={}, root={}...",
        state.epoch,
        state.commitment_count,
        state.nullifier_count,
        &state.state_root[..16]
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
            // Deserialize vertex from hex
            let vertex_bytes = hex::decode(&entry.vertex_hex)
                .map_err(|e| WalletError::Rpc(format!("invalid vertex hex: {}", e)))?;
            let vertex: crate::consensus::dag::Vertex = bincode::deserialize(&vertex_bytes)
                .map_err(|e| WalletError::Rpc(format!("invalid vertex: {}", e)))?;

            // Scan each transaction
            let old_count = wallet.output_count();
            for tx in &vertex.transactions {
                wallet.scan_transaction(tx);
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

        let export_path = dir.path().join("exported.spectra-address");
        cmd_export(dir.path(), &export_path).unwrap();
        assert!(export_path.exists());

        // Exported file should be valid hex that deserializes to PublicAddress
        let hex_content = std::fs::read_to_string(&export_path).unwrap();
        let bytes = hex::decode(hex_content.trim()).unwrap();
        let _addr: PublicAddress = bincode::deserialize(&bytes).unwrap();
    }

    #[test]
    fn cmd_messages_empty_wallet() {
        let dir = tempfile::tempdir().unwrap();
        cmd_init(dir.path()).unwrap();

        // messages on a fresh wallet should succeed (just print "No messages")
        cmd_messages(dir.path()).unwrap();
    }
}
