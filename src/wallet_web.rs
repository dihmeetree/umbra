//! Wallet web UI served via axum + askama templates.
//!
//! Provides a browser-based interface for all wallet operations: creating a wallet,
//! checking balance, sending transactions, viewing messages, and exporting addresses.
//! The web server runs as a separate process and communicates with the node via HTTP RPC
//! (the same way the CLI wallet does). The node never learns which outputs belong to the wallet.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::crypto::keys::PublicAddress;
use crate::wallet::{Wallet, WalletError};
use crate::wallet_cli;

// ── State ──

/// Shared state for the wallet web server.
#[derive(Clone)]
pub struct WalletWebState {
    pub data_dir: PathBuf,
    pub rpc_addr: SocketAddr,
    /// Cached wallet + last scanned sequence. None if not yet loaded.
    wallet: Arc<RwLock<Option<(Wallet, u64)>>>,
}

impl WalletWebState {
    fn new(data_dir: PathBuf, rpc_addr: SocketAddr) -> Self {
        WalletWebState {
            data_dir,
            rpc_addr,
            wallet: Arc::new(RwLock::new(None)),
        }
    }

    /// Check if a wallet file exists on disk.
    fn wallet_exists(&self) -> bool {
        wallet_cli::wallet_path(&self.data_dir).exists()
    }

    /// Load or return cached wallet. Returns None if wallet doesn't exist.
    async fn load_wallet(&self) -> Result<Option<(Wallet, u64)>, WalletError> {
        let mut cache = self.wallet.write().await;
        if cache.is_some() {
            return Ok(cache.clone());
        }
        let path = wallet_cli::wallet_path(&self.data_dir);
        if !path.exists() {
            return Ok(None);
        }
        let (wallet, seq) = Wallet::load_from_file(&path)?;
        *cache = Some((wallet.clone(), seq));
        Ok(Some((wallet, seq)))
    }

    /// Save wallet to disk and update cache.
    async fn save_wallet(&self, wallet: &Wallet, seq: u64) -> Result<(), WalletError> {
        let path = wallet_cli::wallet_path(&self.data_dir);
        wallet.save_to_file(&path, seq)?;
        let mut cache = self.wallet.write().await;
        *cache = Some((wallet.clone(), seq));
        Ok(())
    }

    /// Invalidate the cache (after external changes).
    async fn invalidate_cache(&self) {
        let mut cache = self.wallet.write().await;
        *cache = None;
    }
}

// ── Templates ──

#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    balance: u64,
    unspent_count: usize,
    total_outputs: usize,
    scanned_seq: u64,
    chain_epoch: u64,
    chain_commitments: usize,
    chain_nullifiers: usize,
    chain_state_root: String,
    flash_success: Option<String>,
    flash_error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "init.html")]
struct InitTemplate {
    flash_error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "address.html")]
struct AddressTemplate {
    address_id: String,
    signing_key_size: usize,
    kem_key_size: usize,
    address_hex: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "send.html")]
struct SendTemplate {
    balance: u64,
    flash_error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "send_result.html")]
struct SendResultTemplate {
    tx_id: String,
    amount: u64,
    fee: u64,
    remaining_balance: u64,
}

struct MessageDisplay {
    tx_hash_hex: String,
    text: Option<String>,
    binary_size: usize,
}

#[derive(Template, WebTemplate)]
#[template(path = "messages.html")]
struct MessagesTemplate {
    messages: Vec<MessageDisplay>,
}

#[derive(Template, WebTemplate)]
#[template(path = "error.html")]
struct ErrorTemplate {
    message: String,
}

fn error_page(msg: impl Into<String>) -> ErrorTemplate {
    ErrorTemplate {
        message: msg.into(),
    }
}

// ── Form types ──

#[derive(Deserialize)]
pub struct SendForm {
    recipient: String,
    amount: u64,
    fee: u64,
    message: Option<String>,
}

// ── Router ──

/// Build the wallet web router.
pub fn router(state: WalletWebState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/init", get(init_page).post(init_action))
        .route("/address", get(address_page))
        .route("/address/export", get(address_export))
        .route("/send", get(send_page).post(send_action))
        .route("/messages", get(messages_page))
        .route("/scan", post(scan_action))
        .with_state(state)
}

/// Start the wallet web server.
pub async fn serve(
    addr: SocketAddr,
    data_dir: PathBuf,
    rpc_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = WalletWebState::new(data_dir.clone(), rpc_addr);
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Wallet web UI listening on http://{}", addr);
    tracing::info!("Data dir: {}", data_dir.display());
    tracing::info!("Node RPC: {}", rpc_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Handlers ──

async fn dashboard(State(state): State<WalletWebState>) -> Response {
    if !state.wallet_exists() {
        return Redirect::to("/init").into_response();
    }

    let (wallet, seq) = match state.load_wallet().await {
        Ok(Some(w)) => w,
        Ok(None) => return Redirect::to("/init").into_response(),
        Err(e) => return error_page(e.to_string()).into_response(),
    };

    // Try to get chain state from node
    let client = wallet_cli::RpcClient::new(state.rpc_addr);
    let (chain_epoch, chain_commitments, chain_nullifiers, chain_state_root) =
        match client.get_state().await {
            Ok(info) => (
                info.epoch,
                info.commitment_count,
                info.nullifier_count,
                info.state_root,
            ),
            Err(_) => (0, 0, 0, "node unreachable".to_string()),
        };

    DashboardTemplate {
        balance: wallet.balance(),
        unspent_count: wallet.unspent_outputs().len(),
        total_outputs: wallet.output_count(),
        scanned_seq: seq,
        chain_epoch,
        chain_commitments,
        chain_nullifiers,
        chain_state_root,
        flash_success: None,
        flash_error: None,
    }
    .into_response()
}

async fn init_page(State(state): State<WalletWebState>) -> Response {
    if state.wallet_exists() {
        return Redirect::to("/").into_response();
    }
    InitTemplate { flash_error: None }.into_response()
}

async fn init_action(State(state): State<WalletWebState>) -> Response {
    if state.wallet_exists() {
        return Redirect::to("/").into_response();
    }

    let path = wallet_cli::wallet_path(&state.data_dir);
    if let Err(e) = std::fs::create_dir_all(&state.data_dir) {
        return InitTemplate {
            flash_error: Some(format!("Failed to create directory: {}", e)),
        }
        .into_response();
    }

    let wallet = Wallet::new();
    if let Err(e) = wallet.save_to_file(&path, 0) {
        return InitTemplate {
            flash_error: Some(format!("Failed to save wallet: {}", e)),
        }
        .into_response();
    }

    // Export address file
    let addr = wallet.address();
    if let Ok(addr_bytes) = crate::serialize(&addr) {
        let addr_hex = hex::encode(&addr_bytes);
        let _ = std::fs::write(wallet_cli::address_path(&state.data_dir), &addr_hex);
    }

    // Populate cache
    let mut cache = state.wallet.write().await;
    *cache = Some((wallet, 0));

    Redirect::to("/").into_response()
}

async fn address_page(State(state): State<WalletWebState>) -> Response {
    if !state.wallet_exists() {
        return Redirect::to("/init").into_response();
    }

    let (wallet, _) = match state.load_wallet().await {
        Ok(Some(w)) => w,
        Ok(None) => return Redirect::to("/init").into_response(),
        Err(e) => return error_page(e.to_string()).into_response(),
    };

    let addr = wallet.address();
    let address_id = hex::encode(&addr.address_id()[..16]);
    let signing_key_size = addr.signing.0.len();
    let kem_key_size = addr.kem.0.len();
    let address_hex = match crate::serialize(&addr) {
        Ok(bytes) => hex::encode(&bytes),
        Err(e) => return error_page(format!("Serialization error: {}", e)).into_response(),
    };

    AddressTemplate {
        address_id,
        signing_key_size,
        kem_key_size,
        address_hex,
    }
    .into_response()
}

async fn address_export(State(state): State<WalletWebState>) -> Response {
    if !state.wallet_exists() {
        return Redirect::to("/init").into_response();
    }

    let (wallet, _) = match state.load_wallet().await {
        Ok(Some(w)) => w,
        Ok(None) => return Redirect::to("/init").into_response(),
        Err(e) => return error_page(e.to_string()).into_response(),
    };

    let addr = wallet.address();
    let addr_hex = match crate::serialize(&addr) {
        Ok(bytes) => hex::encode(&bytes),
        Err(e) => return error_page(format!("Serialization error: {}", e)).into_response(),
    };

    (
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"wallet.spectra-address\"",
            ),
        ],
        addr_hex,
    )
        .into_response()
}

async fn send_page(State(state): State<WalletWebState>) -> Response {
    if !state.wallet_exists() {
        return Redirect::to("/init").into_response();
    }

    let (wallet, _) = match state.load_wallet().await {
        Ok(Some(w)) => w,
        Ok(None) => return Redirect::to("/init").into_response(),
        Err(e) => return error_page(e.to_string()).into_response(),
    };

    SendTemplate {
        balance: wallet.balance(),
        flash_error: None,
    }
    .into_response()
}

async fn send_action(State(state): State<WalletWebState>, Form(form): Form<SendForm>) -> Response {
    if !state.wallet_exists() {
        return Redirect::to("/init").into_response();
    }

    // Reload wallet from disk to get fresh state
    state.invalidate_cache().await;
    let (mut wallet, last_seq) = match state.load_wallet().await {
        Ok(Some(w)) => w,
        Ok(None) => return Redirect::to("/init").into_response(),
        Err(e) => return error_page(e.to_string()).into_response(),
    };

    // Scan chain first
    let scanned_to = match wallet_cli::scan_chain(&mut wallet, last_seq, state.rpc_addr).await {
        Ok(s) => s,
        Err(e) => {
            return SendTemplate {
                balance: wallet.balance(),
                flash_error: Some(format!("Scan failed: {}", e)),
            }
            .into_response()
        }
    };

    // Parse recipient address
    let recipient_hex = form.recipient.trim();
    let addr_bytes = match hex::decode(recipient_hex) {
        Ok(b) => b,
        Err(e) => {
            return SendTemplate {
                balance: wallet.balance(),
                flash_error: Some(format!("Invalid recipient hex: {}", e)),
            }
            .into_response()
        }
    };
    let recipient: PublicAddress = match crate::deserialize(&addr_bytes) {
        Ok(a) => a,
        Err(e) => {
            return SendTemplate {
                balance: wallet.balance(),
                flash_error: Some(format!("Invalid recipient address: {}", e)),
            }
            .into_response()
        }
    };

    // Build transaction
    let msg_bytes = form
        .message
        .filter(|m| !m.is_empty())
        .map(|m| m.into_bytes());
    let tx = match wallet.build_transaction(&recipient.kem, form.amount, form.fee, msg_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            return SendTemplate {
                balance: wallet.balance(),
                flash_error: Some(format!("Build failed: {}", e)),
            }
            .into_response()
        }
    };

    // Submit to node
    let tx_bytes = match crate::serialize(&tx) {
        Ok(b) => b,
        Err(e) => return error_page(format!("Serialization error: {}", e)).into_response(),
    };
    let tx_hex = hex::encode(&tx_bytes);

    let client = wallet_cli::RpcClient::new(state.rpc_addr);
    let result = match client.submit_tx(&tx_hex).await {
        Ok(r) => r,
        Err(e) => {
            // Cancel pending outputs since submission failed
            wallet.cancel_transaction(&tx.tx_binding);
            let _ = state.save_wallet(&wallet, scanned_to).await;
            return SendTemplate {
                balance: wallet.balance(),
                flash_error: Some(format!("Submission failed: {}", e)),
            }
            .into_response();
        }
    };

    let remaining = wallet.balance();
    // Save wallet with pending outputs
    let _ = state.save_wallet(&wallet, scanned_to).await;

    SendResultTemplate {
        tx_id: result.tx_id,
        amount: form.amount,
        fee: form.fee,
        remaining_balance: remaining,
    }
    .into_response()
}

async fn messages_page(State(state): State<WalletWebState>) -> Response {
    if !state.wallet_exists() {
        return Redirect::to("/init").into_response();
    }

    let (wallet, _) = match state.load_wallet().await {
        Ok(Some(w)) => w,
        Ok(None) => return Redirect::to("/init").into_response(),
        Err(e) => return error_page(e.to_string()).into_response(),
    };

    let messages: Vec<MessageDisplay> = wallet
        .received_messages()
        .iter()
        .map(|msg| {
            let text = std::str::from_utf8(&msg.content).ok().map(String::from);
            MessageDisplay {
                tx_hash_hex: hex::encode(&msg.tx_hash[..16]),
                text,
                binary_size: msg.content.len(),
            }
        })
        .collect();

    MessagesTemplate { messages }.into_response()
}

async fn scan_action(State(state): State<WalletWebState>) -> Response {
    if !state.wallet_exists() {
        return Redirect::to("/init").into_response();
    }

    // Reload from disk
    state.invalidate_cache().await;
    let (mut wallet, last_seq) = match state.load_wallet().await {
        Ok(Some(w)) => w,
        Ok(None) => return Redirect::to("/init").into_response(),
        Err(e) => return error_page(e.to_string()).into_response(),
    };

    let scanned_to = match wallet_cli::scan_chain(&mut wallet, last_seq, state.rpc_addr).await {
        Ok(s) => s,
        Err(e) => return error_page(format!("Scan failed: {}", e)).into_response(),
    };

    let _ = state.save_wallet(&wallet, scanned_to).await;

    // Render dashboard with success flash
    let client = wallet_cli::RpcClient::new(state.rpc_addr);
    let (chain_epoch, chain_commitments, chain_nullifiers, chain_state_root) =
        match client.get_state().await {
            Ok(info) => (
                info.epoch,
                info.commitment_count,
                info.nullifier_count,
                info.state_root,
            ),
            Err(_) => (0, 0, 0, "node unreachable".to_string()),
        };

    DashboardTemplate {
        balance: wallet.balance(),
        unspent_count: wallet.unspent_outputs().len(),
        total_outputs: wallet.output_count(),
        scanned_seq: scanned_to,
        chain_epoch,
        chain_commitments,
        chain_nullifiers,
        chain_state_root,
        flash_success: Some("Chain scan complete.".to_string()),
        flash_error: None,
    }
    .into_response()
}
