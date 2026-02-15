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

use super::cli as wallet_cli;
use super::{Wallet, WalletError};
use crate::crypto::keys::PublicAddress;

// ── State ──

/// Shared state for the wallet web server.
#[derive(Clone)]
pub struct WalletWebState {
    pub data_dir: PathBuf,
    pub rpc_addr: SocketAddr,
    /// Optional mTLS configuration for RPC connections.
    pub wallet_tls: Option<crate::config::WalletTlsConfig>,
    /// Cached wallet + last scanned sequence. None if not yet loaded.
    wallet: Arc<RwLock<Option<(Wallet, u64)>>>,
    /// Serializes mutating wallet operations (send, consolidate) to prevent
    /// race conditions between concurrent requests.
    wallet_op_lock: Arc<tokio::sync::Mutex<()>>,
    /// CSRF token for form submissions (hex-encoded 32 random bytes).
    csrf_token: String,
}

impl WalletWebState {
    fn new(
        data_dir: PathBuf,
        rpc_addr: SocketAddr,
        wallet_tls: Option<crate::config::WalletTlsConfig>,
    ) -> Self {
        let csrf_bytes: [u8; 32] = rand::random();
        WalletWebState {
            data_dir,
            rpc_addr,
            wallet_tls,
            wallet: Arc::new(RwLock::new(None)),
            wallet_op_lock: Arc::new(tokio::sync::Mutex::new(())),
            csrf_token: hex::encode(csrf_bytes),
        }
    }

    /// Validate a CSRF token from a form submission.
    fn validate_csrf(&self, token: &str) -> bool {
        crate::constant_time_eq(token.as_bytes(), self.csrf_token.as_bytes())
    }

    /// Create an RPC client, using mTLS if configured.
    fn rpc_client(&self) -> Result<wallet_cli::RpcClient, WalletError> {
        wallet_cli::RpcClient::new_maybe_tls(self.rpc_addr, self.wallet_tls.as_ref())
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
        let result = tokio::task::spawn_blocking(move || Wallet::load_from_file(&path, None))
            .await
            .map_err(|e| WalletError::Persistence(format!("spawn_blocking failed: {}", e)))?;
        let (wallet, seq) = result?;
        *cache = Some((wallet.clone(), seq));
        Ok(Some((wallet, seq)))
    }

    /// Save wallet to disk and update cache.
    async fn save_wallet(&self, wallet: &Wallet, seq: u64) -> Result<(), WalletError> {
        let path = wallet_cli::wallet_path(&self.data_dir);
        let wallet_clone = wallet.clone();
        tokio::task::spawn_blocking(move || wallet_clone.save_to_file(&path, seq, None))
            .await
            .map_err(|e| WalletError::Persistence(format!("spawn_blocking failed: {}", e)))??;
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
    active_tab: &'static str,
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
    csrf_token: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "init.html")]
struct InitTemplate {
    active_tab: &'static str,
    flash_error: Option<String>,
    csrf_token: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "address.html")]
struct AddressTemplate {
    active_tab: &'static str,
    address_id: String,
    signing_key_size: usize,
    kem_key_size: usize,
    address_hex: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "send.html")]
struct SendTemplate {
    active_tab: &'static str,
    balance: u64,
    flash_error: Option<String>,
    csrf_token: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "send_result.html")]
struct SendResultTemplate {
    active_tab: &'static str,
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
    active_tab: &'static str,
    messages: Vec<MessageDisplay>,
}

#[derive(Template, WebTemplate)]
#[template(path = "error.html")]
struct ErrorTemplate {
    active_tab: &'static str,
    message: String,
}

struct HistoryEntryDisplay {
    direction: String,
    amount: u64,
    fee: u64,
    tx_id_hex: String,
    epoch: u64,
}

#[derive(Template, WebTemplate)]
#[template(path = "history.html")]
struct HistoryTemplate {
    active_tab: &'static str,
    entries: Vec<HistoryEntryDisplay>,
}

fn error_page(msg: impl Into<String>) -> ErrorTemplate {
    ErrorTemplate {
        active_tab: "",
        message: msg.into(),
    }
}

// ── Form types ──

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct SendForm {
    csrf_token: String,
    recipient: String,
    amount: u64,
    message: Option<String>,
}

// ── Router ──

/// Middleware that adds security headers to every response.
async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("Cache-Control", "no-store".parse().unwrap());
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'"
            .parse()
            .unwrap(),
    );
    response
}

/// Build the wallet web router.
pub fn router(state: WalletWebState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/init", get(init_page).post(init_action))
        .route("/address", get(address_page))
        .route("/address/export", get(address_export))
        .route("/send", get(send_page).post(send_action))
        .route("/messages", get(messages_page))
        .route("/history", get(history_page))
        .route("/scan", post(scan_action))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

/// Start the wallet web server.
pub async fn serve(
    addr: SocketAddr,
    data_dir: PathBuf,
    rpc_addr: SocketAddr,
    wallet_tls: Option<crate::config::WalletTlsConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    // M17: Warn when binding to a non-loopback address, since the wallet web
    // UI has no authentication and exposes spending capabilities.
    if !addr.ip().is_loopback() {
        tracing::warn!(
            bind_addr = %addr,
            "Wallet web UI is binding to a non-loopback address. \
             This exposes wallet operations to the network. \
             Use 127.0.0.1 unless you understand the risks."
        );
    }

    let state = WalletWebState::new(data_dir.clone(), rpc_addr, wallet_tls);
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
    let (chain_epoch, chain_commitments, chain_nullifiers, chain_state_root) =
        match state.rpc_client() {
            Ok(client) => match client.get_state().await {
                Ok(info) => (
                    info.epoch,
                    info.commitment_count,
                    info.nullifier_count,
                    info.state_root,
                ),
                Err(_) => (0, 0, 0, "node unreachable".to_string()),
            },
            Err(_) => (0, 0, 0, "TLS config error".to_string()),
        };

    DashboardTemplate {
        active_tab: "dashboard",
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
        csrf_token: state.csrf_token.clone(),
    }
    .into_response()
}

async fn init_page(State(state): State<WalletWebState>) -> Response {
    if state.wallet_exists() {
        return Redirect::to("/").into_response();
    }
    InitTemplate {
        active_tab: "",
        flash_error: None,
        csrf_token: state.csrf_token.clone(),
    }
    .into_response()
}

async fn init_action(State(state): State<WalletWebState>, Form(form): Form<CsrfForm>) -> Response {
    if !state.validate_csrf(&form.csrf_token) {
        return InitTemplate {
            active_tab: "",
            flash_error: Some("Invalid CSRF token. Please reload the page and try again.".into()),
            csrf_token: state.csrf_token.clone(),
        }
        .into_response();
    }

    if state.wallet_exists() {
        return Redirect::to("/").into_response();
    }

    let path = wallet_cli::wallet_path(&state.data_dir);
    if let Err(e) = std::fs::create_dir_all(&state.data_dir) {
        return InitTemplate {
            active_tab: "",
            flash_error: Some(format!("Failed to create directory: {}", e)),
            csrf_token: state.csrf_token.clone(),
        }
        .into_response();
    }

    let wallet = Wallet::new();
    if let Err(e) = wallet.save_to_file(&path, 0, None) {
        return InitTemplate {
            active_tab: "",
            flash_error: Some(format!("Failed to save wallet: {}", e)),
            csrf_token: state.csrf_token.clone(),
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
        active_tab: "address",
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
                "attachment; filename=\"wallet.umbra-address\"",
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
        active_tab: "send",
        balance: wallet.balance(),
        flash_error: None,
        csrf_token: state.csrf_token.clone(),
    }
    .into_response()
}

async fn send_action(State(state): State<WalletWebState>, Form(form): Form<SendForm>) -> Response {
    if !state.validate_csrf(&form.csrf_token) {
        return SendTemplate {
            active_tab: "send",
            balance: 0,
            flash_error: Some("Invalid CSRF token. Please reload the page and try again.".into()),
            csrf_token: state.csrf_token.clone(),
        }
        .into_response();
    }

    if !state.wallet_exists() {
        return Redirect::to("/init").into_response();
    }

    // Acquire the operation lock to prevent concurrent mutations
    let _guard = state.wallet_op_lock.lock().await;

    // Reload wallet from disk to get fresh state
    state.invalidate_cache().await;
    let (mut wallet, last_seq) = match state.load_wallet().await {
        Ok(Some(w)) => w,
        Ok(None) => return Redirect::to("/init").into_response(),
        Err(e) => return error_page(e.to_string()).into_response(),
    };

    // Scan chain first
    let scanned_to = match wallet_cli::scan_chain(
        &mut wallet,
        last_seq,
        state.rpc_addr,
        state.wallet_tls.as_ref(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            return SendTemplate {
                active_tab: "send",
                balance: wallet.balance(),
                flash_error: Some(format!("Scan failed: {}", e)),
                csrf_token: state.csrf_token.clone(),
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
                active_tab: "send",
                balance: wallet.balance(),
                flash_error: Some(format!("Invalid recipient hex: {}", e)),
                csrf_token: state.csrf_token.clone(),
            }
            .into_response()
        }
    };
    let recipient: PublicAddress = match crate::deserialize(&addr_bytes) {
        Ok(a) => a,
        Err(e) => {
            return SendTemplate {
                active_tab: "send",
                balance: wallet.balance(),
                flash_error: Some(format!("Invalid recipient address: {}", e)),
                csrf_token: state.csrf_token.clone(),
            }
            .into_response()
        }
    };

    // Validate message size before building transaction.
    // The ciphertext after encryption is padded: ceil((len+4)/64)*64 bytes.
    // validate_structure checks ciphertext.len() > MAX_MESSAGE_SIZE, so we
    // must check the estimated ciphertext size, not the raw plaintext size.
    let msg_bytes = form
        .message
        .filter(|m| !m.is_empty())
        .map(|m| m.into_bytes());
    if let Some(ref msg) = msg_bytes {
        let estimated_ciphertext_len = msg.len().saturating_add(4).div_ceil(64) * 64;
        if estimated_ciphertext_len > crate::constants::MAX_MESSAGE_SIZE {
            return SendTemplate {
                active_tab: "send",
                balance: wallet.balance(),
                flash_error: Some(format!(
                    "Message too large: {} bytes (encrypted ~{} bytes, max {})",
                    msg.len(),
                    estimated_ciphertext_len,
                    crate::constants::MAX_MESSAGE_SIZE
                )),
                csrf_token: state.csrf_token.clone(),
            }
            .into_response();
        }
    }

    // Build transaction (fee is auto-computed)
    let tx = match wallet.build_transaction(&recipient.kem, form.amount, msg_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            return SendTemplate {
                active_tab: "send",
                balance: wallet.balance(),
                flash_error: Some(format!("Build failed: {}", e)),
                csrf_token: state.csrf_token.clone(),
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

    let client = match state.rpc_client() {
        Ok(c) => c,
        Err(e) => return error_page(format!("TLS config error: {}", e)).into_response(),
    };
    let result = match client.submit_tx(&tx_hex).await {
        Ok(r) => r,
        Err(e) => {
            // Cancel pending outputs since submission failed
            wallet.cancel_transaction(&tx.tx_binding);
            let _ = state.save_wallet(&wallet, scanned_to).await;
            return SendTemplate {
                active_tab: "send",
                balance: wallet.balance(),
                flash_error: Some(format!("Submission failed: {}", e)),
                csrf_token: state.csrf_token.clone(),
            }
            .into_response();
        }
    };

    let remaining = wallet.balance();
    // Save wallet with pending outputs
    let _ = state.save_wallet(&wallet, scanned_to).await;

    SendResultTemplate {
        active_tab: "send",
        tx_id: result.tx_id,
        amount: form.amount,
        fee: tx.fee,
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

    MessagesTemplate {
        active_tab: "messages",
        messages,
    }
    .into_response()
}

async fn history_page(State(state): State<WalletWebState>) -> Response {
    if !state.wallet_exists() {
        return Redirect::to("/init").into_response();
    }

    let (wallet, _) = match state.load_wallet().await {
        Ok(Some(w)) => w,
        Ok(None) => return Redirect::to("/init").into_response(),
        Err(e) => return error_page(e.to_string()).into_response(),
    };

    use super::TxDirection;
    let entries: Vec<HistoryEntryDisplay> = wallet
        .history()
        .iter()
        .rev()
        .map(|e| HistoryEntryDisplay {
            direction: match e.direction {
                TxDirection::Send => "Send".to_string(),
                TxDirection::Receive => "Receive".to_string(),
                TxDirection::Coinbase => "Coinbase".to_string(),
            },
            amount: e.amount,
            fee: e.fee,
            tx_id_hex: hex::encode(&e.tx_id[..8]),
            epoch: e.epoch,
        })
        .collect();

    HistoryTemplate {
        active_tab: "history",
        entries,
    }
    .into_response()
}

async fn scan_action(State(state): State<WalletWebState>, Form(form): Form<CsrfForm>) -> Response {
    if !state.validate_csrf(&form.csrf_token) {
        return error_page("Invalid CSRF token. Please reload the page and try again.")
            .into_response();
    }

    if !state.wallet_exists() {
        return Redirect::to("/init").into_response();
    }

    // Acquire the operation lock to prevent concurrent mutations
    let _guard = state.wallet_op_lock.lock().await;

    // Reload from disk
    state.invalidate_cache().await;
    let (mut wallet, last_seq) = match state.load_wallet().await {
        Ok(Some(w)) => w,
        Ok(None) => return Redirect::to("/init").into_response(),
        Err(e) => return error_page(e.to_string()).into_response(),
    };

    let scanned_to = match wallet_cli::scan_chain(
        &mut wallet,
        last_seq,
        state.rpc_addr,
        state.wallet_tls.as_ref(),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return error_page(format!("Scan failed: {}", e)).into_response(),
    };

    let _ = state.save_wallet(&wallet, scanned_to).await;

    // Render dashboard with success flash
    let (chain_epoch, chain_commitments, chain_nullifiers, chain_state_root) =
        match state.rpc_client() {
            Ok(client) => match client.get_state().await {
                Ok(info) => (
                    info.epoch,
                    info.commitment_count,
                    info.nullifier_count,
                    info.state_root,
                ),
                Err(_) => (0, 0, 0, "node unreachable".to_string()),
            },
            Err(_) => (0, 0, 0, "TLS config error".to_string()),
        };

    DashboardTemplate {
        active_tab: "dashboard",
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
        csrf_token: state.csrf_token.clone(),
    }
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state(dir: &std::path::Path) -> WalletWebState {
        WalletWebState::new(dir.to_path_buf(), "127.0.0.1:18080".parse().unwrap(), None)
    }

    async fn send_request(
        app: Router,
        req: Request<Body>,
    ) -> axum::http::Response<axum::body::Body> {
        app.oneshot(req).await.unwrap()
    }

    #[test]
    fn wallet_web_state_new_has_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        assert_eq!(state.data_dir, dir.path());
        assert!(state.wallet_tls.is_none());
    }

    #[test]
    fn wallet_exists_returns_false_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        assert!(!state.wallet_exists());
    }

    #[test]
    fn wallet_exists_returns_true_when_file_present() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = Wallet::new();
        let path = wallet_cli::wallet_path(dir.path());
        wallet.save_to_file(&path, 0, None).unwrap();
        let state = test_state(dir.path());
        assert!(state.wallet_exists());
    }

    #[test]
    fn rpc_client_without_tls() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        // Should succeed and create a plain HTTP client
        let _client = state.rpc_client().unwrap();
    }

    #[tokio::test]
    async fn invalidate_cache_clears_loaded_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        // Manually populate cache
        {
            let mut cache = state.wallet.write().await;
            *cache = Some((Wallet::new(), 42));
        }
        // Verify cache is populated
        {
            let cache = state.wallet.read().await;
            assert!(cache.is_some());
        }
        state.invalidate_cache().await;
        let cache = state.wallet.read().await;
        assert!(cache.is_none());
    }

    #[tokio::test]
    async fn load_wallet_returns_none_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let result = state.load_wallet().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn load_wallet_caches_on_first_load() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = Wallet::new();
        let path = wallet_cli::wallet_path(dir.path());
        wallet.save_to_file(&path, 7, None).unwrap();

        let state = test_state(dir.path());
        let result = state.load_wallet().await.unwrap();
        assert!(result.is_some());
        let (w, seq) = result.unwrap();
        assert_eq!(seq, 7);
        assert_eq!(w.balance(), 0);

        // Second call should return cached value
        let result2 = state.load_wallet().await.unwrap();
        assert!(result2.is_some());
    }

    #[tokio::test]
    async fn save_wallet_updates_cache() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        let state = test_state(dir.path());
        let wallet = Wallet::new();
        state.save_wallet(&wallet, 99).await.unwrap();

        let cache = state.wallet.read().await;
        let (_, seq) = cache.as_ref().unwrap();
        assert_eq!(*seq, 99);
    }

    #[test]
    fn error_page_sets_message() {
        let tpl = error_page("something broke");
        assert_eq!(tpl.message, "something broke");
        assert_eq!(tpl.active_tab, "");
    }

    #[tokio::test]
    async fn dashboard_redirects_to_init_when_no_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = router(state);
        let resp = send_request(app, Request::get("/").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), 303); // See Other redirect
        assert_eq!(resp.headers().get("location").unwrap(), "/init");
    }

    #[tokio::test]
    async fn init_page_returns_200_when_no_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = router(state);
        let resp = send_request(app, Request::get("/init").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn init_page_redirects_when_wallet_exists() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = Wallet::new();
        let path = wallet_cli::wallet_path(dir.path());
        wallet.save_to_file(&path, 0, None).unwrap();

        let state = test_state(dir.path());
        let app = router(state);
        let resp = send_request(app, Request::get("/init").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), 303);
        assert_eq!(resp.headers().get("location").unwrap(), "/");
    }

    #[tokio::test]
    async fn init_action_creates_wallet_and_redirects() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let csrf = state.csrf_token.clone();
        let app = router(state);
        let body = format!("csrf_token={}", csrf);
        let resp = send_request(
            app,
            Request::post("/init")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), 303);
        assert_eq!(resp.headers().get("location").unwrap(), "/");
        // Wallet file should now exist
        assert!(wallet_cli::wallet_path(dir.path()).exists());
        // Address file should also exist
        assert!(wallet_cli::address_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn init_action_rejects_invalid_csrf() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = router(state);
        let body = "csrf_token=invalid_token_value";
        let resp = send_request(
            app,
            Request::post("/init")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
        // Should return 200 with error page, not redirect
        assert_eq!(resp.status(), 200);
        // Wallet file should NOT exist
        assert!(!wallet_cli::wallet_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn scan_action_rejects_invalid_csrf() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        // Create wallet first
        let wallet = Wallet::new();
        let path = wallet_cli::wallet_path(dir.path());
        wallet.save_to_file(&path, 0, None).unwrap();

        let app = router(state);
        let body = "csrf_token=invalid_token_value";
        let resp = send_request(
            app,
            Request::post("/scan")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status(), 200);
    }

    #[test]
    fn csrf_token_validation() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let valid_token = state.csrf_token.clone();
        assert!(state.validate_csrf(&valid_token));
        assert!(!state.validate_csrf("wrong_token"));
        assert!(!state.validate_csrf(""));
    }

    #[tokio::test]
    async fn security_headers_present() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = router(state);
        let resp = send_request(app, Request::get("/init").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.headers().get("X-Frame-Options").unwrap(), "DENY");
        assert_eq!(
            resp.headers().get("X-Content-Type-Options").unwrap(),
            "nosniff"
        );
        assert_eq!(resp.headers().get("Cache-Control").unwrap(), "no-store");
        assert!(resp
            .headers()
            .get("Content-Security-Policy")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("default-src 'self'"));
    }

    #[tokio::test]
    async fn send_page_redirects_without_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = router(state);
        let resp = send_request(app, Request::get("/send").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), 303);
        assert_eq!(resp.headers().get("location").unwrap(), "/init");
    }

    #[tokio::test]
    async fn messages_page_redirects_without_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = router(state);
        let resp = send_request(app, Request::get("/messages").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), 303);
        assert_eq!(resp.headers().get("location").unwrap(), "/init");
    }

    #[tokio::test]
    async fn history_page_redirects_without_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = router(state);
        let resp = send_request(app, Request::get("/history").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), 303);
        assert_eq!(resp.headers().get("location").unwrap(), "/init");
    }

    #[tokio::test]
    async fn address_page_redirects_without_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = router(state);
        let resp = send_request(app, Request::get("/address").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), 303);
        assert_eq!(resp.headers().get("location").unwrap(), "/init");
    }

    #[tokio::test]
    async fn nonexistent_route_returns_404() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let app = router(state);
        let resp = send_request(
            app,
            Request::get("/nonexistent").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(resp.status(), 404);
    }
}
