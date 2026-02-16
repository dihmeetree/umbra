//! JSON HTTP RPC API for the Umbra node.
//!
//! Provides endpoints for submitting transactions, querying state,
//! and inspecting the mempool and peer list.
//!
//! # Authentication (mTLS)
//!
//! The RPC server supports mutual TLS (mTLS) for non-localhost deployments.
//! When TLS is configured, both the server and client authenticate via
//! certificates signed by a trusted CA. The server refuses to start on
//! non-loopback addresses without TLS configured.
//!
//! # Privacy considerations
//!
//! Some RPC endpoints reveal aggregate chain state information:
//! - `/state` and `/state-summary` expose commitment and nullifier counts,
//!   which reveal overall chain activity. This is inherent to public blockchains.
//! - `/commitment-proof/{index}` returns Merkle proofs for arbitrary indices,
//!   enabling tree enumeration. Wallets querying this endpoint from a public
//!   node reveal which commitment indices they hold.
//!
//! For production deployments exposed beyond localhost:
//! - Add rate-limiting middleware (e.g., `tower::limit`) to sensitive endpoints.
//! - Consider requiring authentication for `/commitment-proof` queries.
//! - Run wallet scanning against a local trusted node, not a remote RPC.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::TlsConfig;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::storage::Storage;
use super::NodeState;
use crate::network::p2p::P2pHandle;
use crate::transaction::TxId;

/// Maximum commitment-proof queries per IP per window.
const COMMITMENT_PROOF_RATE_LIMIT: u32 = 60;
/// Rate limit window duration in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Maximum number of entries in the rate limiter map before eviction.
const RATE_LIMITER_MAX_ENTRIES: usize = 50_000;

/// Shared RPC state.
#[derive(Clone)]
pub struct RpcState {
    pub node: Arc<RwLock<NodeState>>,
    pub p2p: P2pHandle,
    /// Per-IP rate limiter for sensitive endpoints (commitment-proof).
    /// Maps IP → (request_count, window_start).
    rate_limiter: Arc<tokio::sync::Mutex<HashMap<std::net::IpAddr, (u32, std::time::Instant)>>>,
}

impl RpcState {
    /// Create a new RpcState with rate limiting.
    pub fn new(node: Arc<RwLock<NodeState>>, p2p: P2pHandle) -> Self {
        Self {
            node,
            p2p,
            rate_limiter: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }
}

/// Build the RPC router.
pub fn router(rpc_state: RpcState) -> Router {
    Router::new()
        .route("/tx", post(submit_tx))
        .route("/tx/{id}", get(get_tx))
        .route("/state", get(get_state))
        .route("/peers", get(get_peers))
        .route("/mempool", get(get_mempool))
        .route("/validators", get(get_validators))
        .route("/validator/{id}", get(get_validator))
        .route("/vertices/finalized", get(get_finalized_vertices))
        .route("/health", get(get_health))
        .route("/metrics", get(get_metrics))
        .route("/fee-estimate", get(get_fee_estimate))
        .route("/vertex/{id}", get(get_vertex_by_id))
        .route("/commitment-proof/{index}", get(get_commitment_proof))
        .route("/state-summary", get(get_state_summary))
        .with_state(rpc_state)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024)) // 2 MB max body
}

/// Loaded TLS configuration ready for use with `axum-server`.
pub struct LoadedTlsConfig {
    pub config: axum_server::tls_rustls::RustlsConfig,
}

/// Load and validate TLS configuration for mTLS.
///
/// Builds a `rustls::ServerConfig` that:
/// 1. Requires client certificates signed by the configured CA
/// 2. Presents the server certificate to clients
/// 3. Supports HTTP/1.1 and HTTP/2 via ALPN
pub fn load_tls(
    tls_config: &TlsConfig,
) -> Result<LoadedTlsConfig, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::RootCertStore;

    // Load CA certificate for client verification
    let ca_pem = std::fs::read(&tls_config.ca_cert_file)?;
    let mut ca_reader = std::io::BufReader::new(ca_pem.as_slice());
    let ca_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut ca_reader).collect::<Result<Vec<_>, _>>()?;
    if ca_certs.is_empty() {
        return Err("no certificates found in CA cert file".into());
    }

    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| format!("failed to build client verifier: {}", e))?;

    // Load server certificate chain
    let cert_pem = std::fs::read(&tls_config.cert_file)?;
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let server_certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    if server_certs.is_empty() {
        return Err("no certificates found in server cert file".into());
    }

    // Load server private key
    let key_pem = std::fs::read(&tls_config.key_file)?;
    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let server_key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_reader)?.ok_or("no private key found in key file")?;

    // Build rustls ServerConfig with client authentication
    let mut server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .map_err(|e| format!("TLS server config error: {}", e))?;

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));

    Ok(LoadedTlsConfig {
        config: rustls_config,
    })
}

/// Start the RPC server, optionally with mTLS.
pub async fn serve(
    addr: SocketAddr,
    rpc_state: RpcState,
    tls: Option<LoadedTlsConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = router(rpc_state);
    match tls {
        Some(loaded) => {
            tracing::info!(addr = %addr, tls = true, "RPC server listening");
            axum_server::bind_rustls(addr, loaded.config)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!(addr = %addr, tls = false, "RPC server listening");
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
    }
    Ok(())
}

// ── POST /tx ──

#[derive(Deserialize)]
struct SubmitTxRequest {
    /// Hex-encoded bincode-serialized transaction.
    tx_hex: String,
}

#[derive(Serialize)]
struct SubmitTxResponse {
    tx_id: String,
}

async fn submit_tx(
    State(state): State<RpcState>,
    Json(req): Json<SubmitTxRequest>,
) -> Result<Json<SubmitTxResponse>, (StatusCode, String)> {
    // Reject oversized payloads before decoding
    if req.tx_hex.len() > 2 * crate::constants::MAX_NETWORK_MESSAGE_BYTES {
        return Err((StatusCode::BAD_REQUEST, "transaction too large".to_string()));
    }

    let tx_bytes = hex::decode(&req.tx_hex).map_err(|e| {
        tracing::debug!(error = %e, "RPC submit_tx: invalid hex encoding");
        (StatusCode::BAD_REQUEST, "invalid hex encoding".to_string())
    })?;
    let tx: crate::transaction::Transaction = crate::deserialize(&tx_bytes).map_err(|e| {
        tracing::debug!(error = %e, "RPC submit_tx: failed to decode transaction");
        (
            StatusCode::BAD_REQUEST,
            "invalid transaction encoding".to_string(),
        )
    })?;

    let tx_id = tx.tx_id();
    let mut node = state.node.write().await;
    node.mempool.insert(tx.clone()).map_err(|e| {
        tracing::debug!(error = %e, "RPC submit_tx: transaction rejected by mempool");
        (StatusCode::BAD_REQUEST, "transaction rejected".to_string())
    })?;

    // Dandelion++ stem phase: send to a single random peer instead of broadcasting
    // to all peers. This prevents the RPC-connected node from being identified as
    // the transaction originator. The receiving peer will either continue the stem
    // relay or fluff (broadcast) according to the Dandelion++ protocol.
    drop(node); // Release write lock before async send
    let stem_target = state.p2p.get_peers().await.ok().and_then(|peers| {
        use rand::prelude::IndexedRandom;
        peers.choose(&mut rand::rng()).map(|p| p.peer_id)
    });
    match stem_target {
        Some(peer_id) => {
            if let Err(e) = state
                .p2p
                .send_to(peer_id, crate::network::Message::NewTransaction(tx.clone()))
                .await
            {
                tracing::warn!(error = %e, "Failed to stem-send transaction, falling back to broadcast");
                let _ = state
                    .p2p
                    .broadcast(crate::network::Message::NewTransaction(tx), None)
                    .await;
            }
        }
        None => {
            // No peers available: fall back to broadcast
            let _ = state
                .p2p
                .broadcast(crate::network::Message::NewTransaction(tx), None)
                .await;
        }
    }

    Ok(Json(SubmitTxResponse {
        tx_id: hex::encode(tx_id.0),
    }))
}

// ── GET /tx/:id ──

#[derive(Serialize)]
struct GetTxResponse {
    found: bool,
    tx_hex: Option<String>,
    source: String,
}

async fn get_tx(
    State(state): State<RpcState>,
    Path(id_hex): Path<String>,
) -> Result<Json<GetTxResponse>, (StatusCode, String)> {
    let id_bytes: [u8; 32] = hex::decode(&id_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid id: {}", e)))?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "id must be 32 bytes hex".to_string(),
            )
        })?;
    let tx_id = TxId(id_bytes);

    let node = state.node.read().await;

    // Check mempool first
    if let Some(tx) = node.mempool.get(&tx_id) {
        let tx_hex = crate::serialize(tx).map(hex::encode).map_err(|e| {
            tracing::error!(error = %e, "RPC get_tx: failed to serialize mempool transaction");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            )
        })?;
        return Ok(Json(GetTxResponse {
            found: true,
            tx_hex: Some(tx_hex),
            source: "mempool".into(),
        }));
    }

    // Then storage
    if let Ok(Some(tx)) = node.storage.get_transaction(&tx_id) {
        let tx_hex = crate::serialize(&tx).map(hex::encode).map_err(|e| {
            tracing::error!(error = %e, "RPC get_tx: failed to serialize stored transaction");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            )
        })?;
        return Ok(Json(GetTxResponse {
            found: true,
            tx_hex: Some(tx_hex),
            source: "storage".into(),
        }));
    }

    Ok(Json(GetTxResponse {
        found: false,
        tx_hex: None,
        source: "none".into(),
    }))
}

// ── GET /state ──

#[derive(Serialize)]
struct ChainStateResponse {
    epoch: u64,
    commitment_count: usize,
    nullifier_count: usize,
    state_root: String,
    commitment_root: String,
    last_finalized: Option<String>,
    total_minted: u64,
}

async fn get_state(State(state): State<RpcState>) -> Json<ChainStateResponse> {
    let node = state.node.read().await;
    let s = &node.ledger.state;
    Json(ChainStateResponse {
        epoch: s.epoch(),
        commitment_count: s.commitment_count(),
        nullifier_count: s.nullifier_count(),
        state_root: hex::encode(s.state_root()),
        commitment_root: hex::encode(s.commitment_root()),
        last_finalized: s.last_finalized().map(|v| hex::encode(v.0)),
        total_minted: s.total_minted(),
    })
}

// ── GET /peers ──

#[derive(Serialize)]
struct PeerInfoResponse {
    peer_id: String,
    last_seen: u64,
}

async fn get_peers(State(state): State<RpcState>) -> Json<Vec<PeerInfoResponse>> {
    let peers = state.p2p.get_peers().await.unwrap_or_default();
    let response: Vec<PeerInfoResponse> = peers
        .into_iter()
        .map(|p| PeerInfoResponse {
            peer_id: hex::encode(p.peer_id),
            last_seen: p.last_seen,
        })
        .collect();
    Json(response)
}

// ── GET /mempool ──

async fn get_mempool(State(state): State<RpcState>) -> Json<super::mempool::MempoolStats> {
    let node = state.node.read().await;
    Json(node.mempool.stats())
}

// ── GET /validators ──

#[derive(Serialize)]
struct ValidatorResponse {
    id: String,
    active: bool,
    bond: Option<u64>,
    slashed: bool,
}

async fn get_validators(State(state): State<RpcState>) -> Json<Vec<ValidatorResponse>> {
    let node = state.node.read().await;
    let s = &node.ledger.state;
    let validators: Vec<ValidatorResponse> = s
        .all_validators()
        .into_iter()
        .map(|v| ValidatorResponse {
            id: hex::encode(v.id),
            active: v.active,
            bond: s.validator_bond(&v.id),
            slashed: s.is_slashed(&v.id),
        })
        .collect();
    Json(validators)
}

// ── GET /validator/:id ──

async fn get_validator(
    State(state): State<RpcState>,
    Path(id_hex): Path<String>,
) -> Result<Json<ValidatorResponse>, (StatusCode, String)> {
    let id_bytes: [u8; 32] = hex::decode(&id_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid id: {}", e)))?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "id must be 32 bytes hex".to_string(),
            )
        })?;

    let node = state.node.read().await;
    let s = &node.ledger.state;
    let validator = s
        .get_validator(&id_bytes)
        .ok_or((StatusCode::NOT_FOUND, "validator not found".to_string()))?;

    Ok(Json(ValidatorResponse {
        id: hex::encode(validator.id),
        active: validator.active,
        bond: s.validator_bond(&id_bytes),
        slashed: s.is_slashed(&id_bytes),
    }))
}

// ── GET /vertices/finalized ──

#[derive(Deserialize)]
struct FinalizedVerticesQuery {
    /// Return vertices with sequence > after (default: return from start)
    #[serde(default)]
    after: u64,
    /// Maximum number of vertices to return (capped at 100)
    #[serde(default = "default_finalized_limit")]
    limit: u32,
}

fn default_finalized_limit() -> u32 {
    crate::constants::SYNC_BATCH_SIZE
}

#[derive(Serialize)]
struct FinalizedVerticesResponse {
    vertices: Vec<FinalizedVertexEntry>,
    has_more: bool,
    total: u64,
}

#[derive(Serialize)]
struct FinalizedVertexEntry {
    sequence: u64,
    vertex_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    coinbase_hex: Option<String>,
}

async fn get_finalized_vertices(
    State(state): State<RpcState>,
    Query(params): Query<FinalizedVerticesQuery>,
) -> Result<Json<FinalizedVerticesResponse>, (StatusCode, String)> {
    let node = state.node.read().await;
    let limit = params.limit.min(crate::constants::SYNC_BATCH_SIZE);
    let total = node.storage.finalized_vertex_count().unwrap_or(0);

    let raw_vertices = node
        .storage
        .get_finalized_vertices_after(params.after, limit)
        .map_err(|e| {
            tracing::error!(error = %e, "RPC get_finalized_vertices: storage read failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            )
        })?;

    let has_more = raw_vertices.len() == limit as usize;

    let entries: Vec<FinalizedVertexEntry> = raw_vertices
        .into_iter()
        .filter_map(|(seq, v)| match crate::serialize(&v) {
            Ok(bytes) => {
                let coinbase_hex = node
                    .storage
                    .get_coinbase_output(seq)
                    .ok()
                    .flatten()
                    .and_then(|cb| crate::serialize(&cb).ok())
                    .map(hex::encode);
                Some(FinalizedVertexEntry {
                    sequence: seq,
                    vertex_hex: hex::encode(bytes),
                    coinbase_hex,
                })
            }
            Err(e) => {
                tracing::error!(seq = seq, error = %e, "Failed to serialize vertex");
                None
            }
        })
        .collect();

    Ok(Json(FinalizedVerticesResponse {
        vertices: entries,
        has_more,
        total,
    }))
}

// ── GET /health (F3) ──

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
    peer_count: usize,
    epoch: u64,
    finalized_count: u64,
    mempool_txs: usize,
}

async fn get_health(State(state): State<RpcState>) -> Json<HealthResponse> {
    let node = state.node.read().await;
    let uptime = node.node_start_time.elapsed().as_secs();
    let peer_count = state.p2p.get_peers().await.map(|p| p.len()).unwrap_or(0);
    let finalized_count = node.storage.finalized_vertex_count().unwrap_or(0);
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_seconds: uptime,
        peer_count,
        epoch: node.ledger.state.epoch(),
        finalized_count,
        mempool_txs: node.mempool.len(),
    })
}

// ── GET /metrics (F3) ──

async fn get_metrics(
    State(state): State<RpcState>,
) -> (
    StatusCode,
    [(axum::http::HeaderName, &'static str); 1],
    String,
) {
    let node = state.node.read().await;
    let uptime = node.node_start_time.elapsed().as_secs();
    let peer_count = state.p2p.get_peers().await.map(|p| p.len()).unwrap_or(0);
    let finalized_count = node.storage.finalized_vertex_count().unwrap_or(0);
    let mempool_txs = node.mempool.len();
    let mempool_bytes = node.mempool.total_bytes();
    let epoch = node.ledger.state.epoch();

    let body = format!(
        "# HELP umbra_uptime_seconds Node uptime in seconds\n\
         # TYPE umbra_uptime_seconds gauge\n\
         umbra_uptime_seconds {uptime}\n\
         # HELP umbra_peer_count Number of connected peers\n\
         # TYPE umbra_peer_count gauge\n\
         umbra_peer_count {peer_count}\n\
         # HELP umbra_epoch Current epoch number\n\
         # TYPE umbra_epoch gauge\n\
         umbra_epoch {epoch}\n\
         # HELP umbra_finalized_vertices Total finalized vertices\n\
         # TYPE umbra_finalized_vertices counter\n\
         umbra_finalized_vertices {finalized_count}\n\
         # HELP umbra_mempool_txs Current mempool transaction count\n\
         # TYPE umbra_mempool_txs gauge\n\
         umbra_mempool_txs {mempool_txs}\n\
         # HELP umbra_mempool_bytes Current mempool size in bytes\n\
         # TYPE umbra_mempool_bytes gauge\n\
         umbra_mempool_bytes {mempool_bytes}\n"
    );
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

// ── GET /fee-estimate (F4) ──

#[derive(Deserialize)]
struct FeeEstimateQuery {
    /// Number of inputs (default: 1)
    #[serde(default = "default_one")]
    inputs: usize,
    /// Total message bytes (default: 0)
    #[serde(default)]
    message_bytes: usize,
}

fn default_one() -> usize {
    1
}

#[derive(Serialize)]
struct FeeEstimateResponse {
    fee: u64,
    base: u64,
    per_input: u64,
    per_message_kb: u64,
}

async fn get_fee_estimate(Query(params): Query<FeeEstimateQuery>) -> Json<FeeEstimateResponse> {
    let fee = crate::constants::compute_weight_fee(params.inputs, params.message_bytes);
    Json(FeeEstimateResponse {
        fee,
        base: crate::constants::FEE_BASE,
        per_input: crate::constants::FEE_PER_INPUT,
        per_message_kb: crate::constants::FEE_PER_MESSAGE_KB,
    })
}

// ── GET /vertex/:id (F15) ──

async fn get_vertex_by_id(
    State(state): State<RpcState>,
    Path(id_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let id_bytes: [u8; 32] = hex::decode(&id_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid id: {}", e)))?
        .try_into()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "id must be 32 bytes hex".to_string(),
            )
        })?;

    let vertex_id = crate::consensus::dag::VertexId(id_bytes);
    let node = state.node.read().await;

    // Check DAG first, then storage
    let vertex = node
        .ledger
        .dag
        .get(&vertex_id)
        .cloned()
        .or_else(|| node.storage.get_vertex(&vertex_id).ok().flatten());

    match vertex {
        Some(v) => {
            let hex = crate::serialize(&v).map(hex::encode).map_err(|e| {
                tracing::error!(error = %e, "RPC get_vertex_by_id: failed to serialize vertex");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            })?;
            Ok(Json(serde_json::json!({
                "found": true,
                "vertex_hex": hex,
                "epoch": v.epoch,
                "round": v.round,
                "tx_count": v.transactions.len(),
            })))
        }
        None => Ok(Json(serde_json::json!({"found": false}))),
    }
}

// ── GET /commitment-proof/:index (F15) ──
// Privacy note: this endpoint allows querying proofs for arbitrary indices.
// In production, rate-limit or require authentication to prevent tree enumeration.

#[derive(Serialize)]
struct CommitmentProofResponse {
    index: usize,
    commitment: String,
    merkle_path: Vec<String>,
    root: String,
}

async fn get_commitment_proof(
    State(state): State<RpcState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(index): Path<usize>,
) -> Result<Json<CommitmentProofResponse>, (StatusCode, String)> {
    // Rate limit: prevent tree enumeration attacks
    {
        let mut limiter = state.rate_limiter.lock().await;
        let now = std::time::Instant::now();

        // Proactive eviction of expired entries on every request to prevent
        // memory bloat from many unique IPs. Only scan if over half capacity.
        if limiter.len() > RATE_LIMITER_MAX_ENTRIES / 2 {
            limiter.retain(|_, (_, start)| {
                now.duration_since(*start).as_secs() < RATE_LIMIT_WINDOW_SECS
            });
            if limiter.len() > RATE_LIMITER_MAX_ENTRIES {
                tracing::warn!(
                    entries = limiter.len(),
                    "rate limiter over capacity after eviction"
                );
            }
        }

        let entry = limiter.entry(addr.ip()).or_insert((0, now));
        // Use duration_since (monotonic) to handle clock skew safely.
        // If the entry's start time is somehow in the future (shouldn't happen
        // with Instant but defensive), treat the window as expired.
        let elapsed = now.saturating_duration_since(entry.1).as_secs();
        if elapsed >= RATE_LIMIT_WINDOW_SECS {
            // Reset window
            *entry = (1, now);
        } else {
            entry.0 += 1;
            if entry.0 > COMMITMENT_PROOF_RATE_LIMIT {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate limit exceeded for commitment-proof queries".to_string(),
                ));
            }
        }
    }

    let node = state.node.read().await;
    let path = node.ledger.state.commitment_path(index).ok_or((
        StatusCode::NOT_FOUND,
        "commitment index out of range".into(),
    ))?;

    let commitment_hash = node.ledger.state.commitment_tree_node(0, index);
    let root = node.ledger.state.commitment_root();

    Ok(Json(CommitmentProofResponse {
        index,
        commitment: hex::encode(commitment_hash),
        merkle_path: path.iter().map(|n| hex::encode(n.hash)).collect(),
        root: hex::encode(root),
    }))
}

// ── GET /state-summary (F15) ──

#[derive(Serialize)]
struct StateSummaryResponse {
    state_root: String,
    commitment_root: String,
    epoch: u64,
    commitment_count: usize,
    nullifier_count: usize,
    total_minted: u64,
    active_validators: Vec<String>,
}

async fn get_state_summary(State(state): State<RpcState>) -> Json<StateSummaryResponse> {
    let node = state.node.read().await;
    let s = &node.ledger.state;
    let active_vals: Vec<String> = s
        .active_validators()
        .iter()
        .map(|v| hex::encode(v.id))
        .collect();
    Json(StateSummaryResponse {
        state_root: hex::encode(s.state_root()),
        commitment_root: hex::encode(s.commitment_root()),
        epoch: s.epoch(),
        commitment_count: s.commitment_count(),
        nullifier_count: s.nullifier_count(),
        total_minted: s.total_minted(),
        active_validators: active_vals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode as HttpStatus};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::consensus::bft::{BftState, Validator};
    use crate::network::p2p::P2pHandle;
    use crate::node::mempool::Mempool;
    use crate::node::storage::SledStorage;
    use crate::state::Ledger;

    fn test_rpc_state() -> RpcState {
        let storage = SledStorage::open_temporary().unwrap();
        let ledger = Ledger::new();
        let mempool = Mempool::with_defaults();
        let chain_id = *ledger.state.chain_id();
        let bft = BftState::new(0, vec![], chain_id);
        let node_state = Arc::new(RwLock::new(crate::node::NodeState {
            ledger,
            mempool,
            storage,
            bft,
            last_finalized_time: None,
            peer_highest_round: 0,
            node_start_time: std::time::Instant::now(),
            version_signals: std::collections::HashMap::new(),
        }));
        // Create a P2pHandle from a channel (we won't use it in most tests)
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let p2p = P2pHandle::from_sender(tx);
        RpcState::new(node_state, p2p)
    }

    async fn get_json(app: &axum::Router, path: &str) -> (HttpStatus, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_else(|e| {
            panic!(
                "JSON parse error: {} (status={}, body={:?})",
                e,
                status,
                String::from_utf8_lossy(&body)
            )
        });
        (status, json)
    }

    #[tokio::test]
    async fn get_state_returns_json() {
        let state = test_rpc_state();
        let app = router(state);
        let (status, json) = get_json(&app, "/state").await;
        assert_eq!(status, HttpStatus::OK);
        assert_eq!(json["epoch"], 0);
        assert_eq!(json["commitment_count"], 0);
        assert_eq!(json["nullifier_count"], 0);
    }

    #[tokio::test]
    async fn get_mempool_returns_stats() {
        let state = test_rpc_state();
        let app = router(state);
        let (status, json) = get_json(&app, "/mempool").await;
        assert_eq!(status, HttpStatus::OK);
        assert_eq!(json["transaction_count"], 0);
    }

    #[tokio::test]
    async fn get_validators_empty() {
        let state = test_rpc_state();
        let app = router(state);
        let (status, json) = get_json(&app, "/validators").await;
        assert_eq!(status, HttpStatus::OK);
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_validators_with_registered() {
        let state = test_rpc_state();
        // Register a validator
        {
            let mut node = state.node.write().await;
            let kp = crate::crypto::keys::SigningKeypair::generate();
            let v = Validator::new(kp.public);
            node.ledger.state.register_genesis_validator(v);
        }
        let app = router(state);
        let (status, json) = get_json(&app, "/validators").await;
        assert_eq!(status, HttpStatus::OK);
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["active"], true);
    }

    #[tokio::test]
    async fn get_validator_not_found() {
        let state = test_rpc_state();
        let app = router(state);
        let fake_id = hex::encode([0u8; 32]);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/validator/{}", fake_id))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HttpStatus::NOT_FOUND);
    }

    #[tokio::test]
    async fn submit_tx_invalid_hex() {
        let state = test_rpc_state();
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"tx_hex":"not_valid_hex!!!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HttpStatus::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_tx_not_found() {
        let state = test_rpc_state();
        let app = router(state);
        let fake_id = hex::encode([0u8; 32]);
        let (status, json) = get_json(&app, &format!("/tx/{}", fake_id)).await;
        assert_eq!(status, HttpStatus::OK);
        assert_eq!(json["found"], false);
        assert_eq!(json["source"], "none");
    }

    #[tokio::test]
    async fn get_finalized_vertices_empty() {
        let state = test_rpc_state();
        let app = router(state);
        let (status, json) = get_json(&app, "/vertices/finalized?after=0&limit=10").await;
        assert_eq!(status, HttpStatus::OK);
        assert!(json["vertices"].as_array().unwrap().is_empty());
        assert_eq!(json["has_more"], false);
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let state = test_rpc_state();
        let app = router(state);
        let (status, json) = get_json(&app, "/health").await;
        assert_eq!(status, HttpStatus::OK);
        assert_eq!(json["status"], "ok");
        assert!(json["uptime_seconds"].as_u64().is_some());
        assert_eq!(json["epoch"], 0);
    }

    #[tokio::test]
    async fn metrics_returns_text_plain() {
        let state = test_rpc_state();
        let app = router(state);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HttpStatus::OK);
        let ct = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/plain"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("umbra_uptime_seconds"));
        assert!(text.contains("umbra_epoch"));
    }

    #[tokio::test]
    async fn fee_estimate_default_params() {
        let state = test_rpc_state();
        let app = router(state);
        // Default: 1 input, 0 message bytes → fee = 100+100 = 200
        let (status, json) = get_json(&app, "/fee-estimate").await;
        assert_eq!(status, HttpStatus::OK);
        assert_eq!(json["fee"], 200);
        assert_eq!(json["base"], 100);
        assert_eq!(json["per_input"], 100);
        assert_eq!(json["per_message_kb"], 10);
    }

    #[tokio::test]
    async fn fee_estimate_custom_params() {
        let state = test_rpc_state();
        let app = router(state);
        // 2 inputs, 2048 message bytes → fee = 100+200+20 = 320
        let (status, json) = get_json(&app, "/fee-estimate?inputs=2&message_bytes=2048").await;
        assert_eq!(status, HttpStatus::OK);
        assert_eq!(json["fee"], 320);
    }

    #[tokio::test]
    async fn state_summary_returns_json() {
        let state = test_rpc_state();
        let app = router(state);
        let (status, json) = get_json(&app, "/state-summary").await;
        assert_eq!(status, HttpStatus::OK);
        assert_eq!(json["epoch"], 0);
        assert!(json["state_root"].as_str().is_some());
        assert!(json["active_validators"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn vertex_by_id_not_found() {
        let state = test_rpc_state();
        let app = router(state);
        let fake_id = hex::encode([0u8; 32]);
        let (status, json) = get_json(&app, &format!("/vertex/{}", fake_id)).await;
        assert_eq!(status, HttpStatus::OK);
        assert_eq!(json["found"], false);
    }

    #[tokio::test]
    async fn commitment_proof_out_of_range() {
        let state = test_rpc_state();
        let app = router(state);
        let mut request = Request::builder()
            .uri("/commitment-proof/0")
            .body(axum::body::Body::empty())
            .unwrap();
        // Inject ConnectInfo so the rate limiter extractor works in tests
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), HttpStatus::NOT_FOUND);
    }

    #[tokio::test]
    async fn submit_and_retrieve_tx() {
        let state = test_rpc_state();

        // Build a valid transaction
        let recipient = crate::crypto::keys::FullKeypair::generate();
        // 1 input, 1 output, no messages → deterministic fee = 200
        let tx = crate::transaction::builder::TransactionBuilder::new()
            .add_input(crate::transaction::builder::InputSpec {
                value: 1000,
                blinding: crate::crypto::commitment::BlindingFactor::random(),
                spend_auth: crate::hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 800)
            .set_proof_options(winterfell::ProofOptions::new(
                42,
                8,
                10,
                winterfell::FieldExtension::Cubic,
                8,
                255,
                winterfell::BatchingMethod::Linear,
                winterfell::BatchingMethod::Linear,
            ))
            .build()
            .unwrap();

        let tx_id = tx.tx_id();
        let tx_hex = hex::encode(crate::serialize(&tx).unwrap());

        // Submit
        let app = router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"tx_hex": tx_hex}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HttpStatus::OK);

        // Retrieve
        let app2 = router(state);
        let tx_id_hex = hex::encode(tx_id.0);
        let (status, json) = get_json(&app2, &format!("/tx/{}", tx_id_hex)).await;
        assert_eq!(status, HttpStatus::OK);
        assert_eq!(json["found"], true);
        assert_eq!(json["source"], "mempool");
    }

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

    /// Build a valid Transfer transaction with 1 input and 1 output.
    /// Deterministic fee = 200 (FEE_BASE + 1*FEE_PER_INPUT).
    fn make_valid_tx(seed: u8) -> crate::transaction::Transaction {
        let recipient = crate::crypto::keys::FullKeypair::generate();
        // 1 input, 1 output, no messages → fee = 200
        let output_value = 100u64;
        let input_value = output_value + 200; // 300
        crate::transaction::builder::TransactionBuilder::new()
            .add_input(crate::transaction::builder::InputSpec {
                value: input_value,
                blinding: crate::crypto::commitment::BlindingFactor::from_bytes([seed; 32]),
                spend_auth: crate::hash_domain(b"test", &[seed]),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), output_value)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap()
    }

    async fn post_tx_hex(app: &axum::Router, tx_hex: &str) -> (HttpStatus, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::json!({"tx_hex": tx_hex}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body).to_string();
        (status, text)
    }

    #[tokio::test]
    async fn submit_tx_oversized_payload() {
        let state = test_rpc_state();
        let app = router(state);

        // The router has a 2 MB body limit (DefaultBodyLimit::max(2 * 1024 * 1024)).
        // Send a payload larger than that limit to trigger rejection.
        // The JSON wrapper adds some overhead, so a hex string of ~2 MB will exceed 2 MB total.
        let oversized_hex = "aa".repeat(1024 * 1024 + 1); // ~1 MB of hex = ~0.5 MB decoded
        let large_json = serde_json::json!({"tx_hex": oversized_hex}).to_string();
        assert!(
            large_json.len() > 2 * 1024 * 1024,
            "payload must exceed body limit"
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(large_json))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Axum's DefaultBodyLimit returns 413 Payload Too Large
        assert_eq!(response.status(), HttpStatus::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn submit_tx_valid_hex_invalid_bincode() {
        let state = test_rpc_state();
        let app = router(state);

        // Valid hex that decodes to random bytes (not a valid serialized transaction)
        let garbage_hex = hex::encode([0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        let (status, body) = post_tx_hex(&app, &garbage_hex).await;
        assert_eq!(status, HttpStatus::BAD_REQUEST);
        assert!(
            body.contains("invalid transaction encoding"),
            "unexpected error body: {}",
            body
        );
    }

    #[tokio::test]
    async fn submit_tx_duplicate() {
        let state = test_rpc_state();

        let tx = make_valid_tx(200);
        let tx_hex = hex::encode(crate::serialize(&tx).unwrap());

        // First submission should succeed
        let app = router(state.clone());
        let (status1, _) = post_tx_hex(&app, &tx_hex).await;
        assert_eq!(status1, HttpStatus::OK);

        // Second submission of the same tx should fail as duplicate
        let app2 = router(state);
        let (status2, body2) = post_tx_hex(&app2, &tx_hex).await;
        assert_eq!(status2, HttpStatus::BAD_REQUEST);
        assert!(
            body2.contains("transaction rejected"),
            "unexpected error body: {}",
            body2
        );
    }

    #[tokio::test]
    async fn get_tx_invalid_hex_id() {
        let state = test_rpc_state();
        let app = router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/tx/not-valid-hex")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HttpStatus::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_tx_wrong_length_id() {
        let state = test_rpc_state();
        let app = router(state);

        // Valid hex but only 3 bytes — not 32 bytes
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/tx/aabbcc")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HttpStatus::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_peers_returns_json() {
        let state = test_rpc_state();
        let app = router(state);
        let (status, json) = get_json(&app, "/peers").await;
        assert_eq!(status, HttpStatus::OK);
        // Should be a JSON array (empty since no peers connected)
        assert!(json.is_array());
    }
}
