//! JSON HTTP RPC API for the Spectra node.
//!
//! Provides endpoints for submitting transactions, querying state,
//! and inspecting the mempool and peer list.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::node::NodeState;
use crate::p2p::P2pHandle;
use crate::storage::Storage;
use crate::transaction::TxId;

/// Shared RPC state.
#[derive(Clone)]
pub struct RpcState {
    pub node: Arc<RwLock<NodeState>>,
    pub p2p: P2pHandle,
}

/// Build the RPC router.
pub fn router(rpc_state: RpcState) -> Router {
    Router::new()
        .route("/tx", post(submit_tx))
        .route("/tx/{id}", get(get_tx))
        .route("/state", get(get_state))
        .route("/peers", get(get_peers))
        .route("/mempool", get(get_mempool))
        .with_state(rpc_state)
}

/// Start the RPC server.
pub async fn serve(
    addr: SocketAddr,
    rpc_state: RpcState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = router(rpc_state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("RPC server listening on {}", addr);
    axum::serve(listener, app).await?;
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
    let tx_bytes = hex::decode(&req.tx_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid hex: {}", e)))?;
    let tx: crate::transaction::Transaction = bincode::deserialize(&tx_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid transaction: {}", e),
        )
    })?;

    let tx_id = tx.tx_id();
    let mut node = state.node.write().await;
    node.mempool
        .insert(tx.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("rejected: {}", e)))?;

    // Broadcast to network
    drop(node); // Release write lock before async send
    let _ = state
        .p2p
        .broadcast(crate::network::Message::NewTransaction(tx), None)
        .await;

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
        let tx_hex = hex::encode(bincode::serialize(tx).unwrap_or_default());
        return Ok(Json(GetTxResponse {
            found: true,
            tx_hex: Some(tx_hex),
            source: "mempool".into(),
        }));
    }

    // Then storage
    if let Ok(Some(tx)) = node.storage.get_transaction(&tx_id) {
        let tx_hex = hex::encode(bincode::serialize(&tx).unwrap_or_default());
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
    })
}

// ── GET /peers ──

#[derive(Serialize)]
struct PeerInfoResponse {
    peer_id: String,
    address: String,
    last_seen: u64,
}

async fn get_peers(State(state): State<RpcState>) -> Json<Vec<PeerInfoResponse>> {
    let peers = state.p2p.get_peers().await.unwrap_or_default();
    let response: Vec<PeerInfoResponse> = peers
        .into_iter()
        .map(|p| PeerInfoResponse {
            peer_id: hex::encode(p.peer_id),
            address: p.address,
            last_seen: p.last_seen,
        })
        .collect();
    Json(response)
}

// ── GET /mempool ──

async fn get_mempool(State(state): State<RpcState>) -> Json<crate::mempool::MempoolStats> {
    let node = state.node.read().await;
    Json(node.mempool.stats())
}
