//! RPC API integration tests with populated state.
//!
//! Tests all 13 RPC endpoints with realistic state: registered validators,
//! funded wallets, commitments, nullifiers, and finalized vertices.
//! Complements the basic unit tests in src/node/rpc.rs.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode as HttpStatus};
use http_body_util::BodyExt;
use tokio::sync::RwLock;
use tower::ServiceExt;

use umbra::consensus::bft::{BftState, Validator};
use umbra::constants;
use umbra::crypto::commitment::{BlindingFactor, Commitment};
use umbra::crypto::keys::{KemKeypair, SigningKeypair};
use umbra::crypto::nullifier::Nullifier;
use umbra::hash_domain;
use umbra::node::mempool::Mempool;
use umbra::node::rpc::{router, RpcState};
use umbra::node::storage::SledStorage;
use umbra::node::NodeState;
use umbra::state::Ledger;

// ── Helpers ──────────────────────────────────────────────────────────────

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

/// Create an RpcState with a genesis validator and commitment in state.
fn populated_rpc_state() -> RpcState {
    let storage = SledStorage::open_temporary().unwrap();
    let mut ledger = Ledger::new();

    // Register a genesis validator
    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let validator = Validator::with_kem(signing.public.clone(), kem.public.clone());
    ledger.state.register_genesis_validator(validator).unwrap();

    // Add a commitment
    let blinding = BlindingFactor::from_bytes([1u8; 32]);
    let commitment = Commitment::commit(1000, &blinding);
    ledger.state.add_commitment(commitment).unwrap();

    // Add a nullifier
    let nullifier = Nullifier(hash_domain(b"test.null", &[1]));
    ledger.state.mark_nullifier(nullifier).unwrap();

    let chain_id = *ledger.state.chain_id();
    let bft = BftState::new(0, vec![], chain_id);
    let node_state = Arc::new(RwLock::new(NodeState {
        ledger,
        mempool: Mempool::with_defaults(),
        storage,
        bft,
        last_finalized_time: None,
        peer_highest_round: 0,
        node_start_time: Instant::now(),
        version_signals: HashMap::new(),
        network: constants::NetworkId::Mainnet,
        pending_stem_fluffs: Vec::new(),
    }));
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let p2p = umbra::network::p2p::P2pHandle::from_sender(tx);
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
            "JSON parse error: {} (body={:?})",
            e,
            String::from_utf8_lossy(&body)
        )
    });
    (status, json)
}

async fn get_text(app: &axum::Router, path: &str) -> (HttpStatus, String) {
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
    (status, String::from_utf8_lossy(&body).to_string())
}

// ── Group A: Fast tests (no STARK proofs) ────────────────────────────────

#[tokio::test]
async fn test_health_endpoint() {
    let state = populated_rpc_state();
    let app = router(state);
    let (status, json) = get_json(&app, "/health").await;
    assert_eq!(status, HttpStatus::OK);
    assert_eq!(json["status"], "ok");
    assert!(json["version"].is_string());
    assert!(json["uptime_seconds"].is_number());
    assert!(json["epoch"].is_number());
    assert!(json["finalized_count"].is_number());
}

#[tokio::test]
async fn test_state_endpoint_populated() {
    let state = populated_rpc_state();
    let app = router(state);
    let (status, json) = get_json(&app, "/state").await;
    assert_eq!(status, HttpStatus::OK);
    assert!(
        json["commitment_count"].as_u64().unwrap() > 0,
        "should have commitments"
    );
    assert!(
        json["nullifier_count"].as_u64().unwrap() > 0,
        "should have nullifiers"
    );
    assert!(json["state_root"].is_string());
    assert!(json["commitment_root"].is_string());
}

#[tokio::test]
async fn test_state_summary_endpoint() {
    let state = populated_rpc_state();
    let app = router(state);
    let (status, json) = get_json(&app, "/state-summary").await;
    assert_eq!(status, HttpStatus::OK);
    assert!(json["state_root"].is_string());
    let validators = json["active_validators"].as_array().unwrap();
    assert!(
        !validators.is_empty(),
        "should have active validators in summary"
    );
}

#[tokio::test]
async fn test_peers_endpoint() {
    let state = populated_rpc_state();
    let app = router(state);
    let (status, json) = get_json(&app, "/peers").await;
    assert_eq!(status, HttpStatus::OK);
    assert!(json.as_array().unwrap().is_empty(), "no P2P in test");
}

#[tokio::test]
async fn test_mempool_endpoint_with_tx() {
    let state = populated_rpc_state();

    // Insert a tx into mempool
    {
        let mut node = state.node.write().await;
        let recipient = umbra::crypto::keys::FullKeypair::generate();
        let tx = umbra::transaction::builder::TransactionBuilder::new()
            .add_input(umbra::transaction::builder::InputSpec {
                value: 1000,
                blinding: BlindingFactor::random(),
                spend_auth: hash_domain(b"test", b"auth"),
                merkle_path: vec![],
            })
            .add_output(recipient.kem.public.clone(), 800)
            .set_proof_options(test_proof_options())
            .build()
            .unwrap();
        node.submit_transaction(tx).unwrap();
    }

    let app = router(state);
    let (status, json) = get_json(&app, "/mempool").await;
    assert_eq!(status, HttpStatus::OK);
    assert_eq!(json["transaction_count"], 1);
    assert!(json["total_bytes"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_validators_endpoint() {
    let state = populated_rpc_state();
    let app = router(state);
    let (status, json) = get_json(&app, "/validators").await;
    assert_eq!(status, HttpStatus::OK);
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["active"], true);
    assert!(arr[0]["bond"].is_number());
}

#[tokio::test]
async fn test_validator_by_id_found_and_not_found() {
    let state = populated_rpc_state();

    // Get the validator ID
    let val_id = {
        let node = state.node.read().await;
        let validators = node.ledger.state.active_validators();
        hex::encode(validators[0].id)
    };

    let app = router(state.clone());
    let (status, json) = get_json(&app, &format!("/validator/{}", val_id)).await;
    assert_eq!(status, HttpStatus::OK);
    assert_eq!(json["active"], true);

    // Not found
    let app2 = router(state);
    let fake_id = hex::encode([0u8; 32]);
    let response = app2
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
async fn test_fee_estimate_endpoint() {
    let state = populated_rpc_state();
    let app = router(state);
    let (status, json) = get_json(&app, "/fee-estimate?inputs=2&message_bytes=100").await;
    assert_eq!(status, HttpStatus::OK);
    assert!(json["fee"].as_u64().unwrap() > 0);
    assert!(json["base"].is_number());
    assert!(json["per_input"].is_number());
}

#[tokio::test]
async fn test_metrics_endpoint() {
    let state = populated_rpc_state();
    let app = router(state);
    let (status, text) = get_text(&app, "/metrics").await;
    assert_eq!(status, HttpStatus::OK);
    assert!(text.contains("umbra_"), "should contain Prometheus metrics");
}

#[tokio::test]
async fn test_commitment_proof_valid() {
    let state = populated_rpc_state();
    let app = router(state);
    let mut request = Request::builder()
        .uri("/commitment-proof/0")
        .body(axum::body::Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), HttpStatus::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["index"], 0);
    assert!(json["commitment"].is_string());
    assert!(json["merkle_path"].is_array());
    assert!(json["root"].is_string());
}

#[tokio::test]
async fn test_commitment_proof_rate_limit() {
    let state = populated_rpc_state();

    // Send 61 requests — the 61st should be rate-limited
    for i in 0..61 {
        let app = router(state.clone());
        let mut request = Request::builder()
            .uri("/commitment-proof/0")
            .body(axum::body::Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
        let response = app.oneshot(request).await.unwrap();

        if i < 60 {
            assert_eq!(
                response.status(),
                HttpStatus::OK,
                "request {} should succeed",
                i
            );
        } else {
            assert_eq!(
                response.status(),
                HttpStatus::TOO_MANY_REQUESTS,
                "request {} should be rate-limited",
                i
            );
        }
    }
}

// ── Group B: Medium tests (1 STARK proof) ────────────────────────────────

#[tokio::test]
async fn test_submit_tx_and_retrieve() {
    let state = populated_rpc_state();

    let recipient = umbra::crypto::keys::FullKeypair::generate();
    let tx = umbra::transaction::builder::TransactionBuilder::new()
        .add_input(umbra::transaction::builder::InputSpec {
            value: 1000,
            blinding: BlindingFactor::random(),
            spend_auth: hash_domain(b"test", b"auth"),
            merkle_path: vec![],
        })
        .add_output(recipient.kem.public.clone(), 800)
        .set_proof_options(test_proof_options())
        .build()
        .unwrap();

    let tx_id = tx.tx_id();
    let tx_hex = hex::encode(umbra::serialize(&tx).unwrap());

    // Submit
    let app = router(state.clone());
    let mut request = Request::builder()
        .method("POST")
        .uri("/tx")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({"tx_hex": tx_hex}).to_string(),
        ))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), HttpStatus::OK);

    // Retrieve
    let app2 = router(state);
    let tx_id_hex = hex::encode(tx_id.0);
    let (status, json) = get_json(&app2, &format!("/tx/{}", tx_id_hex)).await;
    assert_eq!(status, HttpStatus::OK);
    assert_eq!(json["found"], true);
    assert_eq!(json["source"], "mempool");
}

#[tokio::test]
async fn test_submit_invalid_tx() {
    let state = populated_rpc_state();
    let app = router(state);
    let mut request = Request::builder()
        .method("POST")
        .uri("/tx")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(r#"{"tx_hex":"not_valid_hex!!!"}"#))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), HttpStatus::BAD_REQUEST);
}
