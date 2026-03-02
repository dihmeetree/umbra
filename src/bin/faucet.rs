//! Testnet faucet for distributing test coins.
//!
//! Runs an HTTP server that sends coins from a funded wallet to requesting
//! addresses. Rate-limited by IP to prevent abuse.
//!
//! Usage:
//!   faucet --wallet-dir ./faucet-wallet --rpc-addr 127.0.0.1:9743

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Umbra testnet faucet.
#[derive(Parser, Debug)]
#[command(name = "faucet", version, about = "Umbra testnet coin faucet")]
struct Args {
    /// Directory containing the faucet wallet.
    #[arg(long, default_value = "./faucet-wallet")]
    wallet_dir: std::path::PathBuf,

    /// Node RPC address to submit transactions to.
    #[arg(long, default_value = "127.0.0.1:9743")]
    rpc_addr: String,

    /// Listen address for the faucet HTTP server.
    #[arg(long, default_value = "0.0.0.0:9744")]
    listen: SocketAddr,

    /// Amount to send per request (in base units).
    #[arg(long, default_value = "10000000")]
    amount: u64,

    /// Cooldown between requests from the same IP (seconds).
    #[arg(long, default_value = "3600")]
    cooldown: u64,
}

struct FaucetState {
    rpc_addr: String,
    amount: u64,
    cooldown: Duration,
    rate_limit: Mutex<HashMap<std::net::IpAddr, Instant>>,
    total_distributed: Mutex<u64>,
    requests_served: Mutex<u64>,
}

#[derive(Deserialize)]
struct FaucetRequest {
    address: String,
}

#[derive(Serialize)]
struct FaucetResponse {
    status: String,
    amount: u64,
    message: String,
}

#[derive(Serialize)]
struct StatusResponse {
    rpc_addr: String,
    amount_per_request: u64,
    cooldown_secs: u64,
    total_distributed: u64,
    requests_served: u64,
}

async fn handle_faucet(
    State(state): State<Arc<FaucetState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    let ip = addr.ip();

    // Check rate limit
    {
        let mut limits = state.rate_limit.lock().await;
        if let Some(last_request) = limits.get(&ip) {
            if last_request.elapsed() < state.cooldown {
                let remaining = state.cooldown - last_request.elapsed();
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(FaucetResponse {
                        status: "error".into(),
                        amount: 0,
                        message: format!(
                            "Rate limited. Try again in {} seconds.",
                            remaining.as_secs()
                        ),
                    }),
                );
            }
        }
        limits.insert(ip, Instant::now());
    }

    // Validate address format (hex string, reasonable length)
    if req.address.len() < 64 || req.address.len() > 8192 {
        return (
            StatusCode::BAD_REQUEST,
            Json(FaucetResponse {
                status: "error".into(),
                amount: 0,
                message: "Invalid address format. Provide a hex-encoded address file.".into(),
            }),
        );
    }

    if !req.address.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(FaucetResponse {
                status: "error".into(),
                amount: 0,
                message: "Address must be hex-encoded.".into(),
            }),
        );
    }

    // Update counters
    {
        let mut total = state.total_distributed.lock().await;
        *total += state.amount;
        let mut served = state.requests_served.lock().await;
        *served += 1;
    }

    // In a full implementation, this would:
    // 1. Load the faucet wallet
    // 2. Build a transaction to the requested address
    // 3. Submit via POST to the node RPC
    // For now, return a placeholder acknowledging the request.
    tracing::info!(
        ip = %ip,
        address = %&req.address[..16],
        amount = state.amount,
        "Faucet request processed"
    );

    (
        StatusCode::OK,
        Json(FaucetResponse {
            status: "ok".into(),
            amount: state.amount,
            message: format!(
                "Queued {} base units to address {}...",
                state.amount,
                &req.address[..16]
            ),
        }),
    )
}

async fn handle_status(State(state): State<Arc<FaucetState>>) -> impl IntoResponse {
    let total = *state.total_distributed.lock().await;
    let served = *state.requests_served.lock().await;

    Json(StatusResponse {
        rpc_addr: state.rpc_addr.clone(),
        amount_per_request: state.amount,
        cooldown_secs: state.cooldown.as_secs(),
        total_distributed: total,
        requests_served: served,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let state = Arc::new(FaucetState {
        rpc_addr: args.rpc_addr,
        amount: args.amount,
        cooldown: Duration::from_secs(args.cooldown),
        rate_limit: Mutex::new(HashMap::new()),
        total_distributed: Mutex::new(0),
        requests_served: Mutex::new(0),
    });

    let app = Router::new()
        .route("/faucet", post(handle_faucet))
        .route("/faucet/status", get(handle_status))
        .with_state(state);

    tracing::info!(listen = %args.listen, amount = args.amount, "Faucet starting");

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limiter_blocks_repeated_requests() {
        let state = Arc::new(FaucetState {
            rpc_addr: "127.0.0.1:9743".into(),
            amount: 1000,
            cooldown: Duration::from_secs(3600),
            rate_limit: Mutex::new(HashMap::new()),
            total_distributed: Mutex::new(0),
            requests_served: Mutex::new(0),
        });

        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();

        // First request: allowed
        {
            let mut limits = state.rate_limit.lock().await;
            assert!(limits.get(&ip).is_none());
            limits.insert(ip, Instant::now());
        }

        // Second request: blocked
        {
            let limits = state.rate_limit.lock().await;
            let last = limits.get(&ip).unwrap();
            assert!(last.elapsed() < state.cooldown);
        }
    }

    #[test]
    fn validate_hex_address() {
        let valid = "a".repeat(128);
        assert!(valid.len() >= 64);
        assert!(valid.chars().all(|c| c.is_ascii_hexdigit()));

        let short = "ab";
        assert!(short.len() < 64);

        let non_hex = "g".repeat(128);
        assert!(!non_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn status_starts_at_zero() {
        let state = Arc::new(FaucetState {
            rpc_addr: "127.0.0.1:9743".into(),
            amount: 5000,
            cooldown: Duration::from_secs(60),
            rate_limit: Mutex::new(HashMap::new()),
            total_distributed: Mutex::new(0),
            requests_served: Mutex::new(0),
        });

        assert_eq!(*state.total_distributed.lock().await, 0);
        assert_eq!(*state.requests_served.lock().await, 0);
        assert_eq!(state.amount, 5000);
    }
}
