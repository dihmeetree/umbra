use std::{collections::HashMap, env, sync::Arc};

use statera_notary::{run_notary, NotaryConfig};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Session state for correlating MPC and attestation connections
struct SessionState {
    /// Pending sessions waiting for both connections
    pending: HashMap<u64, PendingSession>,
    /// Next session ID to assign
    next_id: u64,
}

enum PendingSession {
    WaitingForAttestation(tokio::net::TcpStream),
    WaitingForMpc(tokio::net::TcpStream),
}

#[tokio::main]
async fn main() {
    // Load .env file if present
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(7047);

    let config = NotaryConfig::from_env().expect("Failed to load notary config");

    let addr = format!("{host}:{port}");
    tracing::info!("Notary service listening on {addr}");
    tracing::info!("Protocol: clients send 1 byte (0=MPC, 1=attestation) + 8-byte session ID");

    let listener = TcpListener::bind(&addr).await.unwrap();
    let sessions = Arc::new(Mutex::new(SessionState {
        pending: HashMap::new(),
        next_id: 1,
    }));

    loop {
        let (mut socket, peer_addr) = listener.accept().await.unwrap();
        tracing::info!("Accepted connection from {peer_addr}");

        let config = config.clone();
        let sessions = sessions.clone();

        tokio::spawn(async move {
            // Read connection type (1 byte): 0 = MPC socket, 1 = attestation socket
            let conn_type = match socket.read_u8().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("Failed to read connection type from {peer_addr}: {e}");
                    return;
                }
            };

            // Read session ID (8 bytes, big-endian)
            // If session ID is 0, this is a new session and we'll assign an ID
            let session_id = match socket.read_u64().await {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("Failed to read session ID from {peer_addr}: {e}");
                    return;
                }
            };

            match conn_type {
                0 => {
                    // MPC connection
                    let mut state = sessions.lock().await;

                    if session_id == 0 {
                        // New session - assign ID and wait for attestation connection
                        let new_id = state.next_id;
                        state.next_id += 1;

                        // Send assigned session ID back to client
                        if let Err(e) = socket.write_u64(new_id).await {
                            tracing::error!("Failed to send session ID to {peer_addr}: {e}");
                            return;
                        }

                        tracing::info!("New session {new_id} from {peer_addr}, waiting for attestation connection");
                        state.pending.insert(new_id, PendingSession::WaitingForAttestation(socket));
                    } else {
                        // Existing session - check if attestation connection is waiting
                        if let Some(PendingSession::WaitingForMpc(attestation_socket)) = state.pending.remove(&session_id) {
                            drop(state);

                            // Send session ID confirmation
                            if let Err(e) = socket.write_u64(session_id).await {
                                tracing::error!("Failed to send session ID to {peer_addr}: {e}");
                                return;
                            }

                            tracing::info!("Session {session_id} complete, starting notary");
                            if let Err(e) = run_notary(socket, attestation_socket, config).await {
                                tracing::error!("Notary error for session {session_id}: {e}");
                            }
                        } else {
                            tracing::error!("Session {session_id} not found or wrong state for MPC connection");
                        }
                    }
                }
                1 => {
                    // Attestation connection
                    let mut state = sessions.lock().await;

                    if session_id == 0 {
                        tracing::error!("Attestation connection must have a session ID");
                        return;
                    }

                    // Check if MPC connection is waiting
                    if let Some(PendingSession::WaitingForAttestation(mpc_socket)) = state.pending.remove(&session_id) {
                        drop(state);

                        tracing::info!("Session {session_id} complete, starting notary");
                        if let Err(e) = run_notary(mpc_socket, socket, config).await {
                            tracing::error!("Notary error for session {session_id}: {e}");
                        }
                    } else {
                        // MPC not yet connected, wait for it
                        tracing::info!("Session {session_id} attestation connection waiting for MPC");
                        state.pending.insert(session_id, PendingSession::WaitingForMpc(socket));
                    }
                }
                _ => {
                    tracing::error!("Invalid connection type {conn_type} from {peer_addr}");
                }
            }
        });
    }
}
