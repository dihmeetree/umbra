//! Node orchestrator tying together the ledger, mempool, storage, and P2P.
//!
//! The `Node` struct owns all subsystems and runs the main event loop,
//! dispatching incoming P2P messages and periodically proposing vertices.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::RwLock;

use crate::crypto::keys::SigningKeypair;
use crate::mempool::Mempool;
use crate::network::Message;
use crate::p2p::{P2pConfig, P2pEvent, P2pHandle};
use crate::state::Ledger;
use crate::storage::{SledStorage, Storage};
use crate::transaction::TxId;

/// Shared node state accessible from RPC handlers.
pub struct NodeState {
    pub ledger: Ledger,
    pub mempool: Mempool,
    pub storage: SledStorage,
}

/// The node orchestrator.
pub struct Node {
    state: Arc<RwLock<NodeState>>,
    p2p: P2pHandle,
    event_rx: mpsc::Receiver<P2pEvent>,
}

/// Node configuration.
#[derive(Clone)]
pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    pub bootstrap_peers: Vec<SocketAddr>,
    pub data_dir: PathBuf,
    pub rpc_addr: SocketAddr,
    pub keypair: SigningKeypair,
}

/// Node errors.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("P2P error: {0}")]
    P2p(#[from] crate::p2p::P2pError),
}

impl Node {
    /// Create and initialize a new node.
    pub async fn new(config: NodeConfig) -> Result<Self, NodeError> {
        // Open storage
        let storage = SledStorage::open(&config.data_dir)?;

        // Initialize ledger (future: restore from storage snapshot)
        let ledger = Ledger::new();

        // Create mempool
        let mempool = Mempool::with_defaults();

        // Start P2P
        let p2p_config = P2pConfig {
            listen_addr: config.listen_addr,
            max_peers: crate::constants::MAX_PEERS,
            our_peer_id: config.keypair.public.fingerprint(),
            our_public_key: config.keypair.public.clone(),
            listen_port: config.listen_addr.port(),
        };
        let p2p_result = crate::p2p::start(p2p_config).await?;
        let p2p = p2p_result.handle;
        let event_rx = p2p_result.events;

        // Connect to bootstrap peers
        for addr in &config.bootstrap_peers {
            let _ = p2p.connect(*addr).await;
        }

        let state = Arc::new(RwLock::new(NodeState {
            ledger,
            mempool,
            storage,
        }));

        Ok(Node {
            state,
            p2p,
            event_rx,
        })
    }

    /// Get a reference to the shared state (for RPC).
    pub fn state(&self) -> Arc<RwLock<NodeState>> {
        Arc::clone(&self.state)
    }

    /// Get a handle to the P2P layer (for RPC).
    pub fn p2p_handle(&self) -> P2pHandle {
        self.p2p.clone()
    }

    /// Run the main event loop.
    pub async fn run(&mut self) {
        let mut proposal_interval = tokio::time::interval(std::time::Duration::from_millis(
            crate::constants::VERTEX_PROPOSAL_INTERVAL_MS,
        ));

        loop {
            tokio::select! {
                Some(event) = self.event_rx.recv() => {
                    self.handle_p2p_event(event).await;
                }
                _ = proposal_interval.tick() => {
                    self.try_propose_vertex().await;
                }
            }
        }
    }

    async fn handle_p2p_event(&self, event: P2pEvent) {
        match event {
            P2pEvent::MessageReceived { from, message } => {
                self.handle_message(from, *message).await;
            }
            P2pEvent::PeerConnected(peer_id) => {
                tracing::info!("Peer connected: {}", hex::encode(&peer_id[..8]));
            }
            P2pEvent::PeerDisconnected(peer_id) => {
                tracing::info!("Peer disconnected: {}", hex::encode(&peer_id[..8]));
            }
        }
    }

    async fn handle_message(&self, from: crate::network::PeerId, message: Message) {
        match message {
            Message::NewTransaction(tx) => {
                let mut state = self.state.write().await;
                match state.mempool.insert(tx.clone()) {
                    Ok(_) => {
                        let _ = self
                            .p2p
                            .broadcast(Message::NewTransaction(tx), Some(from))
                            .await;
                    }
                    Err(e) => {
                        tracing::debug!("Rejected tx: {}", e);
                    }
                }
            }
            Message::NewVertex(vertex) => {
                let mut state = self.state.write().await;
                match state.ledger.apply_finalized_vertex(*vertex.clone()) {
                    Ok(_) => {
                        // Remove conflicting mempool txs
                        for tx in &vertex.transactions {
                            let nullifiers: Vec<_> =
                                tx.inputs.iter().map(|i| i.nullifier).collect();
                            state.mempool.remove_conflicting(&nullifiers);
                        }
                        // Persist vertex
                        let _ = state.storage.put_vertex(&vertex);
                        // Gossip
                        let _ = self
                            .p2p
                            .broadcast(Message::NewVertex(vertex), Some(from))
                            .await;
                    }
                    Err(e) => {
                        tracing::debug!("Rejected vertex: {}", e);
                    }
                }
            }
            Message::BftVote(vote) => {
                let _ = self.p2p.broadcast(Message::BftVote(vote), Some(from)).await;
            }
            Message::BftCertificate(cert) => {
                let _ = self
                    .p2p
                    .broadcast(Message::BftCertificate(cert), Some(from))
                    .await;
            }
            Message::GetTransaction(hash) => {
                let state = self.state.read().await;
                let tx_id = TxId(hash);
                let tx = state
                    .mempool
                    .get(&tx_id)
                    .cloned()
                    .or_else(|| state.storage.get_transaction(&tx_id).ok().flatten());
                let _ = self
                    .p2p
                    .send_to(from, Message::TransactionResponse(tx))
                    .await;
            }
            Message::GetPeers => {
                if let Ok(peers) = self.p2p.get_peers().await {
                    let _ = self.p2p.send_to(from, Message::PeersResponse(peers)).await;
                }
            }
            Message::PeersResponse(peers) => {
                for peer_info in peers {
                    if let Ok(addr) = peer_info.address.parse::<SocketAddr>() {
                        let _ = self.p2p.connect(addr).await;
                    }
                }
            }
            Message::GetVertex(vertex_id) => {
                let state = self.state.read().await;
                let vertex = state
                    .ledger
                    .dag
                    .get(&vertex_id)
                    .cloned()
                    .or_else(|| state.storage.get_vertex(&vertex_id).ok().flatten());
                let _ = self
                    .p2p
                    .send_to(from, Message::VertexResponse(vertex.map(Box::new)))
                    .await;
            }
            Message::GetTips => {
                let state = self.state.read().await;
                let tips: Vec<_> = state.ledger.dag.tips().iter().copied().collect();
                let _ = self.p2p.send_to(from, Message::TipsResponse(tips)).await;
            }
            Message::GetEpochState => {
                let state = self.state.read().await;
                let s = &state.ledger.state;
                let _ = self
                    .p2p
                    .send_to(
                        from,
                        Message::EpochStateResponse {
                            epoch: s.epoch(),
                            committee: vec![],
                            commitment_root: s.commitment_root(),
                            nullifier_count: s.nullifier_count() as u64,
                        },
                    )
                    .await;
            }
            // Response messages don't need forwarding
            Message::TransactionResponse(_)
            | Message::VertexResponse(_)
            | Message::TipsResponse(_)
            | Message::EpochStateResponse { .. }
            | Message::Hello { .. } => {}
        }
    }

    async fn try_propose_vertex(&self) {
        let state = self.state.read().await;
        if state.mempool.is_empty() {
            return;
        }
        // Vertex proposal is a placeholder — full implementation requires
        // committee membership check and signing
        tracing::trace!("Mempool has {} txs pending", state.mempool.len());
    }
}
