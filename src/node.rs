//! Node orchestrator tying together the ledger, mempool, storage, and P2P.
//!
//! The `Node` struct owns all subsystems and runs the main event loop,
//! dispatching incoming P2P messages and periodically proposing vertices.
//! When configured as a validator (`genesis_validator`), the node actively
//! participates in consensus: proposing vertices, casting BFT votes, and
//! managing epoch transitions.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::sync::RwLock;

use crate::consensus::bft::{self, BftState, Validator};
use crate::consensus::dag::{Vertex, VertexId};
use crate::crypto::keys::SigningKeypair;
use crate::crypto::vrf::VrfOutput;
use crate::mempool::Mempool;
use crate::network::Message;
use crate::p2p::{P2pConfig, P2pEvent, P2pHandle};
use crate::state::Ledger;
use crate::storage::{SledStorage, Storage};
use crate::transaction::TxId;
use crate::Hash;

/// Shared node state accessible from RPC handlers.
pub struct NodeState {
    pub ledger: Ledger,
    pub mempool: Mempool,
    pub storage: SledStorage,
    pub bft: BftState,
}

/// The node orchestrator.
pub struct Node {
    state: Arc<RwLock<NodeState>>,
    p2p: P2pHandle,
    event_rx: mpsc::Receiver<P2pEvent>,
    keypair: SigningKeypair,
    our_validator_id: Hash,
    our_vrf_output: Option<VrfOutput>,
}

/// Node configuration.
#[derive(Clone)]
pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    pub bootstrap_peers: Vec<SocketAddr>,
    pub data_dir: PathBuf,
    pub rpc_addr: SocketAddr,
    pub keypair: SigningKeypair,
    /// If true, register this node as a genesis validator.
    pub genesis_validator: bool,
}

/// Node errors.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("P2P error: {0}")]
    P2p(#[from] crate::p2p::P2pError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Load or generate a persistent validator keypair.
///
/// Reads from `data_dir/validator.key` if it exists; otherwise generates
/// a new keypair and writes it to that path.
pub fn load_or_generate_keypair(data_dir: &Path) -> Result<SigningKeypair, std::io::Error> {
    let key_path = data_dir.join("validator.key");

    if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        // Format: [pk_len: u32 LE] [pk_bytes] [sk_bytes]
        if bytes.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "key file too short",
            ));
        }
        let pk_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + pk_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "key file truncated",
            ));
        }
        let pk_bytes = bytes[4..4 + pk_len].to_vec();
        let sk_bytes = bytes[4 + pk_len..].to_vec();
        let keypair = SigningKeypair::from_bytes(pk_bytes, sk_bytes).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key data")
        })?;
        tracing::info!(
            "Loaded validator key: {}",
            hex::encode(&keypair.public.fingerprint()[..8])
        );
        Ok(keypair)
    } else {
        std::fs::create_dir_all(data_dir)?;
        let keypair = SigningKeypair::generate();
        let pk_len = (keypair.public.0.len() as u32).to_le_bytes();
        let mut bytes = Vec::with_capacity(4 + keypair.public.0.len() + keypair.secret.0.len());
        bytes.extend_from_slice(&pk_len);
        bytes.extend_from_slice(&keypair.public.0);
        bytes.extend_from_slice(&keypair.secret.0);
        std::fs::write(&key_path, &bytes)?;
        tracing::info!(
            "Generated validator key: {}",
            hex::encode(&keypair.public.fingerprint()[..8])
        );
        Ok(keypair)
    }
}

impl Node {
    /// Create and initialize a new node.
    pub async fn new(config: NodeConfig) -> Result<Self, NodeError> {
        // Open storage
        let storage = SledStorage::open(&config.data_dir)?;

        // Initialize ledger (future: restore from storage snapshot)
        let mut ledger = Ledger::new();

        // Create mempool
        let mempool = Mempool::with_defaults();

        let our_validator_id = config.keypair.public.fingerprint();

        // Initialize BFT state
        let chain_id = *ledger.state.chain_id();
        let mut bft = BftState::new(0, vec![], chain_id);
        bft.set_our_keypair(config.keypair.clone());

        // Genesis validator bootstrap
        let mut our_vrf_output = None;
        if config.genesis_validator {
            let validator = Validator::new(config.keypair.public.clone());
            ledger.state.register_genesis_validator(validator);

            // Evaluate VRF for epoch 0
            let epoch_seed = ledger.state.epoch_seed().clone();
            let vrf_input = epoch_seed.vrf_input(&our_validator_id);
            let vrf = VrfOutput::evaluate(&config.keypair, &vrf_input);

            let total_validators = ledger.state.total_validators();
            if vrf.is_selected(crate::constants::COMMITTEE_SIZE, total_validators) {
                tracing::info!("Selected for epoch 0 committee via VRF");
                our_vrf_output = Some(vrf.clone());
                bft.set_our_vrf_proof(vrf);
            } else {
                tracing::info!("Not selected for epoch 0 committee");
            }

            // Persist validator to storage
            storage
                .put_validator(
                    &Validator::new(config.keypair.public.clone()),
                    crate::constants::VALIDATOR_BOND,
                )
                .unwrap_or_else(|e| tracing::warn!("Failed to persist validator: {}", e));

            tracing::info!(
                "Registered as genesis validator: {}",
                hex::encode(&our_validator_id[..8])
            );
        }

        // Start P2P
        let p2p_config = P2pConfig {
            listen_addr: config.listen_addr,
            max_peers: crate::constants::MAX_PEERS,
            our_peer_id: our_validator_id,
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
            bft,
        }));

        Ok(Node {
            state,
            p2p,
            event_rx,
            keypair: config.keypair,
            our_validator_id,
            our_vrf_output,
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

                // Insert into DAG (but don't finalize yet — wait for BFT)
                match state.ledger.insert_vertex(*vertex.clone()) {
                    Ok(_) => {
                        // If we're on committee, vote Accept
                        if let Some(vrf) = &self.our_vrf_output {
                            let vote = bft::create_vote(
                                vertex.id,
                                &self.keypair,
                                vertex.epoch,
                                vertex.round,
                                true,
                                state.ledger.state.chain_id(),
                                Some(vrf.clone()),
                            );
                            // Process vote locally
                            if let Some(cert) = state.bft.receive_vote(vote.clone()) {
                                // Quorum reached — finalize
                                self.finalize_vertex_inner(&mut state, &cert.vertex_id)
                                    .await;
                                let _ = self
                                    .p2p
                                    .broadcast(Message::BftCertificate(cert), None)
                                    .await;
                            }
                            let _ = self.p2p.broadcast(Message::BftVote(vote), Some(from)).await;
                        }

                        // Gossip vertex
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
                let mut state = self.state.write().await;
                if let Some(cert) = state.bft.receive_vote(vote.clone()) {
                    // Quorum reached — finalize
                    self.finalize_vertex_inner(&mut state, &cert.vertex_id)
                        .await;
                    let _ = self
                        .p2p
                        .broadcast(Message::BftCertificate(cert), None)
                        .await;
                }
                let _ = self.p2p.broadcast(Message::BftVote(vote), Some(from)).await;
            }
            Message::BftCertificate(cert) => {
                let mut state = self.state.write().await;
                self.finalize_vertex_inner(&mut state, &cert.vertex_id)
                    .await;
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
                let validators: Vec<Hash> = s.active_validators().iter().map(|v| v.id).collect();
                let _ = self
                    .p2p
                    .send_to(
                        from,
                        Message::EpochStateResponse {
                            epoch: s.epoch(),
                            committee: validators,
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

    /// Finalize a vertex and apply its transactions to state.
    async fn finalize_vertex_inner(&self, state: &mut NodeState, vertex_id: &VertexId) {
        if state.ledger.dag.is_finalized(vertex_id) {
            return; // Already finalized
        }

        // Get vertex transactions for mempool cleanup before finalization
        let nullifiers: Vec<_> = state
            .ledger
            .dag
            .get(vertex_id)
            .map(|v| {
                v.transactions
                    .iter()
                    .flat_map(|tx| tx.inputs.iter().map(|i| i.nullifier))
                    .collect()
            })
            .unwrap_or_default();

        match state.ledger.finalize_vertex(vertex_id) {
            Ok(_) => {
                // Remove conflicting mempool txs
                state.mempool.remove_conflicting(&nullifiers);

                // Persist vertex
                if let Some(v) = state.ledger.dag.get(vertex_id) {
                    let _ = state.storage.put_vertex(v);
                }

                // Check for equivocation evidence and slash
                for evidence in state.bft.equivocations() {
                    let _ = state.ledger.state.slash_validator(&evidence.voter_id);
                    tracing::warn!(
                        "Slashed validator {} for equivocation in round {}",
                        hex::encode(&evidence.voter_id[..8]),
                        evidence.round
                    );
                }

                // Advance BFT round
                state.bft.advance_round();
                state.ledger.dag.advance_round();

                tracing::info!("Finalized vertex {}", hex::encode(&vertex_id.0[..8]));
            }
            Err(e) => {
                tracing::debug!("Failed to finalize vertex: {}", e);
            }
        }
    }

    /// Try to propose a new vertex if we're on the committee.
    async fn try_propose_vertex(&self) {
        let vrf = match &self.our_vrf_output {
            Some(vrf) => vrf.clone(),
            None => return, // Not on committee
        };

        let mut state = self.state.write().await;

        // Only propose if mempool has transactions
        if state.mempool.is_empty() {
            return;
        }

        // Drain transactions from mempool
        let transactions = state
            .mempool
            .drain_highest_fee(crate::constants::VERTEX_MAX_DRAIN);
        if transactions.is_empty() {
            return;
        }

        let epoch = state.ledger.state.epoch();
        let round = state.bft.round + 1;

        // Collect current tips as parents
        let parents: Vec<VertexId> = state
            .ledger
            .dag
            .tips()
            .iter()
            .copied()
            .take(crate::constants::MAX_PARENTS)
            .collect();

        if parents.is_empty() {
            return;
        }

        let state_root = state.ledger.state.state_root();
        let proposer_fingerprint = self.our_validator_id;

        // Build and sign vertex
        let mut vertex = Vertex {
            id: VertexId([0u8; 32]), // Placeholder, will compute
            parents: parents.clone(),
            epoch,
            round,
            proposer: self.keypair.public.clone(),
            transactions,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            state_root,
            signature: crate::crypto::keys::Signature(vec![]),
            vrf_proof: Some(vrf.clone()),
        };

        // Compute vertex ID
        let tx_root = vertex.tx_root();
        vertex.id = Vertex::compute_id(
            &vertex.parents,
            epoch,
            round,
            &proposer_fingerprint,
            &tx_root,
            Some(&vrf.value),
        );

        // Sign vertex
        vertex.signature = self.keypair.sign(&vertex.id.0);

        let vertex_id = vertex.id;
        tracing::info!(
            "Proposing vertex {} with {} txs",
            hex::encode(&vertex_id.0[..8]),
            vertex.transactions.len()
        );

        // Insert into local DAG
        match state.ledger.insert_vertex(vertex.clone()) {
            Ok(_) => {
                // Vote Accept on our own vertex
                let vote = bft::create_vote(
                    vertex_id,
                    &self.keypair,
                    epoch,
                    round,
                    true,
                    state.ledger.state.chain_id(),
                    Some(vrf),
                );
                if let Some(cert) = state.bft.receive_vote(vote.clone()) {
                    self.finalize_vertex_inner(&mut state, &cert.vertex_id)
                        .await;
                    let _ = self
                        .p2p
                        .broadcast(Message::BftCertificate(cert), None)
                        .await;
                }

                // Broadcast vertex + vote
                let _ = self
                    .p2p
                    .broadcast(Message::NewVertex(Box::new(vertex)), None)
                    .await;
                let _ = self.p2p.broadcast(Message::BftVote(vote), None).await;
            }
            Err(e) => {
                tracing::warn!("Failed to insert own vertex: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let kp1 = load_or_generate_keypair(dir.path()).unwrap();
        let kp2 = load_or_generate_keypair(dir.path()).unwrap();
        // Should load the same key
        assert_eq!(kp1.public.fingerprint(), kp2.public.fingerprint());
    }
}
