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
use crate::crypto::stark::spend_air::MERKLE_DEPTH;
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

/// Sync progress tracking for catching up with the network.
enum SyncState {
    /// Haven't started sync yet — waiting for a peer to query.
    NeedSync { our_finalized: u64 },
    /// Actively syncing vertices from a peer.
    Syncing {
        peer: crate::network::PeerId,
        next_seq: u64,
        #[allow(dead_code)]
        target: u64,
    },
    /// Fully synced with the network.
    Synced,
}

/// The node orchestrator.
pub struct Node {
    state: Arc<RwLock<NodeState>>,
    p2p: P2pHandle,
    event_rx: mpsc::Receiver<P2pEvent>,
    keypair: SigningKeypair,
    our_validator_id: Hash,
    our_vrf_output: Option<VrfOutput>,
    sync_state: SyncState,
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
        // H4: Restrict key file permissions to owner-only
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
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

        // Restore ledger from storage if a snapshot exists, otherwise start fresh
        let mut ledger = match storage.get_chain_state_meta() {
            Ok(Some(meta)) => match Ledger::restore_from_storage(&storage, &meta) {
                Ok(l) => {
                    tracing::info!(
                        "Restored state from storage: epoch={}, commitments={}, nullifiers={}, finalized={}",
                        meta.epoch,
                        meta.commitment_count,
                        meta.nullifier_count,
                        meta.finalized_count,
                    );
                    l
                }
                Err(e) => {
                    tracing::warn!("Failed to restore state, starting fresh: {}", e);
                    Ledger::new()
                }
            },
            _ => Ledger::new(),
        };

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
            // H1: Set epoch context for VRF verification on incoming votes
            bft.set_epoch_context(epoch_seed, total_validators);

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

        // Record our finalized count before storage is moved into NodeState
        let our_finalized = storage.finalized_vertex_count().unwrap_or(0);

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

        let sync_state = SyncState::NeedSync { our_finalized };

        Ok(Node {
            state,
            p2p,
            event_rx,
            keypair: config.keypair,
            our_validator_id,
            our_vrf_output,
            sync_state,
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

    async fn handle_p2p_event(&mut self, event: P2pEvent) {
        match event {
            P2pEvent::MessageReceived { from, message } => {
                self.handle_message(from, *message).await;
            }
            P2pEvent::PeerConnected(peer_id) => {
                tracing::info!("Peer connected: {}", hex::encode(&peer_id[..8]));
                // If we need sync, ask this peer about their state
                if let SyncState::NeedSync { .. } = &self.sync_state {
                    let _ = self.p2p.send_to(peer_id, Message::GetEpochState).await;
                }
            }
            P2pEvent::PeerDisconnected(peer_id) => {
                tracing::info!("Peer disconnected: {}", hex::encode(&peer_id[..8]));
                // If we were syncing from this peer, revert to NeedSync
                if let SyncState::Syncing { peer, next_seq, .. } = &self.sync_state {
                    if *peer == peer_id {
                        tracing::warn!("Sync peer disconnected, will retry with next peer");
                        self.sync_state = SyncState::NeedSync {
                            our_finalized: *next_seq,
                        };
                    }
                }
            }
        }
    }

    async fn handle_message(&mut self, from: crate::network::PeerId, message: Message) {
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

                // C3: Validate VRF proof before accepting the vertex.
                // Genesis vertex (round=0) has no VRF proof.
                if vertex.round > 0 {
                    let epoch_seed = state.ledger.state.epoch_seed().clone();
                    let total_validators = state.ledger.state.total_validators();
                    if let Err(e) = vertex.validate_vrf(&epoch_seed, total_validators) {
                        tracing::debug!("Rejected vertex (invalid VRF): {}", e);
                        return;
                    }
                }

                // C2: Validate all transactions structurally before inserting.
                let current_epoch = state.ledger.state.epoch();
                for tx in &vertex.transactions {
                    if let Err(e) = tx.validate_structure(current_epoch) {
                        tracing::debug!("Rejected vertex (invalid tx): {}", e);
                        return;
                    }
                }

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
                // H5: Only re-broadcast if the vote was accepted
                if let Some(cert) = state.bft.receive_vote(vote.clone()) {
                    // Quorum reached — finalize
                    self.finalize_vertex_inner(&mut state, &cert.vertex_id)
                        .await;
                    let _ = self
                        .p2p
                        .broadcast(Message::BftCertificate(cert), None)
                        .await;
                    // Broadcast the vote that completed the certificate
                    let _ = self.p2p.broadcast(Message::BftVote(vote), Some(from)).await;
                } else if state.bft.is_vote_accepted(&vote) {
                    // Vote was accepted (not rejected) — forward to peers
                    let _ = self.p2p.broadcast(Message::BftVote(vote), Some(from)).await;
                }
            }
            Message::BftCertificate(cert) => {
                let mut state = self.state.write().await;
                // C1: Verify certificate before finalizing
                let committee = state.bft.committee.clone();
                let chain_id = state.bft.chain_id;
                if !cert.verify(&committee, &chain_id) {
                    tracing::debug!("Rejected invalid BFT certificate");
                    return;
                }
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
                // L12: Limit how many peers we connect to from a single response
                // to prevent amplification attacks.
                for peer_info in peers.iter().take(crate::constants::MAX_PEERS) {
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
            Message::GetFinalizedVertices {
                after_sequence,
                limit,
            } => {
                let state = self.state.read().await;
                let capped_limit = limit.min(crate::constants::SYNC_BATCH_SIZE);
                let total_finalized = state.storage.finalized_vertex_count().unwrap_or(0);
                match state
                    .storage
                    .get_finalized_vertices_after(after_sequence, capped_limit)
                {
                    Ok(vertices) => {
                        let has_more = vertices.len() == capped_limit as usize;
                        let boxed: Vec<(u64, Box<Vertex>)> = vertices
                            .into_iter()
                            .map(|(seq, v)| (seq, Box::new(v)))
                            .collect();
                        let _ = self
                            .p2p
                            .send_to(
                                from,
                                Message::FinalizedVerticesResponse {
                                    vertices: boxed,
                                    has_more,
                                    total_finalized,
                                },
                            )
                            .await;
                    }
                    Err(e) => {
                        tracing::debug!("Failed to serve sync request: {}", e);
                    }
                }
            }

            Message::EpochStateResponse {
                nullifier_count, ..
            } => {
                // Check if we need to sync from this peer
                if let SyncState::NeedSync { our_finalized } = self.sync_state {
                    let state = self.state.read().await;
                    let our_nullifiers = state.ledger.state.nullifier_count() as u64;
                    drop(state);

                    // Use nullifier count as a rough proxy for how far ahead the peer is
                    if nullifier_count > our_nullifiers || our_finalized == 0 {
                        tracing::info!(
                            "Starting sync from peer {} (our finalized: {}, peer nullifiers: {})",
                            hex::encode(&from[..8]),
                            our_finalized,
                            nullifier_count,
                        );
                        // Start requesting finalized vertices
                        let start_after = if our_finalized > 0 {
                            our_finalized - 1
                        } else {
                            u64::MAX // will be wrapped to 0 by the range query
                        };
                        self.sync_state = SyncState::Syncing {
                            peer: from,
                            next_seq: start_after,
                            target: 0, // unknown until first response
                        };
                        let _ = self
                            .p2p
                            .send_to(
                                from,
                                Message::GetFinalizedVertices {
                                    after_sequence: start_after,
                                    limit: crate::constants::SYNC_BATCH_SIZE,
                                },
                            )
                            .await;
                    } else {
                        tracing::info!("Already synced with network");
                        self.sync_state = SyncState::Synced;
                    }
                }
            }
            Message::FinalizedVerticesResponse {
                vertices,
                has_more,
                total_finalized,
            } => {
                if let SyncState::Syncing { peer, .. } = &self.sync_state {
                    if from != *peer {
                        return; // Ignore responses from unexpected peers
                    }

                    let batch_len = vertices.len();
                    let mut last_seq = 0u64;
                    let mut applied = 0usize;

                    for (seq, vertex) in vertices {
                        last_seq = seq;
                        let mut state = self.state.write().await;

                        // Record commitment count for incremental persistence
                        let old_cc = state.ledger.state.commitment_count();

                        // Apply vertex to chain state (skip DAG for already-finalized vertices)
                        match state.ledger.state.apply_vertex(&vertex) {
                            Ok(_) => {
                                applied += 1;

                                // Persist the same way as finalize_vertex_inner
                                let _ = state.storage.put_vertex(&vertex);
                                for tx in &vertex.transactions {
                                    let _ = state.storage.put_transaction(tx);
                                    for input in &tx.inputs {
                                        let _ = state.storage.put_nullifier(&input.nullifier);
                                    }
                                }
                                let _ = state.storage.put_finalized_vertex_index(seq, &vertex.id);

                                // Persist modified commitment tree nodes
                                let new_cc = state.ledger.state.commitment_count();
                                if new_cc > old_cc {
                                    for level in 0..=MERKLE_DEPTH {
                                        let range_start = old_cc >> level;
                                        let range_end = ((new_cc - 1) >> level) + 1;
                                        for idx in range_start..range_end {
                                            let hash =
                                                state.ledger.state.commitment_tree_node(level, idx);
                                            let _ = state
                                                .storage
                                                .put_commitment_level(level, idx, &hash);
                                        }
                                    }
                                }

                                // Persist validators
                                for validator in state.ledger.state.all_validators() {
                                    let bond = state
                                        .ledger
                                        .state
                                        .validator_bond(&validator.id)
                                        .unwrap_or(0);
                                    let _ = state.storage.put_validator(validator, bond);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Sync: failed to apply vertex at seq {}: {}",
                                    seq,
                                    e
                                );
                                // Stop syncing on error
                                self.sync_state = SyncState::NeedSync { our_finalized: seq };
                                return;
                            }
                        }
                    }

                    // Persist meta snapshot after batch
                    {
                        let state = self.state.read().await;
                        let fc = state.storage.finalized_vertex_count().unwrap_or(0);
                        let meta = state.ledger.state.to_chain_state_meta(fc);
                        let _ = state.storage.put_chain_state_meta(&meta);
                        let _ = state.storage.flush();
                    }

                    tracing::info!(
                        "Sync: applied {} vertices (up to seq {}), total finalized on peer: {}",
                        applied,
                        last_seq,
                        total_finalized,
                    );

                    if has_more && batch_len > 0 {
                        // Request next batch
                        self.sync_state = SyncState::Syncing {
                            peer: from,
                            next_seq: last_seq,
                            target: total_finalized,
                        };
                        let _ = self
                            .p2p
                            .send_to(
                                from,
                                Message::GetFinalizedVertices {
                                    after_sequence: last_seq,
                                    limit: crate::constants::SYNC_BATCH_SIZE,
                                },
                            )
                            .await;
                    } else {
                        tracing::info!("Sync complete");
                        self.sync_state = SyncState::Synced;
                    }
                }
            }
            // Response messages that don't need special handling
            Message::TransactionResponse(_)
            | Message::VertexResponse(_)
            | Message::TipsResponse(_)
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

        // Record commitment count before finalization for incremental tree persistence
        let old_commitment_count = state.ledger.state.commitment_count();

        match state.ledger.finalize_vertex(vertex_id) {
            Ok(_) => {
                // Remove conflicting mempool txs
                state.mempool.remove_conflicting(&nullifiers);

                // ── Persist finalized vertex and state ──
                if let Some(v) = state.ledger.dag.get(vertex_id) {
                    let _ = state.storage.put_vertex(v);

                    // Persist individual transactions and their nullifiers
                    for tx in &v.transactions {
                        let _ = state.storage.put_transaction(tx);
                        for input in &tx.inputs {
                            let _ = state.storage.put_nullifier(&input.nullifier);
                        }
                    }
                }

                // Persist finalized vertex index
                let finalized_count = state.storage.finalized_vertex_count().unwrap_or(0);
                let _ = state
                    .storage
                    .put_finalized_vertex_index(finalized_count, vertex_id);

                // Persist modified commitment tree nodes (incremental)
                let new_commitment_count = state.ledger.state.commitment_count();
                if new_commitment_count > old_commitment_count {
                    for level in 0..=MERKLE_DEPTH {
                        let range_start = old_commitment_count >> level;
                        let range_end = ((new_commitment_count - 1) >> level) + 1;
                        for idx in range_start..range_end {
                            let hash = state.ledger.state.commitment_tree_node(level, idx);
                            let _ = state.storage.put_commitment_level(level, idx, &hash);
                        }
                    }
                }

                // Persist validators (update all active + bonded)
                for validator in state.ledger.state.all_validators() {
                    let bond = state
                        .ledger
                        .state
                        .validator_bond(&validator.id)
                        .unwrap_or(0);
                    let _ = state.storage.put_validator(validator, bond);
                }

                // Persist chain state meta snapshot
                let meta = state.ledger.state.to_chain_state_meta(finalized_count + 1);
                let _ = state.storage.put_chain_state_meta(&meta);

                // Flush to disk
                let _ = state.storage.flush();

                // Check for equivocation evidence and slash
                for evidence in state.bft.equivocations() {
                    if let Ok(()) = state.ledger.state.slash_validator(&evidence.voter_id) {
                        tracing::warn!(
                            "Slashed validator {} for equivocation in round {}",
                            hex::encode(&evidence.voter_id[..8]),
                            evidence.round
                        );
                    }
                }
                // M5: Clear processed evidence to avoid re-processing
                state.bft.clear_equivocations();

                // Advance BFT round
                state.bft.advance_round();
                state.ledger.dag.advance_round();

                // M1: Check for epoch transition
                let dag_epoch = state.ledger.dag.epoch();
                if dag_epoch > state.bft.epoch {
                    let (fees, new_seed) = state.ledger.state.advance_epoch();
                    tracing::info!(
                        "Epoch advanced to {} (fees collected: {})",
                        new_seed.epoch,
                        fees
                    );

                    // Re-evaluate our VRF for the new epoch
                    let total_validators = state.ledger.state.total_validators();
                    let vrf_input = new_seed.vrf_input(&self.our_validator_id);
                    let vrf = VrfOutput::evaluate(&self.keypair, &vrf_input);

                    // Update BFT for the new epoch
                    state.bft.epoch = dag_epoch;
                    state.bft.set_epoch_context(new_seed, total_validators);

                    if vrf.is_selected(crate::constants::COMMITTEE_SIZE, total_validators) {
                        tracing::info!("Selected for epoch {} committee via VRF", dag_epoch);
                        state.bft.set_our_vrf_proof(vrf);
                        // Note: self.our_vrf_output is not updated here because
                        // it's behind &self. The next proposal interval will
                        // pick up the VRF from bft state.
                    } else {
                        tracing::info!("Not selected for epoch {} committee", dag_epoch);
                    }
                }

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
