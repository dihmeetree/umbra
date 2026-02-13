//! Node orchestrator tying together the ledger, mempool, storage, and P2P.
//!
//! The `Node` struct owns all subsystems and runs the main event loop,
//! dispatching incoming P2P messages and periodically proposing vertices.
//! When configured as a validator (`genesis_validator`), the node actively
//! participates in consensus: proposing vertices, casting BFT votes, and
//! managing epoch transitions.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::consensus::bft::{self, BftState, Validator};
use crate::consensus::dag::{Vertex, VertexId};
use crate::crypto::keys::{KemKeypair, SigningKeypair};
use crate::crypto::stark::spend_air::MERKLE_DEPTH;
use crate::crypto::vrf::VrfOutput;
use crate::mempool::Mempool;
use crate::network::Message;
use crate::p2p::{P2pConfig, P2pEvent, P2pHandle};
use crate::state::Ledger;
use crate::storage::{SledStorage, Storage};
use crate::transaction::TxId;
use crate::Hash;

/// Maximum number of entries in the seen_messages dedup set before clearing.
const SEEN_MESSAGES_CAPACITY: usize = 10_000;

/// Maximum number of sync batch rounds before giving up on the current peer.
const MAX_SYNC_ROUNDS: u64 = 1000;

/// Shared node state accessible from RPC handlers.
pub struct NodeState {
    pub ledger: Ledger,
    pub mempool: Mempool,
    pub storage: SledStorage,
    pub bft: BftState,
    /// Time of last vertex finalization (for view change detection).
    pub last_finalized_time: Option<Instant>,
    /// Highest round observed from peer vertices/votes (for lag detection).
    pub peer_highest_round: u64,
    /// Time the node was started (for health/metrics reporting).
    pub node_start_time: Instant,
    /// Protocol version signal counts per epoch (F16).
    pub version_signals: HashMap<u32, u64>,
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
        /// When we last received a sync response (for timeout detection).
        last_activity: Instant,
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
    /// Counter for periodic mempool eviction.
    proposal_tick_count: u64,
    /// Peers that failed sync recently (with cooldown timestamp).
    sync_failed_peers: HashMap<crate::network::PeerId, Instant>,
    /// Dandelion++ stem-phase transactions: tx_hash -> (hops_remaining, inserted_at).
    stem_txs: HashMap<Hash, (u8, Instant)>,
    /// Peers recently attempted for discovery (cleared each round).
    recently_attempted: HashSet<SocketAddr>,
    /// Gossip deduplication: recently seen message IDs to avoid rebroadcasting.
    seen_messages: HashSet<Hash>,
    /// Counter for sync batch rounds (reset on new sync peer).
    sync_rounds: u64,
}

/// Node configuration.
#[derive(Clone)]
pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    pub bootstrap_peers: Vec<SocketAddr>,
    pub data_dir: PathBuf,
    pub rpc_addr: SocketAddr,
    pub keypair: SigningKeypair,
    pub kem_keypair: KemKeypair,
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
pub fn load_or_generate_keypair(
    data_dir: &Path,
) -> Result<(SigningKeypair, KemKeypair), std::io::Error> {
    let key_path = data_dir.join("validator.key");

    if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        // Format: [pk_len: u32 LE][pk_bytes][sk_bytes]
        //         [kem_pk_len: u32 LE][kem_pk_bytes][kem_sk_bytes]  (optional, added later)
        if bytes.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "key file too short",
            ));
        }
        let pk_len = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "key file header corrupted")
        })?) as usize;
        if bytes.len() < 4 + pk_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "key file truncated",
            ));
        }

        // Dilithium5 has fixed secret key size of 4896 bytes
        let signing_sk_end = 4 + pk_len + 4896;
        let (pk_bytes, sk_bytes, kem_kp) = if bytes.len() > signing_sk_end + 4 {
            // KEM section exists
            let pk_bytes = bytes[4..4 + pk_len].to_vec();
            let sk_bytes = bytes[4 + pk_len..signing_sk_end].to_vec();
            let kem_pk_len = u32::from_le_bytes(
                bytes[signing_sk_end..signing_sk_end + 4]
                    .try_into()
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "key file KEM header corrupted",
                        )
                    })?,
            ) as usize;
            let kem_pk_start = signing_sk_end + 4;
            if bytes.len() < kem_pk_start + kem_pk_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "key file truncated (KEM section)",
                ));
            }
            let kem_pk_bytes = bytes[kem_pk_start..kem_pk_start + kem_pk_len].to_vec();
            let kem_sk_bytes = bytes[kem_pk_start + kem_pk_len..].to_vec();
            let kem = KemKeypair::from_bytes(kem_pk_bytes, kem_sk_bytes).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid KEM key data")
            })?;
            (pk_bytes, sk_bytes, kem)
        } else {
            // Legacy file without KEM — use all remaining bytes as signing sk
            let pk_bytes = bytes[4..4 + pk_len].to_vec();
            let sk_bytes = bytes[4 + pk_len..].to_vec();
            let kem = KemKeypair::generate();
            // Re-save with KEM section appended
            let mut new_bytes = bytes.clone();
            let kem_pk_len = (kem.public.0.len() as u32).to_le_bytes();
            new_bytes.extend_from_slice(&kem_pk_len);
            new_bytes.extend_from_slice(&kem.public.0);
            new_bytes.extend_from_slice(&kem.secret.0);
            std::fs::write(&key_path, &new_bytes)?;
            tracing::info!("Upgraded key file with KEM keypair");
            (pk_bytes, sk_bytes, kem)
        };

        let keypair = SigningKeypair::from_bytes(pk_bytes, sk_bytes).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key data")
        })?;
        tracing::info!(
            "Loaded validator key: {}",
            hex::encode(&keypair.public.fingerprint()[..8])
        );
        Ok((keypair, kem_kp))
    } else {
        std::fs::create_dir_all(data_dir)?;
        let keypair = SigningKeypair::generate();
        let kem_kp = KemKeypair::generate();
        let pk_len = (keypair.public.0.len() as u32).to_le_bytes();
        let kem_pk_len = (kem_kp.public.0.len() as u32).to_le_bytes();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&pk_len);
        bytes.extend_from_slice(&keypair.public.0);
        bytes.extend_from_slice(&keypair.secret.0);
        bytes.extend_from_slice(&kem_pk_len);
        bytes.extend_from_slice(&kem_kp.public.0);
        bytes.extend_from_slice(&kem_kp.secret.0);
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
        Ok((keypair, kem_kp))
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

        // Create mempool and set epoch for expiry validation
        let mut mempool = Mempool::with_defaults();
        mempool.set_epoch(ledger.state.epoch());

        let our_validator_id = config.keypair.public.fingerprint();

        // Initialize BFT state
        let chain_id = *ledger.state.chain_id();
        let mut bft = BftState::new(0, vec![], chain_id);
        bft.set_our_keypair(config.keypair.clone());

        // Genesis validator bootstrap
        let mut our_vrf_output = None;
        if config.genesis_validator {
            let validator = Validator::with_kem(
                config.keypair.public.clone(),
                config.kem_keypair.public.clone(),
            );
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

            // Create genesis coinbase (initial coin distribution)
            if let Some(genesis_cb) = ledger
                .state
                .create_genesis_coinbase(&config.kem_keypair.public)
            {
                storage
                    .put_coinbase_output(0, &genesis_cb)
                    .unwrap_or_else(|e| {
                        tracing::warn!("Failed to persist genesis coinbase: {}", e)
                    });
                tracing::info!(
                    "Genesis coinbase: {} units minted",
                    crate::constants::GENESIS_MINT
                );
            }

            // Persist validator to storage
            storage
                .put_validator(
                    &Validator::with_kem(
                        config.keypair.public.clone(),
                        config.kem_keypair.public.clone(),
                    ),
                    crate::constants::VALIDATOR_BOND,
                )
                .unwrap_or_else(|e| tracing::warn!("Failed to persist validator: {}", e));

            // Persist commitment tree nodes from genesis coinbase
            for level in 0..=MERKLE_DEPTH {
                for idx in 0..ledger.state.commitment_tree_level_len(level) {
                    let hash = ledger.state.commitment_tree_node(level, idx);
                    let _ = storage.put_commitment_level(level, idx, &hash);
                }
            }

            // Persist chain state meta after genesis setup
            let fc = storage.finalized_vertex_count().unwrap_or(0);
            let meta = ledger.state.to_chain_state_meta(fc);
            let _ = storage.put_chain_state_meta(&meta);
            let _ = storage.flush();

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
            our_kem_keypair: config.kem_keypair.clone(),
            our_signing_keypair: config.keypair.clone(),
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
            last_finalized_time: None,
            peer_highest_round: 0,
            node_start_time: Instant::now(),
            version_signals: HashMap::new(),
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
            proposal_tick_count: 0,
            sync_failed_peers: HashMap::new(),
            stem_txs: HashMap::new(),
            recently_attempted: HashSet::new(),
            seen_messages: HashSet::new(),
            sync_rounds: 0,
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
    pub async fn run(&mut self, shutdown: CancellationToken) {
        let mut proposal_interval = tokio::time::interval(std::time::Duration::from_millis(
            crate::constants::VERTEX_PROPOSAL_INTERVAL_MS,
        ));
        let mut sync_check_interval = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut peer_exchange_interval = tokio::time::interval(std::time::Duration::from_millis(
            crate::constants::PEER_EXCHANGE_INTERVAL_MS,
        ));
        let mut dandelion_flush_interval =
            tokio::time::interval(std::time::Duration::from_millis(1000));

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("Shutdown signal received");
                    self.shutdown().await;
                    break;
                }
                Some(event) = self.event_rx.recv() => {
                    self.handle_p2p_event(event).await;
                }
                _ = proposal_interval.tick() => {
                    self.proposal_tick_count += 1;
                    // Periodic mempool eviction (~every 50 seconds)
                    if self.proposal_tick_count.is_multiple_of(100) {
                        let mut state = self.state.write().await;
                        let evicted = state.mempool.evict_expired();
                        if evicted > 0 {
                            tracing::debug!("Periodic eviction: removed {} expired txs", evicted);
                        }
                    }
                    self.try_propose_vertex().await;
                }
                _ = sync_check_interval.tick() => {
                    self.check_sync_and_view_change().await;
                }
                _ = peer_exchange_interval.tick() => {
                    self.peer_discovery().await;
                }
                _ = dandelion_flush_interval.tick() => {
                    self.flush_dandelion_stems().await;
                }
            }
        }
    }

    /// Gracefully shut down the node: flush storage and stop P2P.
    async fn shutdown(&self) {
        let state = self.state.read().await;
        if let Err(e) = state.storage.flush() {
            tracing::error!("Failed to flush storage on shutdown: {}", e);
        }
        tracing::info!("Storage flushed, shutting down P2P...");
        drop(state);
        let _ = self.p2p.shutdown().await;
        tracing::info!("Node shutdown complete");
    }

    async fn handle_p2p_event(&mut self, event: P2pEvent) {
        match event {
            P2pEvent::MessageReceived { from, message } => {
                self.handle_message(from, *message).await;
                // After message handling, sync our VRF output with BFT state.
                // Epoch transitions in finalize_vertex_inner update bft but
                // cannot update self.our_vrf_output since it takes &self.
                self.refresh_vrf_from_bft().await;
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
            // Fix 5: For received stem-phase txs, defer mempool insertion until fluff.
            Message::NewTransaction(tx) => {
                let tx_hash = tx.tx_id().0;

                // Check if this is a continuation of an existing stem phase
                if let Some(&(hops, _)) = self.stem_txs.get(&tx_hash) {
                    if hops > 0 {
                        // Continue stem phase -- do NOT insert into mempool yet
                        // to preserve Dandelion++ privacy for the originator.
                        self.stem_forward(tx, hops - 1).await;
                        return;
                    }
                    // hops == 0: fall through to fluff (insert + broadcast)
                }

                // Fluff phase or new transaction: validate and insert into mempool
                let mut state = self.state.write().await;
                match state.mempool.insert(tx.clone()) {
                    Ok(_) => {
                        drop(state);
                        // Start new stem phase for received transactions
                        self.stem_forward(
                            tx,
                            crate::constants::DANDELION_STEM_HOPS.saturating_sub(1),
                        )
                        .await;
                    }
                    Err(e) => {
                        tracing::debug!("Rejected tx: {}", e);
                    }
                }
            }
            Message::NewVertex(vertex) => {
                // Fix 6: Gossip deduplication -- skip already-seen vertices
                if self.seen_messages.len() > SEEN_MESSAGES_CAPACITY {
                    self.seen_messages.clear();
                }
                if !self.seen_messages.insert(vertex.id.0) {
                    return; // Already processed this vertex
                }

                let mut state = self.state.write().await;

                // Track peer's highest round for view change detection
                if vertex.round > state.peer_highest_round {
                    state.peer_highest_round = vertex.round;
                }

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

                // Insert into DAG (but don't finalize yet -- wait for BFT)
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
                                // Quorum reached -- finalize
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
                // Fix 6: Gossip deduplication for votes
                let vote_dedup_key = crate::hash_concat(&[&vote.voter_id, &vote.vertex_id.0]);
                if self.seen_messages.len() > SEEN_MESSAGES_CAPACITY {
                    self.seen_messages.clear();
                }
                if !self.seen_messages.insert(vote_dedup_key) {
                    return; // Already processed this vote
                }

                let mut state = self.state.write().await;
                // Track peer's highest round for view change detection
                if vote.round > state.peer_highest_round {
                    state.peer_highest_round = vote.round;
                }
                // H5: Only re-broadcast if the vote was accepted
                if let Some(cert) = state.bft.receive_vote(vote.clone()) {
                    // Quorum reached -- finalize
                    self.finalize_vertex_inner(&mut state, &cert.vertex_id)
                        .await;
                    let _ = self
                        .p2p
                        .broadcast(Message::BftCertificate(cert), None)
                        .await;
                    // Broadcast the vote that completed the certificate
                    let _ = self.p2p.broadcast(Message::BftVote(vote), Some(from)).await;
                } else if state.bft.is_vote_accepted(&vote) {
                    // Vote was accepted (not rejected) -- forward to peers
                    let _ = self.p2p.broadcast(Message::BftVote(vote), Some(from)).await;
                }
            }
            Message::BftCertificate(cert) => {
                // Fix 6: Gossip deduplication for certificates
                if self.seen_messages.len() > SEEN_MESSAGES_CAPACITY {
                    self.seen_messages.clear();
                }
                if !self.seen_messages.insert(cert.vertex_id.0) {
                    return; // Already processed certificate for this vertex
                }

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
                // F5: Limit how many new peers we connect per discovery round
                let mut connected = 0;
                for peer_info in peers.iter().take(crate::constants::MAX_PEERS) {
                    if connected >= crate::constants::PEER_DISCOVERY_MAX {
                        break;
                    }
                    if let Ok(addr) = peer_info.address.parse::<SocketAddr>() {
                        if !self.recently_attempted.contains(&addr) {
                            self.recently_attempted.insert(addr);
                            let _ = self.p2p.connect(addr).await;
                            connected += 1;
                        }
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
                    // Skip peers on cooldown from recent failures
                    if self.sync_failed_peers.contains_key(&from) {
                        tracing::debug!(
                            "Skipping sync peer {} (on cooldown)",
                            hex::encode(&from[..8])
                        );
                        return;
                    }

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
                        // Fix 7: Reset sync round counter for new peer
                        self.sync_rounds = 0;
                        self.sync_state = SyncState::Syncing {
                            peer: from,
                            next_seq: start_after,
                            target: 0, // unknown until first response
                            last_activity: Instant::now(),
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

                    // Fix 7: Verify total_finalized is within reasonable bounds
                    let our_finalized_count = {
                        let st = self.state.read().await;
                        st.storage.finalized_vertex_count().unwrap_or(0)
                    };
                    let max_reasonable = our_finalized_count + crate::constants::EPOCH_LENGTH * 10;
                    if total_finalized > max_reasonable {
                        tracing::warn!(
                            "Sync: peer claims {} finalized vertices (our: {}, max reasonable: {}), aborting",
                            total_finalized,
                            our_finalized_count,
                            max_reasonable,
                        );
                        let peer_id = from;
                        self.sync_failed_peers.insert(peer_id, Instant::now());
                        self.sync_state = SyncState::NeedSync {
                            our_finalized: our_finalized_count,
                        };
                        return;
                    }

                    // Fix 7: Check max sync rounds
                    self.sync_rounds += 1;
                    if self.sync_rounds > MAX_SYNC_ROUNDS {
                        tracing::warn!(
                            "Sync: exceeded {} rounds with peer {}, giving up",
                            MAX_SYNC_ROUNDS,
                            hex::encode(&from[..8])
                        );
                        let peer_id = from;
                        self.sync_failed_peers.insert(peer_id, Instant::now());
                        self.sync_state = SyncState::NeedSync {
                            our_finalized: our_finalized_count,
                        };
                        return;
                    }

                    let batch_len = vertices.len();
                    let mut last_seq = 0u64;
                    let mut applied = 0usize;

                    for (seq, vertex) in vertices {
                        last_seq = seq;
                        let mut state = self.state.write().await;

                        // Record commitment count for incremental persistence
                        let old_cc = state.ledger.state.commitment_count();

                        // Fix 1: Apply vertex via validated path (insert_vertex validates
                        // structure + signature, then finalize applies to state).
                        match state.ledger.apply_finalized_vertex(*vertex.clone()) {
                            Ok(coinbase) => {
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

                                // Persist coinbase output if created
                                if let Some(ref cb) = coinbase {
                                    let _ = state.storage.put_coinbase_output(seq, cb);
                                }

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
                            last_activity: Instant::now(),
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
            Message::TipsResponse(tips) => {
                // View change: check for tips we don't have
                let state = self.state.read().await;
                let missing: Vec<VertexId> = tips
                    .iter()
                    .filter(|tip| state.ledger.dag.get(tip).is_none())
                    .copied()
                    .collect();
                drop(state);

                for tip in missing {
                    let _ = self.p2p.send_to(from, Message::GetVertex(tip)).await;
                }
            }
            // Fix 4: VRF validation for VertexResponse
            Message::VertexResponse(maybe_vertex) => {
                if let Some(vertex) = maybe_vertex {
                    let mut state = self.state.write().await;
                    if state.ledger.dag.get(&vertex.id).is_none() {
                        // Validate VRF proof before inserting (same as NewVertex handler)
                        if vertex.round > 0 {
                            let epoch_seed = state.ledger.state.epoch_seed().clone();
                            let total_validators = state.ledger.state.total_validators();
                            if let Err(e) = vertex.validate_vrf(&epoch_seed, total_validators) {
                                tracing::warn!("VertexResponse failed VRF validation: {}", e);
                                return;
                            }
                        }
                        let _ = state.ledger.insert_vertex(*vertex);
                    }
                }
            }
            // Response messages that don't need special handling
            Message::TransactionResponse(_)
            | Message::Hello { .. }
            | Message::KeyExchange { .. }
            | Message::AuthResponse { .. } => {}
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
            Ok(coinbase) => {
                state.last_finalized_time = Some(Instant::now());
                // Remove conflicting mempool txs
                state.mempool.remove_conflicting(&nullifiers);

                // -- Persist finalized vertex and state --
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

                // Persist coinbase output if created
                if let Some(ref cb) = coinbase {
                    let _ = state.storage.put_coinbase_output(finalized_count, cb);
                }

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

                // Track protocol version signal (F16)
                if let Some(v) = state.ledger.dag.get(vertex_id) {
                    *state.version_signals.entry(v.protocol_version).or_insert(0) += 1;
                }

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

                    // Fix 2: Update committee from current active validators
                    state.bft.committee = state
                        .ledger
                        .state
                        .active_validators()
                        .into_iter()
                        .cloned()
                        .collect();

                    if vrf.is_selected(crate::constants::COMMITTEE_SIZE, total_validators) {
                        tracing::info!("Selected for epoch {} committee via VRF", dag_epoch);
                        state.bft.set_our_vrf_proof(vrf);
                    } else {
                        tracing::info!("Not selected for epoch {} committee", dag_epoch);
                    }

                    // Update mempool epoch and evict expired transactions
                    state.mempool.set_epoch(dag_epoch);
                    let evicted = state.mempool.evict_expired();
                    if evicted > 0 {
                        tracing::info!("Evicted {} expired txs on epoch transition", evicted);
                    }

                    let eligible = state.ledger.state.eligible_validators(dag_epoch);
                    tracing::info!(
                        "Epoch {}: {} eligible validators of {} active",
                        dag_epoch,
                        eligible.len(),
                        total_validators,
                    );

                    // F16: Check protocol upgrade signals
                    let total_signals: u64 = state.version_signals.values().sum();
                    if total_signals > 0 {
                        for (&ver, &count) in &state.version_signals {
                            if ver > crate::constants::PROTOCOL_VERSION_ID
                                && count * crate::constants::UPGRADE_THRESHOLD_DEN
                                    > total_signals * crate::constants::UPGRADE_THRESHOLD_NUM
                            {
                                tracing::warn!(
                                    "Protocol upgrade signaled: version {} has {}/{} signals (>75%), effective epoch {}",
                                    ver, count, total_signals, dag_epoch + 2
                                );
                            }
                        }
                    }
                    state.version_signals.clear();

                    // F13: DAG memory pruning -- remove old finalized vertices
                    if dag_epoch > crate::constants::PRUNING_RETAIN_EPOCHS {
                        let before = dag_epoch - crate::constants::PRUNING_RETAIN_EPOCHS;
                        let pruned = state.ledger.dag.prune_finalized(before);
                        if pruned > 0 {
                            tracing::info!("Pruned {} old vertices from DAG memory", pruned);
                        }
                    }
                }

                tracing::info!("Finalized vertex {}", hex::encode(&vertex_id.0[..8]));
            }
            Err(e) => {
                tracing::debug!("Failed to finalize vertex: {}", e);
            }
        }
    }

    /// Check sync timeout and view change conditions.
    ///
    /// Called periodically (every 5s) to detect:
    /// - Sync peers that stopped responding (revert to NeedSync)
    /// - Stale finalization or round lag (broadcast GetTips to discover missing state)
    async fn check_sync_and_view_change(&mut self) {
        // Sync timeout: if syncing peer hasn't responded, try another
        if let SyncState::Syncing {
            peer,
            next_seq,
            last_activity,
            ..
        } = &self.sync_state
        {
            let elapsed = last_activity.elapsed();
            if elapsed > std::time::Duration::from_millis(crate::constants::SYNC_REQUEST_TIMEOUT_MS)
            {
                tracing::warn!(
                    "Sync timeout: peer {} unresponsive for {}ms, retrying",
                    hex::encode(&peer[..8]),
                    elapsed.as_millis()
                );
                let peer_id = *peer;
                let seq = *next_seq;

                self.sync_failed_peers.insert(peer_id, Instant::now());
                self.sync_state = SyncState::NeedSync { our_finalized: seq };
                let _ = self.p2p.broadcast(Message::GetEpochState, None).await;
            }
        }

        // Clean expired cooldowns
        let cutoff = std::time::Duration::from_millis(crate::constants::SYNC_PEER_COOLDOWN_MS);
        self.sync_failed_peers
            .retain(|_, failed_at| failed_at.elapsed() < cutoff);

        // View change: if synced but no finalization for too long, or peers
        // are ahead, broadcast GetTips to discover missing state
        if matches!(self.sync_state, SyncState::Synced) {
            let state = self.state.read().await;
            let view_change_timeout = std::time::Duration::from_millis(
                crate::constants::VIEW_CHANGE_TIMEOUT_INTERVALS
                    * crate::constants::VERTEX_PROPOSAL_INTERVAL_MS,
            );

            let stale = match state.last_finalized_time {
                Some(t) => t.elapsed() > view_change_timeout,
                None => false,
            };

            let our_round = state.bft.round;
            let peer_round = state.peer_highest_round;
            drop(state);

            if stale || peer_round > our_round + crate::constants::MAX_ROUND_LAG {
                tracing::warn!(
                    "View change: stale={}, our_round={}, peer_round={}. Broadcasting GetTips.",
                    stale,
                    our_round,
                    peer_round
                );
                let _ = self.p2p.broadcast(Message::GetTips, None).await;
                let _ = self.p2p.broadcast(Message::GetEpochState, None).await;
            }
        }
    }

    /// Fix 3: Dandelion++ stem-forward: send tx to one *random* peer, track hops.
    async fn stem_forward(&mut self, tx: crate::transaction::Transaction, hops_remaining: u8) {
        use rand::prelude::IndexedRandom;
        let tx_hash = tx.tx_id().0;
        if hops_remaining == 0 {
            // Fluff: broadcast to all
            self.stem_txs.remove(&tx_hash);
            let _ = self.p2p.broadcast(Message::NewTransaction(tx), None).await;
        } else {
            // Stem: forward to one random peer
            self.stem_txs
                .insert(tx_hash, (hops_remaining, Instant::now()));
            if let Ok(peers) = self.p2p.get_peers().await {
                if let Some(peer) = peers.choose(&mut rand::rng()) {
                    let _ = self
                        .p2p
                        .send_to(peer.peer_id, Message::NewTransaction(tx))
                        .await;
                    return;
                }
            }
            // No peers: fluff immediately
            self.stem_txs.remove(&tx_hash);
            let _ = self.p2p.broadcast(Message::NewTransaction(tx), None).await;
        }
    }

    /// Flush timed-out Dandelion++ stem transactions (fluff them).
    async fn flush_dandelion_stems(&mut self) {
        let timeout = std::time::Duration::from_millis(crate::constants::DANDELION_TIMEOUT_MS);
        let expired: Vec<Hash> = self
            .stem_txs
            .iter()
            .filter(|(_, (_, inserted_at))| inserted_at.elapsed() > timeout)
            .map(|(hash, _)| *hash)
            .collect();

        for hash in expired {
            self.stem_txs.remove(&hash);
            // The tx is already in our mempool, broadcast it
            let state = self.state.read().await;
            if let Some(tx) = state.mempool.get(&TxId(hash)).cloned() {
                drop(state);
                let _ = self.p2p.broadcast(Message::NewTransaction(tx), None).await;
            }
        }
    }

    /// Peer discovery: ask random connected peers for their peer lists.
    async fn peer_discovery(&mut self) {
        self.recently_attempted.clear();
        if let Ok(peers) = self.p2p.get_peers().await {
            // Pick up to 3 random peers to ask
            for peer in peers.iter().take(3) {
                let _ = self.p2p.send_to(peer.peer_id, Message::GetPeers).await;
            }
        }
    }

    /// Fix 2: Sync our VRF output from BFT state after epoch transitions.
    ///
    /// Called after message handling since `finalize_vertex_inner` (which takes
    /// `&self`) cannot update `self.our_vrf_output` directly. This method
    /// re-evaluates our VRF for the current epoch and updates the cached output.
    async fn refresh_vrf_from_bft(&mut self) {
        let state = self.state.read().await;
        let epoch_seed = state.ledger.state.epoch_seed().clone();
        let total_validators = state.ledger.state.total_validators();
        drop(state);

        // Re-evaluate VRF for the current epoch seed
        let vrf_input = epoch_seed.vrf_input(&self.our_validator_id);
        let vrf = VrfOutput::evaluate(&self.keypair, &vrf_input);

        if vrf.is_selected(crate::constants::COMMITTEE_SIZE, total_validators) {
            // Update if VRF value changed (new epoch) or was previously None
            if self
                .our_vrf_output
                .as_ref()
                .map(|v| v.value != vrf.value)
                .unwrap_or(true)
            {
                self.our_vrf_output = Some(vrf);
            }
        } else if self.our_vrf_output.is_some() {
            self.our_vrf_output = None;
        }
    }

    /// Try to propose a new vertex if we're on the committee.
    async fn try_propose_vertex(&self) {
        let vrf = match &self.our_vrf_output {
            Some(vrf) => vrf.clone(),
            None => return, // Not on committee
        };

        let mut state = self.state.write().await;

        // Drain transactions from mempool (may be empty -- empty vertices are
        // allowed for liveness so that epochs advance and coinbase rewards
        // are distributed even during low-activity periods).
        let transactions = state
            .mempool
            .drain_highest_fee(crate::constants::VERTEX_MAX_DRAIN);

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
            protocol_version: crate::constants::PROTOCOL_VERSION_ID,
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
        let (signing1, kem1) = load_or_generate_keypair(dir.path()).unwrap();
        let (signing2, kem2) = load_or_generate_keypair(dir.path()).unwrap();
        // Should load the same keys
        assert_eq!(signing1.public.fingerprint(), signing2.public.fingerprint());
        assert_eq!(kem1.public.0, kem2.public.0);
    }
}
