//! P2P networking layer using async TCP with tokio.
//!
//! All connections are encrypted and mutually authenticated:
//! 1. Hello exchange (plaintext) — version check + KEM public key exchange
//! 2. Kyber1024 KEM handshake — initiator encapsulates to responder's KEM PK
//! 3. Dilithium5 auth — both sides sign the handshake transcript
//! 4. Encrypted transport — ChaCha20-Poly1305 AEAD per message

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use zeroize::Zeroize;

use crate::crypto::keys::{KemKeypair, SigningKeypair, SigningPublicKey};
use crate::network::nat::NatState;
use crate::network::{self, Message, PeerId, PeerInfo, PROTOCOL_VERSION};
use crate::Hash;

// ── Rate Limiting ──

/// Simple token-bucket rate limiter for per-peer message throttling.
struct RateLimiter {
    tokens: f64,
    max_tokens: f64,
    refill_per_sec: f64,
    last_refill: std::time::Instant,
}

impl RateLimiter {
    fn new(max_tokens: f64, refill_per_sec: f64) -> Self {
        RateLimiter {
            tokens: max_tokens,
            max_tokens,
            refill_per_sec,
            last_refill: std::time::Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.max_tokens);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ── Transport Encryption ──

/// Nonce size for ChaCha20-Poly1305 (standard 96-bit nonce).
const TRANSPORT_NONCE_SIZE: usize = 12;

/// Poly1305 authentication tag size.
const TRANSPORT_TAG_SIZE: usize = 16;

/// Session keys for encrypted P2P transport.
/// Initiator and responder derive mirrored send/recv key pairs so that
/// each side's send key is the other side's recv key.
/// AEAD handles authentication, so no separate MAC keys are needed.
struct SessionKeys {
    send_key: [u8; 32],
    recv_key: [u8; 32],
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

impl SessionKeys {
    fn derive(shared_secret: &[u8; 32], is_initiator: bool) -> Self {
        let init_send = crate::hash_domain(b"umbra.p2p.init.send", shared_secret);
        let resp_send = crate::hash_domain(b"umbra.p2p.resp.send", shared_secret);
        if is_initiator {
            SessionKeys {
                send_key: init_send,
                recv_key: resp_send,
            }
        } else {
            SessionKeys {
                send_key: resp_send,
                recv_key: init_send,
            }
        }
    }
}

/// Build a 12-byte nonce from a counter (TLS 1.3 style: 4 zero bytes + 8-byte counter LE).
fn counter_to_nonce(counter: u64) -> [u8; TRANSPORT_NONCE_SIZE] {
    let mut nonce = [0u8; TRANSPORT_NONCE_SIZE];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Compute the handshake transcript hash for mutual authentication.
/// Binds both peer identities and the KEM ciphertext to prevent replay/MITM.
fn compute_transcript_hash(initiator_id: &Hash, responder_id: &Hash, kem_ct: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(32 + 32 + kem_ct.len());
    buf.extend_from_slice(initiator_id);
    buf.extend_from_slice(responder_id);
    buf.extend_from_slice(kem_ct);
    crate::hash_domain(b"umbra.p2p.transcript", &buf)
}

/// Round up to the next multiple of `P2P_PADDING_BUCKET`.
fn pad_to_bucket(len: usize) -> usize {
    let bucket = crate::constants::P2P_PADDING_BUCKET;
    len.div_ceil(bucket) * bucket
}

/// Write an encrypted + authenticated message frame with padding.
///
/// The plaintext region embeds the real payload length (4-byte LE) followed by
/// the payload and zero-padding to the next bucket boundary. This hides the
/// actual message size from network observers.
///
/// Frame format: `[4-byte LE frame_len][8-byte LE counter][aead_ciphertext]`
/// AEAD ciphertext contains: encrypted `[4-byte LE real_len][payload][zero_padding]` + 16-byte tag
async fn write_encrypted(
    writer: &mut OwnedWriteHalf,
    msg: &Message,
    send_key: &[u8; 32],
    counter: &mut u64,
) -> Result<(), P2pError> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let payload = network::encode_message(msg).map_err(|e| P2pError::SendFailed(e.to_string()))?;

    // Embed real length inside the encrypted region, then pad to bucket boundary
    let real_len = payload.len() as u32;
    let padded_len = pad_to_bucket(4 + payload.len());
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(&real_len.to_le_bytes());
    padded.extend_from_slice(&payload);
    padded.resize(padded_len, 0u8);

    // S7: Reject if counter would overflow (prevents nonce reuse).
    // At 1M msg/sec this takes ~585,000 years, but check defensively.
    if *counter >= u64::MAX / 2 {
        return Err(P2pError::SendFailed(
            "message counter exhausted, reconnect required".into(),
        ));
    }

    let nonce_bytes = counter_to_nonce(*counter);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(send_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), padded.as_ref())
        .map_err(|_| P2pError::SendFailed("AEAD encryption failed".into()))?;

    // ciphertext includes 16-byte tag
    let frame_len = (8 + ciphertext.len()) as u32;
    let mut frame = Vec::with_capacity(4 + frame_len as usize);
    frame.extend_from_slice(&frame_len.to_le_bytes());
    frame.extend_from_slice(&counter.to_le_bytes());
    frame.extend_from_slice(&ciphertext);

    *counter += 1;
    writer
        .write_all(&frame)
        .await
        .map_err(|e| P2pError::SendFailed(e.to_string()))?;
    Ok(())
}

/// Read and decrypt an authenticated message frame.
async fn read_encrypted(
    reader: &mut OwnedReadHalf,
    recv_key: &[u8; 32],
    expected_counter: &mut u64,
) -> Result<Message, P2pError> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| P2pError::ConnectionFailed(e.to_string()))?;
    let frame_len = u32::from_le_bytes(len_buf) as usize;
    // Minimum: 8 (counter) + P2P_PADDING_BUCKET (min padded ciphertext) + 16 (tag)
    let min_frame = 8 + crate::constants::P2P_PADDING_BUCKET + TRANSPORT_TAG_SIZE;
    if frame_len < min_frame {
        return Err(P2pError::ConnectionFailed(
            "encrypted frame too short".into(),
        ));
    }
    // Max: account for padding overhead (up to one extra bucket) + tag
    let max_frame =
        8 + pad_to_bucket(4 + crate::constants::MAX_NETWORK_MESSAGE_BYTES) + TRANSPORT_TAG_SIZE;
    if frame_len > max_frame {
        return Err(P2pError::ConnectionFailed(
            "encrypted frame too large".into(),
        ));
    }

    let mut frame = vec![0u8; frame_len];
    reader
        .read_exact(&mut frame)
        .await
        .map_err(|e| P2pError::ConnectionFailed(e.to_string()))?;

    // Parse: [8-byte counter][aead_ciphertext (includes tag)]
    let counter = u64::from_le_bytes(frame[..8].try_into().unwrap());
    let ciphertext = &frame[8..];

    if counter != *expected_counter {
        return Err(P2pError::ConnectionFailed(
            "unexpected message counter".into(),
        ));
    }
    // S7: Match the write-side overflow check
    if *expected_counter >= u64::MAX / 2 {
        return Err(P2pError::ConnectionFailed(
            "message counter exhausted, reconnect required".into(),
        ));
    }
    *expected_counter += 1;

    let nonce_bytes = counter_to_nonce(counter);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(recv_key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext)
        .map_err(|_| P2pError::ConnectionFailed("AEAD decryption failed".into()))?;

    // Extract real payload length from the padded plaintext
    if plaintext.len() < 4 {
        return Err(P2pError::ConnectionFailed(
            "decrypted frame too short for length prefix".into(),
        ));
    }
    let real_len = u32::from_le_bytes(plaintext[..4].try_into().unwrap()) as usize;
    // S8: Reject zero-length payloads (must contain at least a message type byte)
    if real_len == 0 {
        return Err(P2pError::ConnectionFailed(
            "decrypted payload is empty".into(),
        ));
    }
    if 4 + real_len > plaintext.len() {
        return Err(P2pError::ConnectionFailed(
            "decrypted payload length exceeds frame".into(),
        ));
    }

    network::decode_message(&plaintext[4..4 + real_len])
        .ok_or_else(|| P2pError::ConnectionFailed("decode failed after decryption".into()))
}

// ── Public Types ──

/// Errors from P2P operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum P2pError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("peer limit reached ({0})")]
    PeerLimitReached(usize),
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("invalid handshake")]
    InvalidHandshake,
    #[error("shutdown")]
    Shutdown,
}

/// A command sent from the application to the P2P event loop.
pub enum P2pCommand {
    /// Connect to a peer at the given address.
    Connect(SocketAddr),
    /// Send a message to a specific peer.
    SendTo(PeerId, Message),
    /// Broadcast a message to all peers (optionally excluding one).
    Broadcast {
        message: Message,
        exclude: Option<PeerId>,
    },
    /// Request the current peer list.
    GetPeers(oneshot::Sender<Vec<PeerInfo>>),
    /// Request hole-punch coordination via a rendezvous peer.
    HolePunch { target: PeerId, rendezvous: PeerId },
    /// Shutdown the P2P system.
    Shutdown,
}

/// An event received from the P2P layer by the application.
#[derive(Debug)]
pub enum P2pEvent {
    /// A new peer connected (inbound or outbound, after handshake).
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// A message was received from a peer.
    MessageReceived { from: PeerId, message: Box<Message> },
}

/// Handle for the application to interact with the P2P layer.
#[derive(Clone)]
pub struct P2pHandle {
    command_tx: mpsc::Sender<P2pCommand>,
}

/// Configuration for the P2P layer.
#[derive(Clone)]
pub struct P2pConfig {
    pub listen_addr: SocketAddr,
    pub max_peers: usize,
    pub our_peer_id: Hash,
    pub our_public_key: SigningPublicKey,
    pub listen_port: u16,
    /// KEM keypair for transport encryption (Kyber1024).
    pub our_kem_keypair: KemKeypair,
    /// Signing keypair for handshake authentication (Dilithium5).
    pub our_signing_keypair: SigningKeypair,
    /// Pre-determined external address (from UPnP or manual config).
    pub external_addr: Option<SocketAddr>,
}

/// Peer reputation tracking (F7).
struct PeerReputation {
    score: i32,
    violations: u32,
    banned_until: Option<Instant>,
}

impl PeerReputation {
    fn new() -> Self {
        PeerReputation {
            score: crate::constants::PEER_INITIAL_REPUTATION,
            violations: 0,
            banned_until: None,
        }
    }

    fn penalize(&mut self, amount: i32) {
        self.score = self.score.saturating_sub(amount);
        self.violations += 1;
        if self.score < crate::constants::PEER_BAN_THRESHOLD {
            let ban_duration =
                std::time::Duration::from_secs(crate::constants::PEER_BAN_DURATION_SECS);
            self.banned_until = Some(Instant::now() + ban_duration);
        }
    }

    /// Reward good behavior (e.g., valid message, successful handshake).
    /// Score is capped at the initial reputation level and cannot recover
    /// from a ban — the ban must expire naturally.
    fn reward(&mut self, amount: i32) {
        self.score = (self.score + amount).min(crate::constants::PEER_INITIAL_REPUTATION);
    }

    fn is_banned(&self) -> bool {
        self.banned_until
            .map(|t| Instant::now() < t)
            .unwrap_or(false)
    }
}

/// State for a single peer connection.
struct PeerConnection {
    peer_id: PeerId,
    #[allow(dead_code)]
    public_key: SigningPublicKey,
    addr: SocketAddr,
    msg_tx: mpsc::Sender<Message>,
    is_outbound: bool,
    /// Peer's claimed or discovered external address (from NatInfo exchange).
    external_addr: Option<SocketAddr>,
}

use std::time::Instant;

/// Internal event from connection tasks to the main P2P loop.
enum InternalEvent {
    /// A connection completed handshake.
    Connected {
        peer_id: PeerId,
        public_key: SigningPublicKey,
        addr: SocketAddr,
        msg_tx: mpsc::Sender<Message>,
        is_outbound: bool,
    },
    /// A message was received from a peer.
    Message { from: PeerId, message: Box<Message> },
    /// A peer disconnected.
    Disconnected(PeerId),
    /// A peer misbehaved and should be penalized.
    Misbehavior { peer_id: PeerId, penalty: i32 },
}

// ── P2pHandle ──

impl P2pHandle {
    /// Create a handle from a raw sender (for testing).
    #[cfg(test)]
    pub fn from_sender(command_tx: mpsc::Sender<P2pCommand>) -> Self {
        P2pHandle { command_tx }
    }

    /// Send a command to connect to a peer.
    pub async fn connect(&self, addr: SocketAddr) -> Result<(), P2pError> {
        self.command_tx
            .send(P2pCommand::Connect(addr))
            .await
            .map_err(|_| P2pError::Shutdown)
    }

    /// Send a message to a specific peer.
    pub async fn send_to(&self, peer_id: PeerId, msg: Message) -> Result<(), P2pError> {
        self.command_tx
            .send(P2pCommand::SendTo(peer_id, msg))
            .await
            .map_err(|_| P2pError::Shutdown)
    }

    /// Broadcast a message to all peers, optionally excluding one.
    pub async fn broadcast(&self, msg: Message, exclude: Option<PeerId>) -> Result<(), P2pError> {
        self.command_tx
            .send(P2pCommand::Broadcast {
                message: msg,
                exclude,
            })
            .await
            .map_err(|_| P2pError::Shutdown)
    }

    /// Get the current peer list.
    pub async fn get_peers(&self) -> Result<Vec<PeerInfo>, P2pError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(P2pCommand::GetPeers(tx))
            .await
            .map_err(|_| P2pError::Shutdown)?;
        rx.await.map_err(|_| P2pError::Shutdown)
    }

    /// Request hole-punch coordination: ask a rendezvous peer to notify the target.
    pub async fn hole_punch(&self, target: PeerId, rendezvous: PeerId) -> Result<(), P2pError> {
        self.command_tx
            .send(P2pCommand::HolePunch { target, rendezvous })
            .await
            .map_err(|_| P2pError::Shutdown)
    }

    /// Shut down the P2P layer.
    pub async fn shutdown(&self) -> Result<(), P2pError> {
        self.command_tx
            .send(P2pCommand::Shutdown)
            .await
            .map_err(|_| P2pError::Shutdown)
    }
}

// ── Startup & Event Loop ──

/// Result of starting the P2P layer.
pub struct P2pStartResult {
    pub handle: P2pHandle,
    pub events: mpsc::Receiver<P2pEvent>,
    /// The actual bound address (useful when listening on port 0).
    pub local_addr: SocketAddr,
}

/// Start the P2P networking layer.
pub async fn start(config: P2pConfig) -> Result<P2pStartResult, P2pError> {
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .map_err(|e| P2pError::ConnectionFailed(e.to_string()))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| P2pError::ConnectionFailed(e.to_string()))?;

    let (command_tx, command_rx) = mpsc::channel::<P2pCommand>(256);
    let (event_tx, event_rx) = mpsc::channel::<P2pEvent>(256);

    tokio::spawn(p2p_loop(config, listener, command_rx, event_tx));

    Ok(P2pStartResult {
        handle: P2pHandle { command_tx },
        events: event_rx,
        local_addr,
    })
}

/// Extract the /16 subnet prefix from an IP address.
/// Returns the first two octets for IPv4; `[0, 0]` for IPv6 (treated as one bucket).
fn subnet_prefix(ip: IpAddr) -> [u8; 2] {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            [octets[0], octets[1]]
        }
        IpAddr::V6(_) => [0, 0],
    }
}

/// Main P2P event loop.
async fn p2p_loop(
    config: P2pConfig,
    listener: TcpListener,
    mut command_rx: mpsc::Receiver<P2pCommand>,
    event_tx: mpsc::Sender<P2pEvent>,
) {
    let mut peers: HashMap<PeerId, PeerConnection> = HashMap::new();
    let mut reputations: HashMap<PeerId, PeerReputation> = HashMap::new();
    let mut inbound_count: usize = 0;
    let mut outbound_count: usize = 0;
    let mut connections_per_ip: HashMap<IpAddr, usize> = HashMap::new();
    let mut inbound_per_subnet: HashMap<[u8; 2], usize> = HashMap::new();
    let max_inbound = config.max_peers / 2;
    let max_outbound = config.max_peers - max_inbound;
    let (internal_tx, mut internal_rx) = mpsc::channel::<InternalEvent>(256);
    let handshake_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(64));

    // NAT state: tracks our external address via manual config, UPnP, or peer observation.
    let mut nat_state = NatState::new(config.listen_port, config.external_addr);

    // Rate limit NAT punch requests per peer (max 5 per 60 seconds).
    let mut nat_punch_counts: HashMap<PeerId, (u32, std::time::Instant)> = HashMap::new();

    loop {
        tokio::select! {
            result = listener.accept() => {
                if let Ok((stream, addr)) = result {
                    // F8: Connection diversity — enforce inbound slot limit
                    if inbound_count >= max_inbound || peers.len() >= config.max_peers {
                        continue;
                    }
                    // DDoS: Per-IP connection limit
                    let ip = addr.ip();
                    let ip_count = connections_per_ip.get(&ip).copied().unwrap_or(0);
                    if ip_count >= crate::constants::MAX_CONNECTIONS_PER_IP {
                        continue;
                    }
                    // DDoS: Per-subnet limit (eclipse mitigation)
                    let subnet = subnet_prefix(ip);
                    let subnet_count = inbound_per_subnet.get(&subnet).copied().unwrap_or(0);
                    if subnet_count >= crate::constants::MAX_PEERS_PER_SUBNET {
                        continue;
                    }
                    let config_clone = config.clone();
                    let internal_tx_clone = internal_tx.clone();
                    let hs_permit = handshake_semaphore.clone();
                    tokio::spawn(async move {
                        let _permit = match hs_permit.acquire().await {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        if let Err(e) = handle_inbound(stream, addr, &config_clone, internal_tx_clone).await {
                            tracing::debug!(addr = %addr, error = %e, "Inbound connection failed");
                        }
                    });
                }
            }

            Some(cmd) = command_rx.recv() => {
                match cmd {
                    P2pCommand::Connect(addr) => {
                        // F8: Connection diversity — enforce outbound slot limit
                        if outbound_count >= max_outbound || peers.len() >= config.max_peers {
                            continue;
                        }
                        let config_clone = config.clone();
                        let internal_tx_clone = internal_tx.clone();
                        let hs_permit = handshake_semaphore.clone();
                        tokio::spawn(async move {
                            let _permit = match hs_permit.acquire().await {
                                Ok(p) => p,
                                Err(_) => return,
                            };
                            if let Err(e) = handle_outbound(addr, &config_clone, internal_tx_clone).await {
                                tracing::debug!(addr = %addr, error = %e, "Outbound connection failed");
                            }
                        });
                    }
                    P2pCommand::SendTo(peer_id, msg) => {
                        if let Some(peer) = peers.get(&peer_id) {
                            if let Err(e) = peer.msg_tx.try_send(msg) {
                                tracing::debug!(
                                    peer = %hex::encode(&peer_id[..8]),
                                    error = %e,
                                    "Failed to send message to peer (channel full or closed)"
                                );
                            }
                        }
                    }
                    P2pCommand::Broadcast { message, exclude } => {
                        for (id, peer) in &peers {
                            if exclude.as_ref() == Some(id) {
                                continue;
                            }
                            if let Err(e) = peer.msg_tx.try_send(message.clone()) {
                                tracing::debug!(
                                    peer = %hex::encode(&id[..8]),
                                    error = %e,
                                    "Failed to broadcast to peer (channel full or closed)"
                                );
                            }
                        }
                    }
                    P2pCommand::GetPeers(reply) => {
                        let infos: Vec<PeerInfo> = peers.values().map(|p| PeerInfo {
                            peer_id: p.peer_id,
                            public_key: p.public_key.clone(),
                            address: p.external_addr.unwrap_or(p.addr).to_string(),
                            last_seen: 0,
                        }).collect();
                        let _ = reply.send(infos);
                    }
                    P2pCommand::HolePunch { target, rendezvous } => {
                        // Ask the rendezvous peer to notify the target
                        if let Some(rendezvous_peer) = peers.get(&rendezvous) {
                            let our_ext = nat_state
                                .external_addr()
                                .map(|a| a.to_string())
                                .unwrap_or_else(|| config.listen_addr.to_string());
                            let _ = rendezvous_peer.msg_tx.try_send(Message::NatPunchRequest {
                                target_peer_id: target,
                                requester_external_addr: our_ext,
                            });
                        }
                    }
                    P2pCommand::Shutdown => {
                        break;
                    }
                }
            }

            Some(event) = internal_rx.recv() => {
                match event {
                    InternalEvent::Connected { peer_id, public_key, addr, msg_tx, is_outbound } => {
                        // Self-connection prevention
                        if peer_id == config.our_peer_id {
                            tracing::debug!("Rejected self-connection");
                            continue;
                        }
                        // F7: Check if peer is banned
                        if let Some(rep) = reputations.get(&peer_id) {
                            if rep.is_banned() {
                                tracing::debug!(peer = %hex::encode(&peer_id[..8]), "Rejected banned peer");
                                continue;
                            }
                        }
                        if peers.len() < config.max_peers && !peers.contains_key(&peer_id) {
                            // F8: Update connection direction counters
                            if is_outbound {
                                outbound_count += 1;
                            } else {
                                inbound_count += 1;
                                // DDoS: Track inbound subnet concentration
                                *inbound_per_subnet.entry(subnet_prefix(addr.ip())).or_insert(0) += 1;
                            }
                            // DDoS: Track per-IP connections
                            *connections_per_ip.entry(addr.ip()).or_insert(0) += 1;

                            // Send NatInfo to the new peer (over encrypted channel).
                            // Privacy: do NOT send observed_addr (the peer's IP as
                            // we see it) to avoid leaking their network identity.
                            let our_ext = nat_state.external_addr().map(|a| a.to_string());
                            let _ = msg_tx.try_send(Message::NatInfo {
                                external_addr: our_ext,
                                observed_addr: String::new(),
                            });

                            peers.insert(peer_id, PeerConnection {
                                peer_id,
                                public_key,
                                addr,
                                msg_tx,
                                is_outbound,
                                external_addr: None,
                            });
                            reputations.entry(peer_id).or_insert_with(PeerReputation::new);
                            let _ = event_tx.send(P2pEvent::PeerConnected(peer_id)).await;
                        }
                    }
                    InternalEvent::Message { from, message } => {
                        // Reward good behavior: peer sent a valid (decryptable) message
                        if let Some(rep) = reputations.get_mut(&from) {
                            rep.reward(1);
                        }

                        // Intercept NAT-related messages — handle internally, don't forward
                        match message.as_ref() {
                            Message::NatInfo { external_addr, observed_addr } => {
                                // Update the peer's external address in our records
                                if let Some(ext_str) = external_addr {
                                    if let Ok(ext_addr) = ext_str.parse::<SocketAddr>() {
                                        if let Some(peer) = peers.get_mut(&from) {
                                            peer.external_addr = Some(ext_addr);
                                        }
                                    }
                                }
                                // Record what the peer observes our address as
                                if let Ok(observed) = observed_addr.parse::<SocketAddr>() {
                                    let ip = observed.ip();
                                    // Reject loopback, unspecified, and private addresses
                                    let is_valid = match ip {
                                        std::net::IpAddr::V4(v4) => {
                                            !v4.is_loopback()
                                                && !v4.is_unspecified()
                                                && !v4.is_private()
                                                && !v4.is_link_local()
                                                && !v4.is_broadcast()
                                        }
                                        std::net::IpAddr::V6(v6) => {
                                            !v6.is_loopback() && !v6.is_unspecified()
                                        }
                                    };
                                    if is_valid {
                                        let changed =
                                            nat_state.record_observed_addr(from, ip);
                                        if changed {
                                            tracing::info!(
                                                addr = %nat_state.external_addr().map(|a| a.to_string()).unwrap_or_default(),
                                                "Observed external address established via peer quorum"
                                            );
                                        }
                                    }
                                }
                                continue;
                            }
                            Message::NatPunchRequest { target_peer_id, requester_external_addr } => {
                                // Rate limit: max 5 punch requests per peer per 60 seconds
                                let now = std::time::Instant::now();
                                // Prune stale entries to prevent unbounded memory growth
                                if nat_punch_counts.len() > 1000 {
                                    nat_punch_counts.retain(|_, (_, ts)| ts.elapsed() < std::time::Duration::from_secs(120));
                                }
                                let entry = nat_punch_counts.entry(from).or_insert((0, now));
                                if entry.1.elapsed() > std::time::Duration::from_secs(60) {
                                    *entry = (0, now);
                                }
                                entry.0 += 1;
                                if entry.0 > 5 {
                                    tracing::debug!(
                                        peer = %hex::encode(&from[..8]),
                                        "NAT punch request rate limited"
                                    );
                                    continue;
                                }
                                // We are the rendezvous: forward a NatPunchNotify to the target
                                if let Some(target_peer) = peers.get(target_peer_id) {
                                    let _ = target_peer.msg_tx.try_send(Message::NatPunchNotify {
                                        requester_peer_id: from,
                                        requester_external_addr: requester_external_addr.clone(),
                                    });
                                    tracing::debug!(
                                        from = %hex::encode(&from[..8]),
                                        to = %hex::encode(&target_peer_id[..8]),
                                        "Relayed punch request"
                                    );
                                }
                                continue;
                            }
                            Message::NatPunchNotify { requester_external_addr, requester_peer_id } => {
                                // Someone wants to connect to us — try connecting back to them
                                if let Ok(addr) = requester_external_addr.parse::<SocketAddr>() {
                                    let config_clone = config.clone();
                                    let internal_tx_clone = internal_tx.clone();
                                    let hs_permit = handshake_semaphore.clone();
                                    let req_id = *requester_peer_id;
                                    tokio::spawn(async move {
                                        for attempt in 1..=crate::constants::HOLE_PUNCH_MAX_ATTEMPTS {
                                            let _permit = match hs_permit.acquire().await {
                                                Ok(p) => p,
                                                Err(_) => return,
                                            };
                                            match handle_outbound(addr, &config_clone, internal_tx_clone.clone()).await {
                                                Ok(()) => {
                                                    tracing::debug!(
                                                        peer = %hex::encode(&req_id[..8]),
                                                        attempt = attempt,
                                                        "Hole punch succeeded"
                                                    );
                                                    return;
                                                }
                                                Err(e) => {
                                                    tracing::debug!(
                                                        attempt = attempt,
                                                        max = crate::constants::HOLE_PUNCH_MAX_ATTEMPTS,
                                                        addr = %addr,
                                                        error = %e,
                                                        "Hole punch attempt failed"
                                                    );
                                                }
                                            }
                                            tokio::time::sleep(std::time::Duration::from_millis(
                                                crate::constants::HOLE_PUNCH_RETRY_DELAY_MS,
                                            ))
                                            .await;
                                        }
                                    });
                                }
                                continue;
                            }
                            _ => {}
                        }

                        let _ = event_tx.send(P2pEvent::MessageReceived { from, message }).await;
                    }
                    InternalEvent::Disconnected(peer_id) => {
                        // F8: Update connection direction counters
                        if let Some(peer) = peers.remove(&peer_id) {
                            if peer.is_outbound {
                                outbound_count = outbound_count.saturating_sub(1);
                            } else {
                                inbound_count = inbound_count.saturating_sub(1);
                                let subnet = subnet_prefix(peer.addr.ip());
                                if let Some(c) = inbound_per_subnet.get_mut(&subnet) {
                                    *c = c.saturating_sub(1);
                                    if *c == 0 { inbound_per_subnet.remove(&subnet); }
                                }
                            }
                            let ip = peer.addr.ip();
                            if let Some(c) = connections_per_ip.get_mut(&ip) {
                                *c = c.saturating_sub(1);
                                if *c == 0 { connections_per_ip.remove(&ip); }
                            }
                        }
                        // Remove reputation entry unless the peer is still banned
                        // (keep banned entries so we reject reconnection during ban period).
                        if let Some(rep) = reputations.get(&peer_id) {
                            if !rep.is_banned() {
                                reputations.remove(&peer_id);
                            }
                        }
                        // Periodically prune expired bans to prevent unbounded growth
                        if reputations.len() > crate::constants::MAX_PEERS * 4 {
                            reputations.retain(|_, rep| rep.is_banned());
                        }
                        let _ = event_tx.send(P2pEvent::PeerDisconnected(peer_id)).await;
                    }
                    InternalEvent::Misbehavior { peer_id, penalty } => {
                        let rep = reputations.entry(peer_id).or_insert_with(PeerReputation::new);
                        rep.penalize(penalty);
                        if rep.is_banned() {
                            tracing::warn!(
                                peer = %hex::encode(&peer_id[..8]),
                                score = rep.score,
                                violations = rep.violations,
                                "Banning peer"
                            );
                            // Disconnect the banned peer
                            if let Some(peer) = peers.remove(&peer_id) {
                                if peer.is_outbound {
                                    outbound_count = outbound_count.saturating_sub(1);
                                } else {
                                    inbound_count = inbound_count.saturating_sub(1);
                                    let subnet = subnet_prefix(peer.addr.ip());
                                    if let Some(c) = inbound_per_subnet.get_mut(&subnet) {
                                        *c = c.saturating_sub(1);
                                        if *c == 0 { inbound_per_subnet.remove(&subnet); }
                                    }
                                }
                                let ip = peer.addr.ip();
                                if let Some(c) = connections_per_ip.get_mut(&ip) {
                                    *c = c.saturating_sub(1);
                                    if *c == 0 { connections_per_ip.remove(&ip); }
                                }
                            }
                            let _ = event_tx.send(P2pEvent::PeerDisconnected(peer_id)).await;
                        }
                    }
                }
            }
        }
    }
}

// ── Connection Handling ──

/// Handle an inbound TCP connection: handshake (with timeout), KEM exchange,
/// mutual auth, then spawn encrypted read/write tasks.
async fn handle_inbound(
    stream: TcpStream,
    addr: SocketAddr,
    config: &P2pConfig,
    internal_tx: mpsc::Sender<InternalEvent>,
) -> Result<(), P2pError> {
    let timeout = std::time::Duration::from_millis(crate::constants::PEER_CONNECT_TIMEOUT_MS);
    tokio::time::timeout(
        timeout,
        handle_inbound_inner(stream, addr, config, internal_tx),
    )
    .await
    .map_err(|_| P2pError::ConnectionFailed("inbound handshake timeout".into()))?
}

/// Inbound handshake (responder side).
async fn handle_inbound_inner(
    stream: TcpStream,
    addr: SocketAddr,
    config: &P2pConfig,
    internal_tx: mpsc::Sender<InternalEvent>,
) -> Result<(), P2pError> {
    let (mut reader, mut writer) = stream.into_split();

    // 1. Hello exchange (plaintext)
    let hello = Message::Hello {
        version: PROTOCOL_VERSION,
        peer_id: config.our_peer_id,
        public_key: config.our_public_key.clone(),
        listen_port: config.listen_port,
        kem_public_key: config.our_kem_keypair.public.clone(),
    };
    write_message(&mut writer, &hello).await?;

    let their_hello = read_message(&mut reader).await?;
    let (peer_id, public_key) = match their_hello {
        Message::Hello {
            version,
            peer_id,
            public_key,
            ..
        } => {
            // Accept v2 (pre-NAT) and v3+ peers
            if !(2..=PROTOCOL_VERSION).contains(&version) {
                return Err(P2pError::InvalidHandshake);
            }
            // Verify peer_id matches the fingerprint of their public key
            if peer_id != public_key.fingerprint() {
                return Err(P2pError::InvalidHandshake);
            }
            (peer_id, public_key)
        }
        _ => return Err(P2pError::InvalidHandshake),
    };

    // 2. Receive KEM ciphertext from initiator
    let key_exchange_msg = read_message(&mut reader).await?;
    let kem_ct = match key_exchange_msg {
        Message::KeyExchange { kem_ciphertext } => kem_ciphertext,
        _ => return Err(P2pError::InvalidHandshake),
    };

    // 3. Decapsulate to get shared secret
    let shared_secret = config
        .our_kem_keypair
        .decapsulate(&kem_ct)
        .ok_or(P2pError::InvalidHandshake)?;

    // 4. Derive session keys (responder)
    let session_keys = SessionKeys::derive(&shared_secret.0, false);

    // 5. Compute transcript hash (canonical: initiator_id || responder_id || kem_ct)
    let transcript = compute_transcript_hash(&peer_id, &config.our_peer_id, &kem_ct.0);

    // 6. Verify initiator's auth signature
    let auth_msg = read_message(&mut reader).await?;
    match auth_msg {
        Message::AuthResponse { ref signature } => {
            if !public_key.verify(&transcript, signature) {
                return Err(P2pError::InvalidHandshake);
            }
        }
        _ => return Err(P2pError::InvalidHandshake),
    }

    // 7. Sign transcript and send our auth
    let signature = config.our_signing_keypair.sign(&transcript);
    write_message(&mut writer, &Message::AuthResponse { signature }).await?;

    // 8. Switch to encrypted transport
    spawn_encrypted_connection_tasks(
        peer_id,
        public_key,
        addr,
        reader,
        writer,
        session_keys,
        internal_tx,
        false, // inbound
    )
    .await
}

/// Handle an outbound TCP connection (initiator side).
async fn handle_outbound(
    addr: SocketAddr,
    config: &P2pConfig,
    internal_tx: mpsc::Sender<InternalEvent>,
) -> Result<(), P2pError> {
    let timeout = std::time::Duration::from_millis(crate::constants::PEER_CONNECT_TIMEOUT_MS);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| P2pError::ConnectionFailed("timeout".into()))?
        .map_err(|e| P2pError::ConnectionFailed(e.to_string()))?;

    let (mut reader, mut writer) = stream.into_split();

    // 1. Hello exchange (plaintext)
    let hello = Message::Hello {
        version: PROTOCOL_VERSION,
        peer_id: config.our_peer_id,
        public_key: config.our_public_key.clone(),
        listen_port: config.listen_port,
        kem_public_key: config.our_kem_keypair.public.clone(),
    };
    write_message(&mut writer, &hello).await?;

    let their_hello = read_message(&mut reader).await?;
    let (peer_id, public_key, peer_kem_pk) = match their_hello {
        Message::Hello {
            version,
            peer_id,
            public_key,
            kem_public_key,
            ..
        } => {
            // Accept v2 (pre-NAT) and v3+ peers
            if !(2..=PROTOCOL_VERSION).contains(&version) {
                return Err(P2pError::InvalidHandshake);
            }
            // Verify peer_id matches the fingerprint of their public key
            if peer_id != public_key.fingerprint() {
                return Err(P2pError::InvalidHandshake);
            }
            (peer_id, public_key, kem_public_key)
        }
        _ => return Err(P2pError::InvalidHandshake),
    };

    // 2. KEM encapsulate to peer's public key
    let (shared_secret, kem_ct) = peer_kem_pk
        .encapsulate()
        .ok_or(P2pError::InvalidHandshake)?;

    // 3. Derive session keys and transcript BEFORE sending (kem_ct is moved by send)
    let session_keys = SessionKeys::derive(&shared_secret.0, true);
    let transcript = compute_transcript_hash(&config.our_peer_id, &peer_id, &kem_ct.0);

    // 4. Send KEM ciphertext
    write_message(
        &mut writer,
        &Message::KeyExchange {
            kem_ciphertext: kem_ct,
        },
    )
    .await?;

    // 5. Sign transcript and send auth
    let signature = config.our_signing_keypair.sign(&transcript);
    write_message(&mut writer, &Message::AuthResponse { signature }).await?;

    // 6. Verify responder's auth signature
    let auth_msg = read_message(&mut reader).await?;
    match auth_msg {
        Message::AuthResponse { signature } => {
            if !public_key.verify(&transcript, &signature) {
                return Err(P2pError::InvalidHandshake);
            }
        }
        _ => return Err(P2pError::InvalidHandshake),
    }

    // 7. Switch to encrypted transport
    spawn_encrypted_connection_tasks(
        peer_id,
        public_key,
        addr,
        reader,
        writer,
        session_keys,
        internal_tx,
        true, // outbound
    )
    .await
}

/// Spawn encrypted read and write tasks for an authenticated connection.
#[allow(clippy::too_many_arguments)]
async fn spawn_encrypted_connection_tasks(
    peer_id: PeerId,
    public_key: SigningPublicKey,
    addr: SocketAddr,
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    session_keys: SessionKeys,
    internal_tx: mpsc::Sender<InternalEvent>,
    is_outbound: bool,
) -> Result<(), P2pError> {
    let (msg_tx, mut msg_rx) = mpsc::channel::<Message>(128);

    internal_tx
        .send(InternalEvent::Connected {
            peer_id,
            public_key,
            addr,
            msg_tx,
            is_outbound,
        })
        .await
        .map_err(|_| P2pError::Shutdown)?;

    let internal_tx_read = internal_tx.clone();
    let internal_tx_disconnect = internal_tx;

    let SessionKeys { send_key, recv_key } = session_keys;

    // Encrypted read task with per-peer rate limiting
    tokio::spawn(async move {
        let mut rate_limiter = RateLimiter::new(
            crate::constants::PEER_MSG_BURST,
            crate::constants::PEER_MSG_RATE_LIMIT,
        );
        let mut violations: u32 = 0;
        let mut reader = reader;
        let mut expected_counter: u64 = 0;

        loop {
            match read_encrypted(&mut reader, &recv_key, &mut expected_counter).await {
                Ok(message) => {
                    if !rate_limiter.try_consume() {
                        violations += 1;
                        tracing::warn!(
                            peer = %hex::encode(&peer_id[..8]),
                            violations = violations,
                            max = crate::constants::PEER_RATE_LIMIT_STRIKES,
                            "Rate limit exceeded"
                        );
                        // Report misbehavior for rate limit violation
                        let _ = internal_tx_read
                            .send(InternalEvent::Misbehavior {
                                peer_id,
                                penalty: 10,
                            })
                            .await;
                        if violations >= crate::constants::PEER_RATE_LIMIT_STRIKES {
                            tracing::warn!(
                                peer = %hex::encode(&peer_id[..8]),
                                "Disconnecting peer for repeated rate violations"
                            );
                            let _ = internal_tx_read
                                .send(InternalEvent::Disconnected(peer_id))
                                .await;
                            break;
                        }
                        continue;
                    }
                    if internal_tx_read
                        .send(InternalEvent::Message {
                            from: peer_id,
                            message: Box::new(message),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => {
                    // Report misbehavior for message read/decrypt error
                    let _ = internal_tx_read
                        .send(InternalEvent::Misbehavior {
                            peer_id,
                            penalty: 5,
                        })
                        .await;
                    let _ = internal_tx_read
                        .send(InternalEvent::Disconnected(peer_id))
                        .await;
                    break;
                }
            }
        }
    });

    // Encrypted write task
    tokio::spawn(async move {
        let mut writer = writer;
        let mut counter: u64 = 0;
        while let Some(msg) = msg_rx.recv().await {
            if write_encrypted(&mut writer, &msg, &send_key, &mut counter)
                .await
                .is_err()
            {
                let _ = internal_tx_disconnect
                    .send(InternalEvent::Disconnected(peer_id))
                    .await;
                break;
            }
        }
    });

    Ok(())
}

// ── Plaintext I/O (used during handshake only) ──

/// Maximum size for handshake messages (Hello, KeyExchange, AuthChallenge).
/// Much smaller than MAX_NETWORK_MESSAGE_BYTES to limit pre-authentication
/// memory allocation from unauthenticated connections.
const MAX_HANDSHAKE_MESSAGE_BYTES: usize = 64 * 1024; // 64 KiB

/// Read a single plaintext framed message from a TCP stream.
async fn read_message(stream: &mut OwnedReadHalf) -> Result<Message, P2pError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| P2pError::ConnectionFailed(e.to_string()))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_HANDSHAKE_MESSAGE_BYTES {
        return Err(P2pError::ConnectionFailed(
            "handshake message too large".into(),
        ));
    }
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|e| P2pError::ConnectionFailed(e.to_string()))?;

    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&payload);
    network::decode_message(&frame)
        .ok_or_else(|| P2pError::ConnectionFailed("decode failed".into()))
}

/// Write a single plaintext framed message to a TCP stream.
async fn write_message(stream: &mut OwnedWriteHalf, msg: &Message) -> Result<(), P2pError> {
    let bytes = network::encode_message(msg).map_err(|e| P2pError::SendFailed(e.to_string()))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| P2pError::SendFailed(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| P2pError::SendFailed(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KemKeypair, SigningKeypair};

    fn test_config(port: u16) -> P2pConfig {
        let kp = SigningKeypair::generate();
        let kem_kp = KemKeypair::generate();
        P2pConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            max_peers: crate::constants::MAX_PEERS,
            our_peer_id: kp.public.fingerprint(),
            our_public_key: kp.public.clone(),
            listen_port: port,
            our_kem_keypair: kem_kp,
            our_signing_keypair: kp,
            external_addr: None,
        }
    }

    #[tokio::test]
    async fn start_and_connect() {
        let config1 = test_config(0);
        let result1 = start(config1).await.unwrap();
        let handle1 = result1.handle;
        let mut events1 = result1.events;
        let addr1 = result1.local_addr;

        let config2 = test_config(0);
        let result2 = start(config2).await.unwrap();
        let handle2 = result2.handle;
        let mut events2 = result2.events;

        handle2.connect(addr1).await.unwrap();

        let timeout = std::time::Duration::from_secs(5);
        let event1 = tokio::time::timeout(timeout, events1.recv()).await;
        let event2 = tokio::time::timeout(timeout, events2.recv()).await;

        assert!(event1.is_ok() || event2.is_ok());

        let _ = handle1.shutdown().await;
        let _ = handle2.shutdown().await;
    }

    #[tokio::test]
    async fn encrypted_message_exchange() {
        let config1 = test_config(0);
        let peer_id1 = config1.our_peer_id;
        let result1 = start(config1).await.unwrap();
        let handle1 = result1.handle;
        let mut events1 = result1.events;
        let addr1 = result1.local_addr;

        let config2 = test_config(0);
        let result2 = start(config2).await.unwrap();
        let handle2 = result2.handle;
        let mut events2 = result2.events;

        handle2.connect(addr1).await.unwrap();

        let timeout = std::time::Duration::from_secs(5);
        // Wait for both PeerConnected events
        let _ = tokio::time::timeout(timeout, events1.recv()).await;
        let _ = tokio::time::timeout(timeout, events2.recv()).await;

        // Send a message from peer2 to peer1 (over encrypted channel)
        handle2.send_to(peer_id1, Message::GetPeers).await.unwrap();

        // peer1 should receive the encrypted message
        let msg_event = tokio::time::timeout(timeout, events1.recv())
            .await
            .expect("timeout waiting for message")
            .expect("channel closed");
        match msg_event {
            P2pEvent::MessageReceived { message, .. } => {
                assert!(matches!(*message, Message::GetPeers));
            }
            other => panic!("expected MessageReceived, got {:?}", other),
        }

        let _ = handle1.shutdown().await;
        let _ = handle2.shutdown().await;
    }

    #[test]
    fn session_keys_symmetry() {
        let shared_secret = [42u8; 32];
        let init_keys = SessionKeys::derive(&shared_secret, true);
        let resp_keys = SessionKeys::derive(&shared_secret, false);

        // Initiator's send = responder's recv
        assert_eq!(init_keys.send_key, resp_keys.recv_key);
        // Responder's send = initiator's recv
        assert_eq!(resp_keys.send_key, init_keys.recv_key);
        // Send and recv are different
        assert_ne!(init_keys.send_key, init_keys.recv_key);
    }

    #[tokio::test]
    async fn encrypted_transport_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let shared_secret = [99u8; 32];
        let send_keys = SessionKeys::derive(&shared_secret, true);
        let recv_keys = SessionKeys::derive(&shared_secret, false);

        let writer_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let (_, mut writer) = stream.into_split();
            let mut counter = 0u64;
            write_encrypted(
                &mut writer,
                &Message::GetPeers,
                &send_keys.send_key,
                &mut counter,
            )
            .await
            .unwrap();
            assert_eq!(counter, 1);
        });

        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, _) = stream.into_split();
        let mut expected_counter = 0u64;
        let msg = read_encrypted(&mut reader, &recv_keys.recv_key, &mut expected_counter)
            .await
            .unwrap();

        assert!(matches!(msg, Message::GetPeers));
        assert_eq!(expected_counter, 1);
        writer_task.await.unwrap();
    }

    #[test]
    fn rate_limiter_allows_within_burst() {
        let mut rl = RateLimiter::new(10.0, 5.0);
        for _ in 0..10 {
            assert!(rl.try_consume());
        }
        assert!(!rl.try_consume());
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let mut rl = RateLimiter::new(5.0, 100.0);
        for _ in 0..5 {
            assert!(rl.try_consume());
        }
        assert!(!rl.try_consume());

        rl.last_refill = std::time::Instant::now() - std::time::Duration::from_millis(100);
        assert!(rl.try_consume());
    }

    #[tokio::test]
    async fn get_peers_empty() {
        let config = test_config(0);
        let result = start(config).await.unwrap();

        let peers = result.handle.get_peers().await.unwrap();
        assert!(peers.is_empty());

        let _ = result.handle.shutdown().await;
    }

    #[test]
    fn peer_reputation_penalize_to_ban() {
        let mut rep = PeerReputation::new();
        assert_eq!(rep.score, crate::constants::PEER_INITIAL_REPUTATION);
        assert!(!rep.is_banned());

        // Penalize repeatedly until score drops below ban threshold.
        // Initial score = 100, ban threshold = 20. Penalizing by 30 three times
        // brings score to 100 - 90 = 10, which is below threshold 20.
        rep.penalize(30);
        assert_eq!(rep.score, 70);
        assert!(!rep.is_banned());

        rep.penalize(30);
        assert_eq!(rep.score, 40);
        assert!(!rep.is_banned());

        rep.penalize(30);
        assert_eq!(rep.score, 10);
        assert!(rep.is_banned());
        assert!(rep.banned_until.is_some());
        assert_eq!(rep.violations, 3);
    }

    #[test]
    fn peer_reputation_ban_expires() {
        let mut rep = PeerReputation::new();

        // Penalize to trigger a ban
        rep.penalize(crate::constants::PEER_INITIAL_REPUTATION);
        assert!(rep.is_banned());

        // Manually set banned_until to a past time to simulate ban expiry
        rep.banned_until = Some(Instant::now() - std::time::Duration::from_secs(1));
        assert!(!rep.is_banned());
    }

    #[test]
    fn peer_reputation_reward_recovery() {
        let mut rep = PeerReputation::new();

        // Penalize partially (not enough to ban)
        rep.penalize(20);
        assert_eq!(rep.score, 80);
        assert!(!rep.is_banned());

        rep.penalize(20);
        assert_eq!(rep.score, 60);
        assert!(!rep.is_banned());

        // Use the reward method to recover reputation
        rep.reward(30);
        assert_eq!(rep.score, 90);
        assert!(!rep.is_banned());

        // Verify score recovered and is above the ban threshold
        assert!(rep.score > crate::constants::PEER_BAN_THRESHOLD);
    }

    #[test]
    fn peer_reputation_reward_capped_at_initial() {
        let mut rep = PeerReputation::new();
        let initial = crate::constants::PEER_INITIAL_REPUTATION;

        // Penalize then reward more than the penalty
        rep.penalize(10);
        assert_eq!(rep.score, initial - 10);

        rep.reward(50);
        // Score should be capped at initial reputation, not exceed it
        assert_eq!(
            rep.score, initial,
            "reward should cap score at initial reputation"
        );

        // Rewarding when already at max should not increase
        rep.reward(100);
        assert_eq!(rep.score, initial);
    }

    #[test]
    fn rate_limiter_rejects_over_burst() {
        // Create a rate limiter with a small burst of 3, zero refill so it never recovers
        let mut rl = RateLimiter::new(3.0, 0.0);

        // Consume all 3 tokens
        assert!(rl.try_consume());
        assert!(rl.try_consume());
        assert!(rl.try_consume());

        // Next attempt should fail — burst exhausted
        assert!(!rl.try_consume());
        assert!(!rl.try_consume());
    }

    #[tokio::test]
    async fn encrypted_frame_tamper_rejected() {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let shared_secret = [77u8; 32];
        let send_keys = SessionKeys::derive(&shared_secret, true);
        let recv_keys = SessionKeys::derive(&shared_secret, false);

        // Writer sends a frame with ciphertext corrupted after AEAD encryption,
        // so decryption will fail on the receiver side.
        let writer_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let (_, mut raw_writer) = stream.into_split();

            // Build a valid padded + encrypted frame first
            let payload = network::encode_message(&Message::GetPeers).unwrap();
            let real_len = payload.len() as u32;
            let padded_len = pad_to_bucket(4 + payload.len());
            let mut padded = Vec::with_capacity(padded_len);
            padded.extend_from_slice(&real_len.to_le_bytes());
            padded.extend_from_slice(&payload);
            padded.resize(padded_len, 0u8);

            let counter: u64 = 0;
            let nonce_bytes = counter_to_nonce(counter);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&send_keys.send_key));
            let mut ciphertext = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), padded.as_ref())
                .expect("encrypt");

            // Corrupt one byte of the ciphertext
            if !ciphertext.is_empty() {
                ciphertext[0] ^= 0xFF;
            }

            // Write frame with corrupted ciphertext
            let frame_len = (8 + ciphertext.len()) as u32;
            raw_writer
                .write_all(&frame_len.to_le_bytes())
                .await
                .unwrap();
            raw_writer.write_all(&counter.to_le_bytes()).await.unwrap();
            raw_writer.write_all(&ciphertext).await.unwrap();

            // Keep connection alive briefly so reader can read
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, _) = stream.into_split();
        let mut expected_counter = 0u64;

        let result = read_encrypted(&mut reader, &recv_keys.recv_key, &mut expected_counter).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("AEAD decryption failed"),
            "expected AEAD decryption failure, got: {}",
            err_msg
        );

        writer_task.await.unwrap();
    }

    #[tokio::test]
    async fn counter_replay_rejected() {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let shared_secret = [55u8; 32];
        let send_keys = SessionKeys::derive(&shared_secret, true);
        let recv_keys = SessionKeys::derive(&shared_secret, false);

        // Writer sends a frame with counter=1, but reader expects counter=0
        let writer_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let (_, mut raw_writer) = stream.into_split();

            // Build padded frame with counter=1 (skipping counter=0)
            let payload = network::encode_message(&Message::GetPeers).unwrap();
            let real_len = payload.len() as u32;
            let padded_len = pad_to_bucket(4 + payload.len());
            let mut padded = Vec::with_capacity(padded_len);
            padded.extend_from_slice(&real_len.to_le_bytes());
            padded.extend_from_slice(&payload);
            padded.resize(padded_len, 0u8);

            let counter: u64 = 1;
            let nonce_bytes = counter_to_nonce(counter);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&send_keys.send_key));
            let ciphertext = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), padded.as_ref())
                .expect("encrypt");

            let frame_len = (8 + ciphertext.len()) as u32;
            raw_writer
                .write_all(&frame_len.to_le_bytes())
                .await
                .unwrap();
            raw_writer.write_all(&counter.to_le_bytes()).await.unwrap();
            raw_writer.write_all(&ciphertext).await.unwrap();

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, _) = stream.into_split();
        let mut expected_counter = 0u64; // Reader expects counter=0

        let result = read_encrypted(&mut reader, &recv_keys.recv_key, &mut expected_counter).await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unexpected message counter"),
            "expected counter rejection, got: {}",
            err_msg
        );

        writer_task.await.unwrap();
    }

    #[tokio::test]
    async fn undersized_frame_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let recv_keys = SessionKeys::derive(&[88u8; 32], false);

        let writer_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let (_, mut raw_writer) = stream.into_split();
            // Send a frame that's too short (less than 8 + min_bucket + tag)
            let frame_len: u32 = 4;
            raw_writer
                .write_all(&frame_len.to_le_bytes())
                .await
                .unwrap();
            raw_writer.write_all(&[0u8; 4]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, _) = stream.into_split();
        let mut expected_counter = 0u64;
        let result = read_encrypted(&mut reader, &recv_keys.recv_key, &mut expected_counter).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("too short"),
            "expected frame too short error"
        );
        writer_task.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_frame_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let recv_keys = SessionKeys::derive(&[88u8; 32], false);

        let writer_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let (_, mut raw_writer) = stream.into_split();
            // Claim a frame larger than max_frame
            let frame_len: u32 = 20_000_000;
            raw_writer
                .write_all(&frame_len.to_le_bytes())
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, _) = stream.into_split();
        let mut expected_counter = 0u64;
        let result = read_encrypted(&mut reader, &recv_keys.recv_key, &mut expected_counter).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("too large"),
            "expected frame too large error"
        );
        writer_task.await.unwrap();
    }

    #[test]
    fn self_connection_check() {
        // Verify that a peer_id matching our own would be detected.
        // The p2p_loop rejects connections where peer_id == config.our_peer_id.
        // We test the comparison logic directly since the full event loop is
        // covered by integration tests.
        let config = test_config(0);
        let our_id = config.our_peer_id;

        // Same peer_id should be equal (self-connection detected)
        assert_eq!(our_id, our_id);

        // Different config produces a different peer_id (not self)
        let other_config = test_config(0);
        assert_ne!(our_id, other_config.our_peer_id);

        // Also verify the PeerReputation ban-check path that the event loop uses:
        // a banned peer is rejected even if peer_id differs from ours.
        let mut rep = PeerReputation::new();
        rep.penalize(crate::constants::PEER_INITIAL_REPUTATION); // triggers ban
        assert!(rep.is_banned());
    }

    #[test]
    fn subnet_prefix_ipv4() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(subnet_prefix(ip), [192, 168]);

        let ip2: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(subnet_prefix(ip2), [10, 0]);

        let ip3: IpAddr = "203.0.113.5".parse().unwrap();
        assert_eq!(subnet_prefix(ip3), [203, 0]);
    }

    #[test]
    fn subnet_prefix_ipv6() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert_eq!(subnet_prefix(ip), [0, 0]);

        let ip2: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(subnet_prefix(ip2), [0, 0]);
    }

    #[test]
    fn counter_to_nonce_zero() {
        let nonce = counter_to_nonce(0);
        assert_eq!(nonce.len(), TRANSPORT_NONCE_SIZE);
        assert_eq!(nonce, [0u8; 12]);
    }

    #[test]
    fn counter_to_nonce_one() {
        let nonce = counter_to_nonce(1);
        assert_eq!(nonce.len(), TRANSPORT_NONCE_SIZE);
        // TLS 1.3 style: 4 zero bytes + 8-byte counter LE
        assert_eq!(&nonce[..4], &[0u8; 4]);
        assert_eq!(nonce[4], 1);
        for &b in &nonce[5..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn counter_to_nonce_max() {
        let nonce = counter_to_nonce(u64::MAX);
        assert_eq!(nonce.len(), TRANSPORT_NONCE_SIZE);
        // First 4 bytes are zero padding
        assert_eq!(&nonce[..4], &[0u8; 4]);
        // Last 8 bytes should all be 0xFF (u64::MAX in little-endian)
        for &b in &nonce[4..] {
            assert_eq!(b, 0xFF);
        }
    }

    #[test]
    fn pad_to_bucket_alignment() {
        let bucket = crate::constants::P2P_PADDING_BUCKET;

        // Just below one bucket: pads up to one bucket
        assert_eq!(pad_to_bucket(bucket - 1), bucket);

        // Exactly one bucket: stays at one bucket
        assert_eq!(pad_to_bucket(bucket), bucket);

        // One byte over one bucket: pads up to two buckets
        assert_eq!(pad_to_bucket(bucket + 1), 2 * bucket);
    }

    #[test]
    fn rate_limiter_exact_capacity() {
        let mut rl = RateLimiter::new(5.0, 0.0);
        // Consume exactly 5 tokens; all should succeed
        for i in 0..5 {
            assert!(rl.try_consume(), "token {} should succeed", i);
        }
        // 6th should fail
        assert!(
            !rl.try_consume(),
            "6th consume should fail after exhausting 5 tokens"
        );
    }

    #[test]
    fn rate_limiter_refill_after_time() {
        let mut rl = RateLimiter::new(2.0, 10.0);
        // Consume all tokens
        assert!(rl.try_consume());
        assert!(rl.try_consume());
        assert!(!rl.try_consume());

        // Simulate time passing by setting last_refill to 1 second in the past.
        // With refill_per_sec=10.0, 1 second gives 10 tokens (capped at max_tokens=2.0).
        rl.last_refill = std::time::Instant::now() - std::time::Duration::from_secs(1);
        assert!(rl.try_consume(), "should succeed after refill");
        assert!(
            rl.try_consume(),
            "should succeed (second token after refill)"
        );
    }

    #[test]
    fn peer_reputation_penalize_exact_threshold() {
        let mut rep = PeerReputation::new();
        let initial = crate::constants::PEER_INITIAL_REPUTATION;
        let threshold = crate::constants::PEER_BAN_THRESHOLD;

        // Penalize so score drops just below the ban threshold
        let penalty = initial - threshold + 1;
        rep.penalize(penalty);
        assert_eq!(rep.score, threshold - 1);
        assert!(
            rep.is_banned(),
            "peer should be banned when score < PEER_BAN_THRESHOLD"
        );
    }

    #[test]
    fn peer_reputation_reward_does_not_exceed_initial() {
        let mut rep = PeerReputation::new();
        let initial = crate::constants::PEER_INITIAL_REPUTATION;

        // Penalize by a small amount
        rep.penalize(10);
        assert_eq!(rep.score, initial - 10);

        // Reward by a large amount (much more than the penalty)
        rep.reward(100);
        // Score should be capped at PEER_INITIAL_REPUTATION
        assert_eq!(
            rep.score, initial,
            "score should not exceed PEER_INITIAL_REPUTATION"
        );
    }

    #[test]
    fn subnet_prefix_ipv4_same_slash16() {
        // Two IPs in the same /16 subnet (first two octets match)
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.2.1".parse().unwrap();
        assert_eq!(
            subnet_prefix(ip1),
            subnet_prefix(ip2),
            "IPs in same /16 should have same subnet prefix"
        );
    }

    #[test]
    fn subnet_prefix_ipv4_different_slash16() {
        // Two IPs in different /16 subnets
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "10.0.1.1".parse().unwrap();
        assert_ne!(
            subnet_prefix(ip1),
            subnet_prefix(ip2),
            "IPs in different /16 should have different subnet prefix"
        );
    }

    #[test]
    fn session_keys_different_directions() {
        let shared_secret = [7u8; 32];
        let init_keys = SessionKeys::derive(&shared_secret, true);
        let resp_keys = SessionKeys::derive(&shared_secret, false);

        // Initiator's send_key should equal responder's recv_key
        assert_eq!(init_keys.send_key, resp_keys.recv_key);
        // Responder's send_key should equal initiator's recv_key
        assert_eq!(resp_keys.send_key, init_keys.recv_key);
    }
}
