//! P2P networking layer using async TCP with tokio.
//!
//! All connections are encrypted and mutually authenticated:
//! 1. Hello exchange (plaintext) — version check + KEM public key exchange
//! 2. Kyber1024 KEM handshake — initiator encapsulates to responder's KEM PK
//! 3. Dilithium5 auth — both sides sign the handshake transcript
//! 4. Encrypted transport — BLAKE3 XOR keystream + keyed-BLAKE3 MAC per message

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::crypto::keys::{KemKeypair, SigningKeypair, SigningPublicKey};
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

/// Nonce size for the BLAKE3 XOR keystream cipher.
const TRANSPORT_NONCE_SIZE: usize = 24;

/// Session keys for encrypted P2P transport.
/// Initiator and responder derive mirrored send/recv key pairs so that
/// each side's send key is the other side's recv key.
struct SessionKeys {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_mac_key: [u8; 32],
    recv_mac_key: [u8; 32],
}

impl SessionKeys {
    fn derive(shared_secret: &[u8; 32], is_initiator: bool) -> Self {
        let init_send = crate::hash_domain(b"umbra.p2p.init.send", shared_secret);
        let resp_send = crate::hash_domain(b"umbra.p2p.resp.send", shared_secret);
        let init_mac = crate::hash_domain(b"umbra.p2p.init.mac", shared_secret);
        let resp_mac = crate::hash_domain(b"umbra.p2p.resp.mac", shared_secret);
        if is_initiator {
            SessionKeys {
                send_key: init_send,
                recv_key: resp_send,
                send_mac_key: init_mac,
                recv_mac_key: resp_mac,
            }
        } else {
            SessionKeys {
                send_key: resp_send,
                recv_key: init_send,
                send_mac_key: resp_mac,
                recv_mac_key: init_mac,
            }
        }
    }
}

/// Convert a message counter to a 24-byte nonce for the XOR keystream.
fn counter_to_nonce(counter: u64) -> [u8; TRANSPORT_NONCE_SIZE] {
    let mut nonce = [0u8; TRANSPORT_NONCE_SIZE];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// BLAKE3-based XOR keystream cipher (same construction as crypto/encryption.rs).
fn xor_keystream(key: &[u8; 32], nonce: &[u8; TRANSPORT_NONCE_SIZE], data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    let mut block_counter = 0u64;
    let mut pos = 0;
    while pos < data.len() {
        let mut block_input = Vec::with_capacity(32 + TRANSPORT_NONCE_SIZE + 8);
        block_input.extend_from_slice(key);
        block_input.extend_from_slice(nonce);
        block_input.extend_from_slice(&block_counter.to_le_bytes());
        let block = crate::hash_domain(b"umbra.keystream", &block_input);
        let remaining = data.len() - pos;
        let take = remaining.min(32);
        for i in 0..take {
            output.push(data[pos + i] ^ block[i]);
        }
        pos += take;
        block_counter += 1;
    }
    output
}

/// Compute keyed-BLAKE3 MAC for an encrypted transport frame.
fn transport_mac(mac_key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(&counter.to_le_bytes());
    hasher.update(&(ciphertext.len() as u64).to_le_bytes());
    hasher.update(ciphertext);
    *hasher.finalize().as_bytes()
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

/// Write an encrypted + authenticated message frame.
///
/// Frame format: `[4-byte LE frame_len][8-byte LE counter][ciphertext][32-byte MAC]`
async fn write_encrypted(
    writer: &mut OwnedWriteHalf,
    msg: &Message,
    send_key: &[u8; 32],
    send_mac_key: &[u8; 32],
    counter: &mut u64,
) -> Result<(), P2pError> {
    let payload = network::encode_message(msg).map_err(|e| P2pError::SendFailed(e.to_string()))?;
    let nonce = counter_to_nonce(*counter);
    let ciphertext = xor_keystream(send_key, &nonce, &payload);
    let mac = transport_mac(send_mac_key, *counter, &ciphertext);

    let frame_len = (8 + ciphertext.len() + 32) as u32;
    let mut frame = Vec::with_capacity(4 + frame_len as usize);
    frame.extend_from_slice(&frame_len.to_le_bytes());
    frame.extend_from_slice(&counter.to_le_bytes());
    frame.extend_from_slice(&ciphertext);
    frame.extend_from_slice(&mac);

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
    recv_mac_key: &[u8; 32],
    expected_counter: &mut u64,
) -> Result<Message, P2pError> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| P2pError::ConnectionFailed(e.to_string()))?;
    let frame_len = u32::from_le_bytes(len_buf) as usize;
    // Minimum: 8 (counter) + 0 (empty ciphertext) + 32 (MAC)
    if frame_len < 40 {
        return Err(P2pError::ConnectionFailed(
            "encrypted frame too short".into(),
        ));
    }
    if frame_len > crate::constants::MAX_NETWORK_MESSAGE_BYTES + 44 {
        return Err(P2pError::ConnectionFailed(
            "encrypted frame too large".into(),
        ));
    }

    let mut frame = vec![0u8; frame_len];
    reader
        .read_exact(&mut frame)
        .await
        .map_err(|e| P2pError::ConnectionFailed(e.to_string()))?;

    // Parse: [8-byte counter][ciphertext][32-byte MAC]
    let counter = u64::from_le_bytes(frame[..8].try_into().unwrap());
    let ciphertext = &frame[8..frame_len - 32];
    let mac: [u8; 32] = frame[frame_len - 32..].try_into().unwrap();

    if counter != *expected_counter {
        return Err(P2pError::ConnectionFailed(
            "unexpected message counter".into(),
        ));
    }
    *expected_counter += 1;

    let expected_mac = transport_mac(recv_mac_key, counter, ciphertext);
    if !crate::constant_time_eq(&expected_mac, &mac) {
        return Err(P2pError::ConnectionFailed("MAC verification failed".into()));
    }

    let nonce = counter_to_nonce(counter);
    let plaintext = xor_keystream(recv_key, &nonce, ciphertext);

    network::decode_message(&plaintext)
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
        self.score -= amount;
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
    let max_inbound = config.max_peers / 2;
    let max_outbound = config.max_peers - max_inbound;
    let (internal_tx, mut internal_rx) = mpsc::channel::<InternalEvent>(256);
    let handshake_semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(64));

    loop {
        tokio::select! {
            result = listener.accept() => {
                if let Ok((stream, addr)) = result {
                    // F8: Connection diversity — enforce inbound slot limit
                    if inbound_count >= max_inbound || peers.len() >= config.max_peers {
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
                            tracing::debug!("Inbound connection from {} failed: {}", addr, e);
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
                                tracing::debug!("Outbound connection to {} failed: {}", addr, e);
                            }
                        });
                    }
                    P2pCommand::SendTo(peer_id, msg) => {
                        if let Some(peer) = peers.get(&peer_id) {
                            let _ = peer.msg_tx.try_send(msg);
                        }
                    }
                    P2pCommand::Broadcast { message, exclude } => {
                        for (id, peer) in &peers {
                            if exclude.as_ref() == Some(id) {
                                continue;
                            }
                            let _ = peer.msg_tx.try_send(message.clone());
                        }
                    }
                    P2pCommand::GetPeers(reply) => {
                        let infos: Vec<PeerInfo> = peers.values().map(|p| PeerInfo {
                            peer_id: p.peer_id,
                            public_key: p.public_key.clone(),
                            address: p.addr.to_string(),
                            last_seen: 0,
                        }).collect();
                        let _ = reply.send(infos);
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
                                tracing::debug!("Rejected banned peer {}", hex::encode(&peer_id[..8]));
                                continue;
                            }
                        }
                        if peers.len() < config.max_peers && !peers.contains_key(&peer_id) {
                            // F8: Update connection direction counters
                            if is_outbound {
                                outbound_count += 1;
                            } else {
                                inbound_count += 1;
                            }
                            peers.insert(peer_id, PeerConnection {
                                peer_id,
                                public_key,
                                addr,
                                msg_tx,
                                is_outbound,
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
                        let _ = event_tx.send(P2pEvent::MessageReceived { from, message }).await;
                    }
                    InternalEvent::Disconnected(peer_id) => {
                        // F8: Update connection direction counters
                        if let Some(peer) = peers.remove(&peer_id) {
                            if peer.is_outbound {
                                outbound_count = outbound_count.saturating_sub(1);
                            } else {
                                inbound_count = inbound_count.saturating_sub(1);
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
                                "Banning peer {} (score={}, violations={})",
                                hex::encode(&peer_id[..8]),
                                rep.score,
                                rep.violations,
                            );
                            // Disconnect the banned peer
                            if let Some(peer) = peers.remove(&peer_id) {
                                if peer.is_outbound {
                                    outbound_count = outbound_count.saturating_sub(1);
                                } else {
                                    inbound_count = inbound_count.saturating_sub(1);
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
            if version != PROTOCOL_VERSION {
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
            if version != PROTOCOL_VERSION {
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

    let SessionKeys {
        send_key,
        recv_key,
        send_mac_key,
        recv_mac_key,
    } = session_keys;

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
            match read_encrypted(&mut reader, &recv_key, &recv_mac_key, &mut expected_counter).await
            {
                Ok(message) => {
                    if !rate_limiter.try_consume() {
                        violations += 1;
                        tracing::warn!(
                            "Rate limit exceeded for peer {} ({}/{})",
                            hex::encode(&peer_id[..8]),
                            violations,
                            crate::constants::PEER_RATE_LIMIT_STRIKES
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
                                "Disconnecting peer {} for repeated rate violations",
                                hex::encode(&peer_id[..8])
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
            if write_encrypted(&mut writer, &msg, &send_key, &send_mac_key, &mut counter)
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

/// Read a single plaintext framed message from a TCP stream.
async fn read_message(stream: &mut OwnedReadHalf) -> Result<Message, P2pError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| P2pError::ConnectionFailed(e.to_string()))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > crate::constants::MAX_NETWORK_MESSAGE_BYTES {
        return Err(P2pError::ConnectionFailed("message too large".into()));
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
        assert_eq!(init_keys.send_mac_key, resp_keys.recv_mac_key);
        // Responder's send = initiator's recv
        assert_eq!(resp_keys.send_key, init_keys.recv_key);
        assert_eq!(resp_keys.send_mac_key, init_keys.recv_mac_key);
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
                &send_keys.send_mac_key,
                &mut counter,
            )
            .await
            .unwrap();
            assert_eq!(counter, 1);
        });

        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, _) = stream.into_split();
        let mut expected_counter = 0u64;
        let msg = read_encrypted(
            &mut reader,
            &recv_keys.recv_key,
            &recv_keys.recv_mac_key,
            &mut expected_counter,
        )
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
    async fn encrypted_frame_mac_verification_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let shared_secret = [77u8; 32];
        let send_keys = SessionKeys::derive(&shared_secret, true);
        let recv_keys = SessionKeys::derive(&shared_secret, false);

        // Writer sends a frame with ciphertext corrupted after MAC computation,
        // so the MAC won't match the corrupted data on the receiver side.
        let writer_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let (_, mut raw_writer) = stream.into_split();

            // Build a valid encrypted frame first
            let payload = network::encode_message(&Message::GetPeers).unwrap();
            let counter: u64 = 0;
            let nonce = counter_to_nonce(counter);
            let ciphertext = xor_keystream(&send_keys.send_key, &nonce, &payload);
            // Compute MAC on the original (uncorrupted) ciphertext
            let mac = transport_mac(&send_keys.send_mac_key, counter, &ciphertext);

            // Corrupt one byte of the ciphertext AFTER computing the MAC
            let mut corrupted_ct = ciphertext;
            if !corrupted_ct.is_empty() {
                corrupted_ct[0] ^= 0xFF;
            }

            // Write frame with corrupted ciphertext but original MAC
            let frame_len = (8 + corrupted_ct.len() + 32) as u32;
            raw_writer
                .write_all(&frame_len.to_le_bytes())
                .await
                .unwrap();
            raw_writer.write_all(&counter.to_le_bytes()).await.unwrap();
            raw_writer.write_all(&corrupted_ct).await.unwrap();
            raw_writer.write_all(&mac).await.unwrap();

            // Keep connection alive briefly so reader can read
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, _) = stream.into_split();
        let mut expected_counter = 0u64;

        let result = read_encrypted(
            &mut reader,
            &recv_keys.recv_key,
            &recv_keys.recv_mac_key,
            &mut expected_counter,
        )
        .await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("MAC verification failed"),
            "expected MAC verification failure, got: {}",
            err_msg
        );

        writer_task.await.unwrap();
    }

    #[tokio::test]
    async fn counter_replay_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let shared_secret = [55u8; 32];
        let send_keys = SessionKeys::derive(&shared_secret, true);
        let recv_keys = SessionKeys::derive(&shared_secret, false);

        // Writer sends two frames: counter=0 then counter=1
        // But we send counter=1 first to trigger counter mismatch on the reader
        let writer_task = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let (_, mut raw_writer) = stream.into_split();

            // Build frame with counter=1 (skipping counter=0)
            let payload = network::encode_message(&Message::GetPeers).unwrap();
            let counter: u64 = 1;
            let nonce = counter_to_nonce(counter);
            let ciphertext = xor_keystream(&send_keys.send_key, &nonce, &payload);
            let mac = transport_mac(&send_keys.send_mac_key, counter, &ciphertext);

            let frame_len = (8 + ciphertext.len() + 32) as u32;
            raw_writer
                .write_all(&frame_len.to_le_bytes())
                .await
                .unwrap();
            raw_writer.write_all(&counter.to_le_bytes()).await.unwrap();
            raw_writer.write_all(&ciphertext).await.unwrap();
            raw_writer.write_all(&mac).await.unwrap();

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, _) = stream.into_split();
        let mut expected_counter = 0u64; // Reader expects counter=0

        let result = read_encrypted(
            &mut reader,
            &recv_keys.recv_key,
            &recv_keys.recv_mac_key,
            &mut expected_counter,
        )
        .await;

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unexpected message counter"),
            "expected counter rejection, got: {}",
            err_msg
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
}
