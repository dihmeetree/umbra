//! P2P networking layer using async TCP with tokio.
//!
//! Uses the existing `network::Message` framing (4-byte LE length prefix + bincode).
//! Architecture: channel-based communication between the application and the P2P
//! event loop via `P2pHandle` (commands) and `P2pEvent` (events).

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::crypto::keys::SigningPublicKey;
use crate::network::{self, Message, PeerId, PeerInfo, PROTOCOL_VERSION};
use crate::Hash;

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
#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub listen_addr: SocketAddr,
    pub max_peers: usize,
    pub our_peer_id: Hash,
    pub our_public_key: SigningPublicKey,
    pub listen_port: u16,
}

/// State for a single peer connection.
struct PeerConnection {
    peer_id: PeerId,
    #[allow(dead_code)]
    public_key: SigningPublicKey,
    addr: SocketAddr,
    msg_tx: mpsc::Sender<Message>,
}

/// Internal event from connection tasks to the main P2P loop.
enum InternalEvent {
    /// A connection completed handshake.
    Connected {
        peer_id: PeerId,
        public_key: SigningPublicKey,
        addr: SocketAddr,
        msg_tx: mpsc::Sender<Message>,
    },
    /// A message was received from a peer.
    Message { from: PeerId, message: Message },
    /// A peer disconnected.
    Disconnected(PeerId),
}

impl P2pHandle {
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

/// Result of starting the P2P layer.
pub struct P2pStartResult {
    pub handle: P2pHandle,
    pub events: mpsc::Receiver<P2pEvent>,
    /// The actual bound address (useful when listening on port 0).
    pub local_addr: SocketAddr,
}

/// Start the P2P networking layer.
///
/// Returns a handle for sending commands, a receiver for events, and the
/// actual bound address.
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
    let (internal_tx, mut internal_rx) = mpsc::channel::<InternalEvent>(256);

    loop {
        tokio::select! {
            // Accept incoming connections
            result = listener.accept() => {
                if let Ok((stream, addr)) = result {
                    if peers.len() >= config.max_peers {
                        continue;
                    }
                    let config_clone = config.clone();
                    let internal_tx_clone = internal_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_inbound(stream, addr, &config_clone, internal_tx_clone).await {
                            tracing::debug!("Inbound connection from {} failed: {}", addr, e);
                        }
                    });
                }
            }

            // Handle commands from application
            Some(cmd) = command_rx.recv() => {
                match cmd {
                    P2pCommand::Connect(addr) => {
                        if peers.len() >= config.max_peers {
                            continue;
                        }
                        let config_clone = config.clone();
                        let internal_tx_clone = internal_tx.clone();
                        tokio::spawn(async move {
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

            // Handle internal events from connection tasks
            Some(event) = internal_rx.recv() => {
                match event {
                    InternalEvent::Connected { peer_id, public_key, addr, msg_tx } => {
                        if peers.len() < config.max_peers && !peers.contains_key(&peer_id) {
                            peers.insert(peer_id, PeerConnection {
                                peer_id,
                                public_key,
                                addr,
                                msg_tx,
                            });
                            let _ = event_tx.send(P2pEvent::PeerConnected(peer_id)).await;
                        }
                    }
                    InternalEvent::Message { from, message } => {
                        let _ = event_tx.send(P2pEvent::MessageReceived { from, message: Box::new(message) }).await;
                    }
                    InternalEvent::Disconnected(peer_id) => {
                        peers.remove(&peer_id);
                        let _ = event_tx.send(P2pEvent::PeerDisconnected(peer_id)).await;
                    }
                }
            }
        }
    }
}

/// Handle an inbound TCP connection: perform handshake, then spawn read/write tasks.
async fn handle_inbound(
    stream: TcpStream,
    addr: SocketAddr,
    config: &P2pConfig,
    internal_tx: mpsc::Sender<InternalEvent>,
) -> Result<(), P2pError> {
    let (mut reader, mut writer) = tokio::io::split(stream);

    // Send our Hello
    let hello = Message::Hello {
        version: PROTOCOL_VERSION,
        peer_id: config.our_peer_id,
        public_key: config.our_public_key.clone(),
        listen_port: config.listen_port,
    };
    write_message(&mut writer, &hello).await?;

    // Read their Hello
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

    spawn_connection_tasks(peer_id, public_key, addr, reader, writer, internal_tx).await
}

/// Handle an outbound TCP connection: connect, perform handshake, spawn tasks.
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

    let (mut reader, mut writer) = tokio::io::split(stream);

    // Send our Hello
    let hello = Message::Hello {
        version: PROTOCOL_VERSION,
        peer_id: config.our_peer_id,
        public_key: config.our_public_key.clone(),
        listen_port: config.listen_port,
    };
    write_message(&mut writer, &hello).await?;

    // Read their Hello
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

    spawn_connection_tasks(peer_id, public_key, addr, reader, writer, internal_tx).await
}

/// Spawn read and write tasks for an established connection.
async fn spawn_connection_tasks(
    peer_id: PeerId,
    public_key: SigningPublicKey,
    addr: SocketAddr,
    mut reader: tokio::io::ReadHalf<TcpStream>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
    internal_tx: mpsc::Sender<InternalEvent>,
) -> Result<(), P2pError> {
    let (msg_tx, mut msg_rx) = mpsc::channel::<Message>(128);

    // Notify that connection is established
    internal_tx
        .send(InternalEvent::Connected {
            peer_id,
            public_key,
            addr,
            msg_tx,
        })
        .await
        .map_err(|_| P2pError::Shutdown)?;

    let internal_tx_read = internal_tx.clone();
    let internal_tx_disconnect = internal_tx;

    // Read task
    tokio::spawn(async move {
        loop {
            match read_message(&mut reader).await {
                Ok(message) => {
                    if internal_tx_read
                        .send(InternalEvent::Message {
                            from: peer_id,
                            message,
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => {
                    let _ = internal_tx_read
                        .send(InternalEvent::Disconnected(peer_id))
                        .await;
                    break;
                }
            }
        }
    });

    // Write task
    tokio::spawn(async move {
        while let Some(msg) = msg_rx.recv().await {
            if write_message(&mut writer, &msg).await.is_err() {
                let _ = internal_tx_disconnect
                    .send(InternalEvent::Disconnected(peer_id))
                    .await;
                break;
            }
        }
    });

    Ok(())
}

/// Read a single framed message from a TCP stream.
async fn read_message(stream: &mut tokio::io::ReadHalf<TcpStream>) -> Result<Message, P2pError> {
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

    // Build the full frame for decode_message
    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&payload);
    network::decode_message(&frame)
        .ok_or_else(|| P2pError::ConnectionFailed("decode failed".into()))
}

/// Write a single framed message to a TCP stream.
async fn write_message(
    stream: &mut tokio::io::WriteHalf<TcpStream>,
    msg: &Message,
) -> Result<(), P2pError> {
    let bytes = network::encode_message(msg).map_err(|e| P2pError::SendFailed(e.to_string()))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| P2pError::SendFailed(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::SigningKeypair;

    fn test_config(port: u16) -> P2pConfig {
        let kp = SigningKeypair::generate();
        P2pConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            max_peers: crate::constants::MAX_PEERS,
            our_peer_id: kp.public.fingerprint(),
            our_public_key: kp.public,
            listen_port: port,
        }
    }

    #[tokio::test]
    async fn start_and_connect() {
        let config1 = test_config(0); // OS-assigned port
        let result1 = start(config1).await.unwrap();
        let handle1 = result1.handle;
        let mut events1 = result1.events;
        let addr1 = result1.local_addr;

        let config2 = test_config(0);
        let result2 = start(config2).await.unwrap();
        let handle2 = result2.handle;
        let mut events2 = result2.events;

        // Connect peer2 to peer1's actual bound address
        handle2.connect(addr1).await.unwrap();

        // Both should get PeerConnected events
        let timeout = std::time::Duration::from_secs(2);
        let event1 = tokio::time::timeout(timeout, events1.recv()).await;
        let event2 = tokio::time::timeout(timeout, events2.recv()).await;

        // At least one side should see a connection event
        assert!(event1.is_ok() || event2.is_ok());

        let _ = handle1.shutdown().await;
        let _ = handle2.shutdown().await;
    }

    #[tokio::test]
    async fn get_peers_empty() {
        let config = test_config(0);
        let result = start(config).await.unwrap();

        let peers = result.handle.get_peers().await.unwrap();
        assert!(peers.is_empty());

        let _ = result.handle.shutdown().await;
    }
}
