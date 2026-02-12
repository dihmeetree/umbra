//! Network protocol message definitions for Spectra P2P communication.
//!
//! Defines the wire protocol messages exchanged between nodes.
//!
//! # Transport security (H2, H3)
//!
//! The current transport is plaintext TCP. Production deployment MUST add:
//! - **Authentication**: Verify peer identity via Dilithium5 signature
//!   challenge-response during the Hello handshake.
//! - **Encryption**: Use a Kyber1024 KEM handshake to establish a shared
//!   secret, then encrypt the TCP stream (e.g., Noise_KK pattern with
//!   post-quantum KEM, or a simple BLAKE3-based stream cipher similar to
//!   the transaction encryption module).
//!
//! Until transport encryption is implemented, the protocol relies on
//! application-layer authentication (signed votes, signed vertices) for
//! integrity of consensus-critical messages.

use bincode::Options;
use serde::{Deserialize, Serialize};

use crate::consensus::bft::{Certificate, Vote};
use crate::consensus::dag::{Vertex, VertexId};
use crate::crypto::keys::SigningPublicKey;
use crate::transaction::Transaction;
use crate::Hash;

/// A peer identifier (fingerprint of their signing key).
pub type PeerId = Hash;

/// Network protocol messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    // ── Transaction Pool ──
    /// Broadcast a new transaction to the mempool
    NewTransaction(Transaction),

    /// Request a transaction by its ID
    GetTransaction(Hash),

    /// Response with a requested transaction
    TransactionResponse(Option<Transaction>),

    // ── DAG Sync ──
    /// Announce a new vertex
    NewVertex(Box<Vertex>),

    /// Request a vertex by its ID
    GetVertex(VertexId),

    /// Response with a requested vertex
    VertexResponse(Option<Box<Vertex>>),

    /// Request all tip vertex IDs
    GetTips,

    /// Response with current tip IDs
    TipsResponse(Vec<VertexId>),

    // ── Consensus ──
    /// A BFT vote from a committee member
    BftVote(Vote),

    /// A finality certificate for a vertex
    BftCertificate(Certificate),

    // ── Peer Discovery ──
    /// Announce ourselves to a peer
    Hello {
        version: u32,
        peer_id: PeerId,
        public_key: SigningPublicKey,
        listen_port: u16,
    },

    /// Request known peers
    GetPeers,

    /// Response with known peer addresses
    PeersResponse(Vec<PeerInfo>),

    // ── Epoch Sync ──
    /// Request the current epoch state
    GetEpochState,

    /// Response with epoch info
    EpochStateResponse {
        epoch: u64,
        committee: Vec<Hash>,
        commitment_root: Hash,
        nullifier_count: u64,
    },
}

/// Information about a known peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub public_key: SigningPublicKey,
    pub address: String,
    pub last_seen: u64,
}

/// Protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Network errors.
#[derive(Clone, Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("message serialization failed: {0}")]
    SerializationFailed(String),
    #[error(
        "message exceeds maximum size ({} bytes)",
        crate::constants::MAX_NETWORK_MESSAGE_BYTES
    )]
    MessageTooLarge,
}

/// Size-limited bincode config used for both serialization and deserialization.
/// Prevents allocation-based DoS from crafted length prefixes within payloads.
fn bincode_config() -> impl bincode::Options {
    bincode::DefaultOptions::new().with_limit(crate::constants::MAX_NETWORK_MESSAGE_BYTES as u64)
}

/// Serialize a message to bytes (length-prefixed).
///
/// Returns an error if serialization fails or the encoded message exceeds
/// `MAX_NETWORK_MESSAGE_BYTES`.
pub fn encode_message(msg: &Message) -> Result<Vec<u8>, NetworkError> {
    let payload = bincode_config()
        .serialize(msg)
        .map_err(|e| NetworkError::SerializationFailed(e.to_string()))?;
    if payload.len() > crate::constants::MAX_NETWORK_MESSAGE_BYTES {
        return Err(NetworkError::MessageTooLarge);
    }
    let len = (payload.len() as u32).to_le_bytes();
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Deserialize a message from bytes (after length prefix).
///
/// Rejects messages whose declared length exceeds `MAX_NETWORK_MESSAGE_BYTES`
/// to prevent allocation-based DoS.
pub fn decode_message(data: &[u8]) -> Option<Message> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
    if len > crate::constants::MAX_NETWORK_MESSAGE_BYTES {
        return None;
    }
    if data.len() < 4 + len {
        return None;
    }
    bincode_config().deserialize(&data[4..4 + len]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::SigningKeypair;

    #[test]
    fn message_roundtrip() {
        let kp = SigningKeypair::generate();
        let msg = Message::Hello {
            version: PROTOCOL_VERSION,
            peer_id: kp.public.fingerprint(),
            public_key: kp.public,
            listen_port: 9000,
        };
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();

        match decoded {
            Message::Hello {
                version,
                listen_port,
                ..
            } => {
                assert_eq!(version, PROTOCOL_VERSION);
                assert_eq!(listen_port, 9000);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn decode_rejects_oversized_length() {
        // Craft a buffer with an absurdly large length prefix
        let len_bytes = (u32::MAX).to_le_bytes();
        let mut data = Vec::new();
        data.extend_from_slice(&len_bytes);
        data.extend_from_slice(&[0u8; 10]);
        assert!(decode_message(&data).is_none());
    }
}
