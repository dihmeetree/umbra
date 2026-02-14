//! Network protocol message definitions for Umbra P2P communication.
//!
//! Defines the wire protocol messages exchanged between nodes.
//!
//! # Transport security
//!
//! All P2P connections are encrypted and authenticated:
//! - **KEM handshake**: Kyber1024 key encapsulation establishes a shared secret.
//! - **Mutual authentication**: Dilithium5 signatures over the handshake
//!   transcript prove both peers' identities.
//! - **Stream encryption**: BLAKE3-based XOR keystream cipher with per-message
//!   counters and keyed-BLAKE3 MACs protect confidentiality and integrity.

use serde::{Deserialize, Serialize};

use crate::consensus::bft::{Certificate, Vote};
use crate::consensus::dag::{Vertex, VertexId};
use crate::crypto::keys::{KemCiphertext, KemPublicKey, Signature, SigningPublicKey};
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
    /// Announce ourselves to a peer (includes KEM public key for encrypted transport)
    Hello {
        version: u32,
        peer_id: PeerId,
        public_key: SigningPublicKey,
        listen_port: u16,
        kem_public_key: KemPublicKey,
    },

    // ── Encrypted Transport Handshake ──
    /// KEM ciphertext for establishing encrypted transport
    KeyExchange { kem_ciphertext: KemCiphertext },

    /// Signed transcript proving peer identity
    AuthResponse { signature: Signature },

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

    // ── State Sync ──
    /// Request finalized vertices after a given sequence number
    GetFinalizedVertices { after_sequence: u64, limit: u32 },

    /// Response with a batch of finalized vertices
    FinalizedVerticesResponse {
        vertices: Vec<(u64, Box<Vertex>)>,
        has_more: bool,
        total_finalized: u64,
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

/// Protocol version (v2: encrypted transport with KEM + auth).
pub const PROTOCOL_VERSION: u32 = 2;

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
fn bincode_config() -> bincode::config::Configuration<
    bincode::config::LittleEndian,
    bincode::config::Fixint,
    bincode::config::Limit<{ 16 * 1024 * 1024 }>,
> {
    bincode::config::legacy().with_limit::<{ 16 * 1024 * 1024 }>()
}

/// Serialize a message to bytes (length-prefixed).
///
/// Returns an error if serialization fails or the encoded message exceeds
/// `MAX_NETWORK_MESSAGE_BYTES`.
pub fn encode_message(msg: &Message) -> Result<Vec<u8>, NetworkError> {
    let payload = bincode::serde::encode_to_vec(msg, bincode_config())
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
    if data.len() < 4usize.saturating_add(len) {
        return None;
    }
    let (msg, _) = bincode::serde::decode_from_slice(&data[4..4 + len], bincode_config()).ok()?;
    Some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{KemKeypair, SigningKeypair};

    #[test]
    fn message_roundtrip() {
        let kp = SigningKeypair::generate();
        let kem_kp = KemKeypair::generate();
        let msg = Message::Hello {
            version: PROTOCOL_VERSION,
            peer_id: kp.public.fingerprint(),
            public_key: kp.public,
            listen_port: 9000,
            kem_public_key: kem_kp.public,
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

    #[test]
    fn get_finalized_vertices_roundtrip() {
        let msg = Message::GetFinalizedVertices {
            after_sequence: 42,
            limit: 100,
        };
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        match decoded {
            Message::GetFinalizedVertices {
                after_sequence,
                limit,
            } => {
                assert_eq!(after_sequence, 42);
                assert_eq!(limit, 100);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn finalized_vertices_response_roundtrip() {
        let msg = Message::FinalizedVerticesResponse {
            vertices: vec![],
            has_more: false,
            total_finalized: 500,
        };
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        match decoded {
            Message::FinalizedVerticesResponse {
                vertices,
                has_more,
                total_finalized,
            } => {
                assert!(vertices.is_empty());
                assert!(!has_more);
                assert_eq!(total_finalized, 500);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn peers_response_roundtrip() {
        let kp = SigningKeypair::generate();
        let peer = PeerInfo {
            peer_id: kp.public.fingerprint(),
            public_key: kp.public,
            address: "127.0.0.1:9732".to_string(),
            last_seen: 12345,
        };
        let msg = Message::PeersResponse(vec![peer]);
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        match decoded {
            Message::PeersResponse(peers) => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].address, "127.0.0.1:9732");
                assert_eq!(peers[0].last_seen, 12345);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn get_peers_roundtrip() {
        let msg = Message::GetPeers;
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        assert!(matches!(decoded, Message::GetPeers));
    }

    #[test]
    fn epoch_state_response_roundtrip() {
        let msg = Message::EpochStateResponse {
            epoch: 5,
            committee: vec![[1u8; 32], [2u8; 32]],
            commitment_root: [3u8; 32],
            nullifier_count: 100,
        };
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        match decoded {
            Message::EpochStateResponse {
                epoch,
                committee,
                nullifier_count,
                ..
            } => {
                assert_eq!(epoch, 5);
                assert_eq!(committee.len(), 2);
                assert_eq!(nullifier_count, 100);
            }
            _ => panic!("wrong message type"),
        }
    }
}
