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

use crate::consensus::bft::{Certificate, EquivocationEvidence, Vote};
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

    /// Equivocation evidence: proof a validator voted for two vertices in one round
    BftEquivocationEvidence(EquivocationEvidence),

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

    // ── Snapshot Sync ──
    /// Request a state snapshot manifest from a peer.
    GetSnapshot,

    /// Response with snapshot manifest describing the available state snapshot.
    SnapshotManifest {
        meta: crate::node::storage::ChainStateMeta,
        total_chunks: u32,
        snapshot_size: u64,
    },

    /// Request a specific chunk of the snapshot.
    GetSnapshotChunk { chunk_index: u32 },

    /// Response with a snapshot chunk (raw bytes of serialized SnapshotData).
    SnapshotChunk {
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
    },

    // ── NAT Traversal (v3) ──
    /// Post-handshake NAT info exchange (sent over encrypted channel).
    /// Contains our claimed external address and what we observe as the peer's address.
    NatInfo {
        external_addr: Option<String>,
        observed_addr: String,
    },

    /// Request a rendezvous peer to help us connect to a NATted target.
    NatPunchRequest {
        target_peer_id: PeerId,
        requester_external_addr: String,
    },

    /// Notification from a rendezvous peer that someone wants to connect to us.
    NatPunchNotify {
        requester_peer_id: PeerId,
        requester_external_addr: String,
    },

    // ── Transport Rekeying (v4) ──
    /// Request a session rekey with a new Kyber KEM ciphertext.
    /// Sent over the existing encrypted channel for forward secrecy.
    RekeyRequest { kem_ciphertext: KemCiphertext },

    /// Acknowledge a rekey request. The receiver has derived new session keys.
    RekeyAck,
}

/// Information about a known peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub public_key: SigningPublicKey,
    pub address: String,
    pub last_seen: u64,
}

/// Protocol version (v3: encrypted transport + NAT traversal).
pub const PROTOCOL_VERSION: u32 = 3;

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
    fn snapshot_messages_roundtrip() {
        // GetSnapshot
        let msg = Message::GetSnapshot;
        let bytes = encode_message(&msg).unwrap();
        assert!(matches!(
            decode_message(&bytes).unwrap(),
            Message::GetSnapshot
        ));

        // SnapshotManifest
        let meta = crate::node::storage::ChainStateMeta {
            epoch: 5,
            last_finalized: None,
            state_root: [1u8; 32],
            commitment_root: [2u8; 32],
            commitment_count: 100,
            nullifier_count: 50,
            nullifier_hash: [3u8; 32],
            epoch_fees: 0,
            validator_count: 10,
            epoch_seed: [4u8; 32],
            finalized_count: 42,
            total_minted: 500_000,
        };
        let msg = Message::SnapshotManifest {
            meta,
            total_chunks: 3,
            snapshot_size: 12_000_000,
        };
        let bytes = encode_message(&msg).unwrap();
        match decode_message(&bytes).unwrap() {
            Message::SnapshotManifest {
                meta: m,
                total_chunks,
                snapshot_size,
            } => {
                assert_eq!(m.epoch, 5);
                assert_eq!(m.finalized_count, 42);
                assert_eq!(total_chunks, 3);
                assert_eq!(snapshot_size, 12_000_000);
            }
            _ => panic!("wrong message type"),
        }

        // GetSnapshotChunk
        let msg = Message::GetSnapshotChunk { chunk_index: 2 };
        let bytes = encode_message(&msg).unwrap();
        match decode_message(&bytes).unwrap() {
            Message::GetSnapshotChunk { chunk_index } => assert_eq!(chunk_index, 2),
            _ => panic!("wrong message type"),
        }

        // SnapshotChunk
        let msg = Message::SnapshotChunk {
            chunk_index: 1,
            total_chunks: 3,
            data: vec![0xAB; 100],
        };
        let bytes = encode_message(&msg).unwrap();
        match decode_message(&bytes).unwrap() {
            Message::SnapshotChunk {
                chunk_index,
                total_chunks,
                data,
            } => {
                assert_eq!(chunk_index, 1);
                assert_eq!(total_chunks, 3);
                assert_eq!(data.len(), 100);
                assert_eq!(data[0], 0xAB);
            }
            _ => panic!("wrong message type"),
        }
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

    #[test]
    fn equivocation_evidence_roundtrip() {
        use crate::consensus::bft::{EquivocationEvidence, VoteType};
        use crate::consensus::dag::VertexId;

        let kp = SigningKeypair::generate();
        let vertex1 = VertexId([1u8; 32]);
        let vertex2 = VertexId([2u8; 32]);

        let evidence = EquivocationEvidence {
            voter_id: kp.public.fingerprint(),
            epoch: 3,
            round: 7,
            first_vertex: vertex1,
            second_vertex: vertex2,
            first_vote_type: VoteType::Accept,
            second_vote_type: VoteType::Accept,
            first_signature: kp.sign(b"vote1"),
            second_signature: kp.sign(b"vote2"),
        };

        let msg = Message::BftEquivocationEvidence(evidence);
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        match decoded {
            Message::BftEquivocationEvidence(e) => {
                assert_eq!(e.epoch, 3);
                assert_eq!(e.round, 7);
                assert_eq!(e.first_vertex.0, [1u8; 32]);
                assert_eq!(e.second_vertex.0, [2u8; 32]);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn bft_vote_roundtrip() {
        use crate::consensus::bft::{vote_sign_data, VoteType};
        use crate::consensus::dag::VertexId;

        let kp = SigningKeypair::generate();
        let chain_id = crate::hash_domain(b"test", b"chain");
        let vertex_id = VertexId([42u8; 32]);
        let msg_data = vote_sign_data(&vertex_id, 3, 7, &VoteType::Accept, &chain_id);
        let sig = kp.sign(&msg_data);
        let vote = Vote {
            vertex_id,
            voter_id: kp.public.fingerprint(),
            epoch: 3,
            round: 7,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };
        let msg = Message::BftVote(vote);
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        match decoded {
            Message::BftVote(v) => {
                assert_eq!(v.epoch, 3);
                assert_eq!(v.round, 7);
                assert_eq!(v.vertex_id, vertex_id);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn key_exchange_roundtrip() {
        let kem_kp = KemKeypair::generate();
        let (_, ct) = kem_kp.public.encapsulate().unwrap();
        let msg = Message::KeyExchange {
            kem_ciphertext: ct.clone(),
        };
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        match decoded {
            Message::KeyExchange { kem_ciphertext } => {
                assert_eq!(kem_ciphertext.as_bytes(), ct.as_bytes());
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn auth_response_roundtrip() {
        let kp = SigningKeypair::generate();
        let sig = kp.sign(b"transcript");
        let msg = Message::AuthResponse {
            signature: sig.clone(),
        };
        let bytes = encode_message(&msg).unwrap();
        let decoded = decode_message(&bytes).unwrap();
        match decoded {
            Message::AuthResponse { signature } => {
                assert_eq!(signature.as_bytes(), sig.as_bytes());
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn get_vertex_and_get_tips_roundtrip() {
        let vid = VertexId([99u8; 32]);
        let msg = Message::GetVertex(vid);
        let bytes = encode_message(&msg).unwrap();
        match decode_message(&bytes).unwrap() {
            Message::GetVertex(id) => assert_eq!(id, vid),
            _ => panic!("wrong message type"),
        }

        let msg = Message::GetTips;
        let bytes = encode_message(&msg).unwrap();
        assert!(matches!(decode_message(&bytes).unwrap(), Message::GetTips));
    }

    #[test]
    fn get_transaction_roundtrip() {
        let tx_hash = [0xABu8; 32];
        let msg = Message::GetTransaction(tx_hash);
        let bytes = encode_message(&msg).unwrap();
        match decode_message(&bytes).unwrap() {
            Message::GetTransaction(h) => assert_eq!(h, tx_hash),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn nat_info_roundtrip() {
        let msg = Message::NatInfo {
            external_addr: Some("203.0.113.5:9732".to_string()),
            observed_addr: "198.51.100.1:54321".to_string(),
        };
        let bytes = encode_message(&msg).unwrap();
        match decode_message(&bytes).unwrap() {
            Message::NatInfo {
                external_addr,
                observed_addr,
            } => {
                assert_eq!(external_addr.as_deref(), Some("203.0.113.5:9732"));
                assert_eq!(observed_addr, "198.51.100.1:54321");
            }
            _ => panic!("wrong message type"),
        }

        // Also test with no external addr
        let msg = Message::NatInfo {
            external_addr: None,
            observed_addr: "10.0.0.1:9732".to_string(),
        };
        let bytes = encode_message(&msg).unwrap();
        match decode_message(&bytes).unwrap() {
            Message::NatInfo {
                external_addr,
                observed_addr,
            } => {
                assert!(external_addr.is_none());
                assert_eq!(observed_addr, "10.0.0.1:9732");
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn nat_punch_request_roundtrip() {
        let peer_id = [42u8; 32];
        let msg = Message::NatPunchRequest {
            target_peer_id: peer_id,
            requester_external_addr: "203.0.113.5:9732".to_string(),
        };
        let bytes = encode_message(&msg).unwrap();
        match decode_message(&bytes).unwrap() {
            Message::NatPunchRequest {
                target_peer_id,
                requester_external_addr,
            } => {
                assert_eq!(target_peer_id, peer_id);
                assert_eq!(requester_external_addr, "203.0.113.5:9732");
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn nat_punch_notify_roundtrip() {
        let peer_id = [99u8; 32];
        let msg = Message::NatPunchNotify {
            requester_peer_id: peer_id,
            requester_external_addr: "198.51.100.1:9732".to_string(),
        };
        let bytes = encode_message(&msg).unwrap();
        match decode_message(&bytes).unwrap() {
            Message::NatPunchNotify {
                requester_peer_id,
                requester_external_addr,
            } => {
                assert_eq!(requester_peer_id, peer_id);
                assert_eq!(requester_external_addr, "198.51.100.1:9732");
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn decode_empty_buffer_returns_none() {
        assert!(decode_message(&[]).is_none());
    }

    #[test]
    fn decode_short_buffer_returns_none() {
        assert!(decode_message(&[1, 2]).is_none());
    }

    #[test]
    fn decode_truncated_payload_returns_none() {
        // Length says 100 bytes but only 10 bytes of payload
        let len_bytes = 100u32.to_le_bytes();
        let mut data = Vec::new();
        data.extend_from_slice(&len_bytes);
        data.extend_from_slice(&[0u8; 10]);
        assert!(decode_message(&data).is_none());
    }

    #[test]
    fn decode_corrupted_payload_returns_none() {
        // Valid length but garbage payload
        let len_bytes = 8u32.to_le_bytes();
        let mut data = Vec::new();
        data.extend_from_slice(&len_bytes);
        data.extend_from_slice(&[0xFF; 8]);
        assert!(decode_message(&data).is_none());
    }

    #[test]
    fn new_transaction_roundtrip() {
        use crate::crypto::commitment::Commitment;
        use crate::crypto::encryption::EncryptedPayload;
        use crate::crypto::keys::KemCiphertext;
        use crate::crypto::nullifier::Nullifier;
        use crate::crypto::stark::types::{BalanceStarkProof, SpendStarkProof};
        use crate::crypto::stealth::StealthAddress;
        use crate::transaction::{Transaction, TxInput, TxOutput, TxType};

        // Use correct sizes for crypto types (Kyber1024 ciphertext = 1568 bytes)
        let kem_ct = KemCiphertext(vec![0u8; 1568]);

        let tx = Transaction {
            inputs: vec![TxInput {
                nullifier: Nullifier([1u8; 32]),
                proof_link: [2u8; 32],
                spend_proof: SpendStarkProof {
                    proof_bytes: vec![3],
                    public_inputs_bytes: vec![4],
                },
            }],
            outputs: vec![TxOutput {
                commitment: Commitment([5u8; 32]),
                stealth_address: StealthAddress {
                    one_time_key: [6u8; 32],
                    kem_ciphertext: kem_ct.clone(),
                },
                encrypted_note: EncryptedPayload {
                    kem_ciphertext: KemCiphertext(vec![0u8; 1568]),
                    nonce: [9u8; 24],
                    ciphertext: vec![10],
                },
                blake3_binding: [11u8; 64],
            }],
            fee: 100,
            chain_id: [0u8; 32],
            expiry_epoch: 0,
            balance_proof: BalanceStarkProof {
                proof_bytes: vec![],
                public_inputs_bytes: vec![],
            },
            messages: vec![],
            tx_binding: [0u8; 32],
            tx_type: TxType::Transfer,
        };
        let msg = Message::NewTransaction(tx.clone());
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        match decoded {
            Message::NewTransaction(decoded_tx) => {
                assert_eq!(decoded_tx.fee, 100);
                assert_eq!(decoded_tx.inputs.len(), 1);
            }
            _ => panic!("expected NewTransaction"),
        }
    }

    #[test]
    fn encode_decode_preserves_all_message_variants() {
        // Test simple parameterless variants
        let msg = Message::GetTips;
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert!(matches!(decoded, Message::GetTips));

        let msg = Message::GetPeers;
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert!(matches!(decoded, Message::GetPeers));

        let msg = Message::GetSnapshot;
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert!(matches!(decoded, Message::GetSnapshot));

        let msg = Message::GetEpochState;
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert!(matches!(decoded, Message::GetEpochState));
    }

    #[test]
    fn rekey_request_roundtrip() {
        use crate::crypto::keys::KemCiphertext;
        let msg = Message::RekeyRequest {
            kem_ciphertext: KemCiphertext(vec![0xABu8; 1568]),
        };
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        match decoded {
            Message::RekeyRequest { kem_ciphertext } => {
                assert_eq!(kem_ciphertext.as_bytes().len(), 1568);
                assert_eq!(kem_ciphertext.as_bytes()[0], 0xAB);
            }
            _ => panic!("expected RekeyRequest"),
        }
    }

    #[test]
    fn rekey_ack_roundtrip() {
        let msg = Message::RekeyAck;
        let encoded = encode_message(&msg).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert!(matches!(decoded, Message::RekeyAck));
    }
}
