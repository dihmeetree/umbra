//! # Umbra
//!
//! A post-quantum private cryptocurrency with:
//! - **DAG-BFT consensus** — not PoW, not PoS; instant deterministic finality
//! - **Post-quantum security** — CRYSTALS-Dilithium signatures + CRYSTALS-Kyber KEM
//! - **Full privacy** — stealth addresses, nullifier-based spend privacy, confidential amounts
//! - **No trusted setup** — all proofs are transparent (zk-STARK compatible)
//! - **Encrypted messaging** — send arbitrary encrypted messages within transactions
//! - **Scalability** — DAG structure enables parallel transaction processing

pub mod config;
pub mod consensus;
pub mod crypto;
pub mod demo;
pub mod network;
pub mod node;
pub mod state;
pub mod transaction;
pub mod wallet;

/// Protocol constants
pub mod constants {
    /// Maximum transaction message size in bytes (64 KiB)
    pub const MAX_MESSAGE_SIZE: usize = 65_536;
    /// Number of validators in each BFT committee
    pub const COMMITTEE_SIZE: usize = 21;
    /// Minimum committee size for BFT safety (need at least 4 for f=1)
    pub const MIN_COMMITTEE_SIZE: usize = 4;
    /// Minimum bond required to become a validator (in base units)
    pub const VALIDATOR_BOND: u64 = 1_000_000;
    /// Maximum transactions per DAG vertex
    pub const MAX_TXS_PER_VERTEX: usize = 10_000;
    /// Target vertex interval in milliseconds
    pub const VERTEX_INTERVAL_MS: u64 = 500;
    /// Maximum allowed future drift for vertex timestamps (seconds).
    /// Vertices with timestamps more than this far ahead of the receiver's
    /// clock are rejected on insertion.
    pub const MAX_VERTEX_TIMESTAMP_DRIFT_SECS: u64 = 60;
    /// BFT quorum threshold: 2f+1 where f = (COMMITTEE_SIZE-1)/3
    pub const BFT_QUORUM: usize = (COMMITTEE_SIZE * 2) / 3 + 1;
    /// Epoch length in vertices before committee rotation
    pub const EPOCH_LENGTH: u64 = 1000;
    /// Maximum number of parent references per DAG vertex
    pub const MAX_PARENTS: usize = 8;
    /// Maximum network message size (16 MiB)
    pub const MAX_NETWORK_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
    /// Maximum plaintext size for encryption (1 MiB)
    pub const MAX_ENCRYPT_PLAINTEXT: usize = 1024 * 1024;
    /// Maximum number of encrypted messages per transaction
    pub const MAX_MESSAGES_PER_TX: usize = 16;
    /// Canonical Merkle tree depth for commitment trees
    pub const MERKLE_DEPTH: usize = 20;
    /// Number of bits for value range proofs
    pub const RANGE_BITS: usize = 59;
    /// Maximum inputs or outputs per transaction.
    ///
    /// Constrained by the range proof system: with RANGE_BITS = 59, the maximum
    /// safe sum is MAX_TX_IO * 2^59 which must be < p (Goldilocks prime ≈ 2^64).
    /// floor(p / 2^59) = 32, so 16 per side is conservative and safe.
    pub const MAX_TX_IO: usize = 16;

    /// Maximum number of transactions in the mempool
    pub const MEMPOOL_MAX_TXS: usize = 10_000;
    /// Maximum total byte size of the mempool (50 MiB)
    pub const MEMPOOL_MAX_BYTES: usize = 50 * 1024 * 1024;
    /// Default P2P listen port
    pub const DEFAULT_P2P_PORT: u16 = 9732;
    /// Default RPC listen port
    pub const DEFAULT_RPC_PORT: u16 = 9733;
    /// Maximum number of connected peers
    pub const MAX_PEERS: usize = 64;
    /// Vertex proposal interval in milliseconds
    pub const VERTEX_PROPOSAL_INTERVAL_MS: u64 = 500;
    /// Peer connection timeout in milliseconds
    pub const PEER_CONNECT_TIMEOUT_MS: u64 = 5_000;
    /// Maximum transactions to drain from mempool per vertex proposal
    pub const VERTEX_MAX_DRAIN: usize = 1_000;

    /// Batch size for vertex sync requests
    pub const SYNC_BATCH_SIZE: u32 = 100;
    /// Timeout for sync requests in milliseconds
    pub const SYNC_REQUEST_TIMEOUT_MS: u64 = 30_000;

    /// Maximum messages per second from a single peer (token bucket refill rate).
    pub const PEER_MSG_RATE_LIMIT: f64 = 100.0;
    /// Maximum burst size for per-peer rate limiting.
    pub const PEER_MSG_BURST: f64 = 200.0;
    /// Number of rate limit violations before disconnecting a peer.
    pub const PEER_RATE_LIMIT_STRIKES: u32 = 5;

    /// Cooldown in milliseconds before retrying a failed sync peer.
    pub const SYNC_PEER_COOLDOWN_MS: u64 = 60_000;

    /// Chunk size for snapshot transfer (4 MiB per chunk).
    /// Must be less than MAX_NETWORK_MESSAGE_BYTES minus serialization overhead.
    pub const SNAPSHOT_CHUNK_SIZE: usize = 4 * 1024 * 1024;
    /// Minimum finalized vertex gap before preferring snapshot sync over vertex sync.
    pub const SNAPSHOT_SYNC_THRESHOLD: u64 = 500;
    /// TTL for cached serialized snapshot on the serving node (seconds).
    pub const SNAPSHOT_CACHE_TTL_SECS: u64 = 120;

    /// View change timeout: if no finalization within this many proposal
    /// intervals, broadcast GetTips to discover missing state.
    pub const VIEW_CHANGE_TIMEOUT_INTERVALS: u64 = 10;
    /// Maximum round lag from peers before triggering re-sync.
    pub const MAX_ROUND_LAG: u64 = 5;

    /// Peer exchange interval in milliseconds (F5: peer discovery gossip).
    pub const PEER_EXCHANGE_INTERVAL_MS: u64 = 60_000;
    /// Maximum new peers to connect per discovery round (F5).
    pub const PEER_DISCOVERY_MAX: usize = 5;

    /// Padding bucket size (bytes) for encrypted P2P frames. Messages are padded
    /// to the next multiple of this value to resist traffic analysis.
    pub const P2P_PADDING_BUCKET: usize = 512;

    /// Number of Dandelion++ stem hops before fluffing (F6).
    pub const DANDELION_STEM_HOPS: u8 = 2;
    /// Dandelion++ stem timeout in milliseconds (F6).
    pub const DANDELION_TIMEOUT_MS: u64 = 5_000;
    /// Maximum entries in the Dandelion++ stem_txs tracking map.
    pub const MAX_STEM_TXS: usize = 5_000;
    /// Minimum random delay (ms) before Dandelion++ stem forwarding (anti-timing).
    pub const DANDELION_STEM_DELAY_MIN_MS: u64 = 100;
    /// Maximum random delay (ms) before Dandelion++ stem forwarding (anti-timing).
    pub const DANDELION_STEM_DELAY_MAX_MS: u64 = 500;

    /// Initial reputation score for new peers (F7).
    pub const PEER_INITIAL_REPUTATION: i32 = 100;
    /// Reputation threshold below which a peer is banned (F7).
    pub const PEER_BAN_THRESHOLD: i32 = 20;
    /// Duration of a peer ban in seconds (F7).
    pub const PEER_BAN_DURATION_SECS: u64 = 3600;
    /// Reputation penalty for a rate-limit violation (F7).
    pub const PEER_PENALTY_RATE_LIMIT: i32 = 10;
    /// Reputation penalty for an invalid message (F7).
    pub const PEER_PENALTY_INVALID_MSG: i32 = 20;
    /// Reputation penalty for a handshake failure (F7).
    pub const PEER_PENALTY_HANDSHAKE_FAIL: i32 = 30;

    /// Number of epochs of finalized data to retain in memory (F12).
    pub const PRUNING_RETAIN_EPOCHS: u64 = 100;

    /// Current protocol version for upgrade signaling (F16).
    pub const PROTOCOL_VERSION_ID: u32 = 1;
    /// Threshold fraction (numerator) for protocol upgrade activation (F16).
    /// Activation requires > UPGRADE_THRESHOLD_NUM / UPGRADE_THRESHOLD_DEN signals.
    pub const UPGRADE_THRESHOLD_NUM: u64 = 75;
    /// Threshold fraction (denominator) for protocol upgrade activation (F16).
    pub const UPGRADE_THRESHOLD_DEN: u64 = 100;
    /// Maximum distinct protocol versions tracked per epoch (F16).
    pub const MAX_VERSION_SIGNALS: usize = 64;

    // ── DDoS Protection ──

    /// Maximum connections allowed from a single IP address.
    pub const MAX_CONNECTIONS_PER_IP: usize = 4;
    /// Maximum inbound connections from the same /16 subnet (eclipse mitigation).
    pub const MAX_PEERS_PER_SUBNET: usize = 8;
    /// Maximum number of recently-attempted peer addresses to track.
    pub const MAX_RECENTLY_ATTEMPTED: usize = 1_000;
    /// Maximum snapshot chunks (caps buffer allocation: 256 × 4 MiB = 1 GiB).
    pub const MAX_SNAPSHOT_CHUNKS: u32 = 256;
    /// Minimum interval between snapshot chunk requests from the same peer (ms).
    pub const SNAPSHOT_CHUNK_REQUEST_INTERVAL_MS: u64 = 100;

    // ── NAT Traversal ──

    /// Timeout for UPnP gateway discovery in milliseconds.
    pub const UPNP_TIMEOUT_MS: u64 = 5_000;
    /// UPnP port mapping lease duration in seconds (1 hour).
    pub const UPNP_LEASE_DURATION_SECS: u32 = 3_600;
    /// UPnP lease renewal interval in seconds (~50 min, before 1hr lease expires).
    pub const UPNP_RENEWAL_INTERVAL_SECS: u64 = 3_000;
    /// Number of unique peers that must report the same external IP before we trust it.
    pub const NAT_OBSERVED_ADDR_QUORUM: usize = 3;
    /// Timeout for a hole punch attempt in milliseconds.
    pub const HOLE_PUNCH_TIMEOUT_MS: u64 = 5_000;
    /// Delay between hole punch retry attempts in milliseconds.
    pub const HOLE_PUNCH_RETRY_DELAY_MS: u64 = 500;
    /// Maximum number of hole punch connection attempts.
    pub const HOLE_PUNCH_MAX_ATTEMPTS: u32 = 3;

    /// Minimum transaction fee (in base units).
    ///
    /// Enforced by `validate_structure()` to prevent zero-fee spam. Coinbase or
    /// genesis funding should add outputs directly to state rather than going
    /// through transaction validation.
    pub const MIN_TX_FEE: u64 = 1;

    /// Maximum transaction fee in base units.
    ///
    /// Prevents fee-based overflow/saturation attacks on epoch fee accumulators.
    pub const MAX_TX_FEE: u64 = 10_000_000_000;

    /// Initial block (vertex) reward in base units.
    pub const INITIAL_BLOCK_REWARD: u64 = 50_000;

    /// Halving interval in epochs. The block reward halves every this many epochs.
    pub const HALVING_INTERVAL_EPOCHS: u64 = 500;

    /// Maximum number of halvings before reward becomes zero.
    pub const MAX_HALVINGS: u32 = 63;

    /// Genesis mint amount — initial coins created for the genesis validator.
    pub const GENESIS_MINT: u64 = 100_000_000;

    /// Compute the block reward for a given epoch.
    pub fn block_reward_for_epoch(epoch: u64) -> u64 {
        let halvings = epoch / HALVING_INTERVAL_EPOCHS;
        if halvings > MAX_HALVINGS as u64 {
            return 0;
        }
        INITIAL_BLOCK_REWARD >> halvings as u32
    }

    /// Compute the chain ID for mainnet.
    pub fn chain_id() -> crate::Hash {
        crate::hash_domain(b"umbra.chain_id", b"umbra-mainnet-v1")
    }
}

/// 32-byte hash used throughout the protocol
pub type Hash = [u8; 32];

/// Compute a domain-separated BLAKE3 hash.
///
/// L1: Takes `&[u8]` rather than `&str` for ergonomics with `b""` literals.
/// The domain MUST be valid UTF-8 (all Umbra domains use ASCII).
/// Panics at runtime if domain is not valid UTF-8 — this is a programming error.
pub fn hash_domain(domain: &[u8], data: &[u8]) -> Hash {
    let domain_str = std::str::from_utf8(domain).expect("hash_domain: domain must be valid UTF-8");
    let mut hasher = blake3::Hasher::new_derive_key(domain_str);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Compute BLAKE3 hash of length-prefixed concatenated slices.
///
/// Each part is prefixed with its length as a little-endian u64, preventing
/// ambiguous concatenation (e.g., `["AB","C"]` vs `["A","BC"]`).
pub fn hash_concat(parts: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Constant-time comparison of two byte slices.
///
/// Returns true only if the slices have equal length and identical contents.
/// Uses the `subtle` crate's audited constant-time operations.
///
/// Note: The length comparison is NOT constant-time (leaks whether lengths match).
/// This is acceptable because all Umbra uses compare fixed-size 32-byte hashes.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Serialize a value using bincode with legacy (v1-compatible) encoding.
pub fn serialize<T: serde::Serialize>(val: &T) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(val, bincode::config::legacy())
}

/// Deserialize a value using bincode with legacy (v1-compatible) encoding.
///
/// Rejects inputs larger than `MAX_NETWORK_MESSAGE_BYTES` to prevent OOM
/// from malicious oversized payloads.
pub fn deserialize<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, bincode::error::DecodeError> {
    if bytes.len() > constants::MAX_NETWORK_MESSAGE_BYTES {
        return Err(bincode::error::DecodeError::LimitExceeded);
    }
    let (val, _len) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())?;
    Ok(val)
}

/// Deserialize a reassembled snapshot blob.
///
/// Unlike `deserialize`, this does NOT enforce `MAX_NETWORK_MESSAGE_BYTES`
/// since a snapshot is assembled locally from multiple network chunks and
/// may legitimately exceed the per-message limit.
pub fn deserialize_snapshot<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, bincode::error::DecodeError> {
    let (val, _len) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())?;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_domain_deterministic() {
        let a = hash_domain(b"umbra.test", b"hello");
        let b = hash_domain(b"umbra.test", b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_domain_different_domains() {
        let a = hash_domain(b"umbra.domain_a", b"data");
        let b = hash_domain(b"umbra.domain_b", b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_concat_deterministic() {
        let a = hash_concat(&[b"hello", b"world"]);
        let b = hash_concat(&[b"hello", b"world"]);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_concat_length_prefix_prevents_ambiguity() {
        let ab_c = hash_concat(&[b"ab", b"c"]);
        let a_bc = hash_concat(&[b"a", b"bc"]);
        assert_ne!(ab_c, a_bc);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn deserialize_rejects_oversized_input() {
        // Create a payload larger than MAX_NETWORK_MESSAGE_BYTES
        let oversized = vec![0u8; constants::MAX_NETWORK_MESSAGE_BYTES + 1];
        let result = deserialize::<Vec<u8>>(&oversized);
        assert!(result.is_err(), "oversized input should be rejected");
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let original: Vec<u8> = vec![1, 2, 3, 4, 5];
        let bytes = serialize(&original).unwrap();
        let restored: Vec<u8> = deserialize(&bytes).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn blinding_factor_debug_redacted() {
        let bf = crate::crypto::commitment::BlindingFactor::from_bytes([42u8; 32]);
        let debug_str = format!("{:?}", bf);
        assert!(
            debug_str.contains("REDACTED"),
            "BlindingFactor debug output should be redacted, got: {}",
            debug_str
        );
        assert!(
            !debug_str.contains("42"),
            "BlindingFactor debug output should not contain secret bytes"
        );
    }
}
