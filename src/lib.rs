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

// Prevent fast-tests from being used in release builds.
#[cfg(all(feature = "fast-tests", not(debug_assertions)))]
compile_error!("fast-tests feature must not be used in release builds");

/// Protocol constants
pub mod constants {
    /// Maximum transaction message size in bytes (64 KiB)
    pub const MAX_MESSAGE_SIZE: usize = 65_536;
    /// Number of validators in each BFT committee
    pub const COMMITTEE_SIZE: usize = 21;
    /// Minimum committee size for BFT safety (need at least 4 for f=1)
    pub const MIN_COMMITTEE_SIZE: usize = 4;
    /// Base bond for validator registration (in base units).
    /// The actual required bond scales with the number of active validators
    /// via [`required_validator_bond`].
    pub const VALIDATOR_BASE_BOND: u64 = 1_000_000;
    /// Scaling factor for the superlinear validator bonding curve.
    /// required_bond(n) = BASE_BOND * (1 + n / SCALING_FACTOR)
    pub const BOND_SCALING_FACTOR: u64 = 100;
    /// Maximum transactions per DAG vertex
    pub const MAX_TXS_PER_VERTEX: usize = 10_000;
    /// Target vertex interval in milliseconds
    pub const VERTEX_INTERVAL_MS: u64 = 500;
    /// Maximum allowed future drift for vertex timestamps (seconds).
    /// Vertices with timestamps more than this far ahead of the receiver's
    /// clock are rejected on insertion.
    pub const MAX_VERTEX_TIMESTAMP_DRIFT_SECS: u64 = 60;
    /// BFT quorum threshold: 2f+1 where f = (COMMITTEE_SIZE-1)/3.
    /// This is only used as a fallback; at runtime, `dynamic_quorum(committee_size)`
    /// computes the quorum from the actual committee size.
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

    /// Peer exchange interval in milliseconds (peer discovery gossip).
    pub const PEER_EXCHANGE_INTERVAL_MS: u64 = 60_000;
    /// Maximum new peers to connect per discovery round (F5).
    pub const PEER_DISCOVERY_MAX: usize = 5;

    /// Padding bucket size (bytes) for encrypted P2P frames. Messages are padded
    /// to the next multiple of this value to resist traffic analysis.
    /// Set to 1024 to reduce message type classification by size bucket.
    pub const P2P_PADDING_BUCKET: usize = 1024;

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

    // ── Operational caps ──

    /// Maximum tips returned in a single TipsResponse message.
    pub const MAX_TIPS_RESPONSE: usize = 1_000;
    /// Maximum entries in the sync_failed_peers set.
    pub const MAX_SYNC_FAILED_PEERS: usize = 1_000;
    /// Maximum observed-IP vote entries tracked for NAT detection.
    pub const MAX_OBSERVED_IP_VOTES: usize = 100;
    /// Number of past epochs of committee history retained for cross-epoch
    /// equivocation verification.
    pub const MAX_EQUIVOCATION_EVIDENCE_EPOCHS: usize = 10;
    /// Maximum vertices a single proposer can insert per epoch.
    pub const MAX_VERTICES_PER_PROPOSER_PER_EPOCH: usize = 100;
    /// Maximum eviction iterations when inserting into a full mempool.
    pub const MAX_MEMPOOL_EVICTIONS: usize = 10;
    /// Number of peers whose snapshot state_root must agree before importing.
    pub const SNAPSHOT_QUORUM: usize = 2;
    /// Upper bound on snapshot blob size accepted by `deserialize_snapshot` (1 GiB).
    pub const MAX_SNAPSHOT_DESERIALIZE_BYTES: usize = 1024 * 1024 * 1024;

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

    // ── P2P Transport Rekeying ──

    /// Number of encrypted messages before triggering automatic session rekey.
    pub const P2P_REKEY_INTERVAL: u64 = 10_000;
    /// Maximum time (seconds) between rekeys for forward secrecy.
    pub const P2P_REKEY_TIME_SECS: u64 = 300;

    /// Minimum transaction fee (in base units).
    ///
    /// Enforced by `validate_structure()` to prevent zero-fee spam. Coinbase or
    /// genesis funding should add outputs directly to state rather than going
    /// through transaction validation.
    pub const MIN_TX_FEE: u64 = 1;

    // ── Deterministic weight-based fee constants ──

    /// Base fee per transaction (covers balance proof verification overhead).
    pub const FEE_BASE: u64 = 100;
    /// Fee per input (covers spend proof verification, nullifier processing).
    pub const FEE_PER_INPUT: u64 = 100;
    /// Fee per 1024 bytes of message ciphertext (covers storage and relay).
    pub const FEE_PER_MESSAGE_KB: u64 = 10;

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

    /// Maximum total supply of coins that can ever be minted.
    ///
    /// This is the theoretical upper bound: genesis mint (100M) + mining rewards.
    /// Mining follows a halving schedule that converges to:
    ///   EPOCH_LENGTH * HALVING_INTERVAL * INITIAL_BLOCK_REWARD * 2 = 50 billion.
    /// The cap is set slightly above this to account for fees included in
    /// coinbase outputs and to provide a hard safety limit against inflation bugs.
    pub const MAX_TOTAL_SUPPLY: u64 = 51_000_000_000;

    /// Compute the block reward for a given epoch.
    pub fn block_reward_for_epoch(epoch: u64) -> u64 {
        let halvings = epoch / HALVING_INTERVAL_EPOCHS;
        if halvings > MAX_HALVINGS as u64 {
            return 0;
        }
        INITIAL_BLOCK_REWARD >> halvings as u32
    }

    /// Compute the required validator bond given the current active validator count.
    ///
    /// Formula: `BASE_BOND * (1 + n / SCALING_FACTOR)`
    ///
    /// This creates a superlinear cost curve for mass validator registration,
    /// making Sybil attacks expensive while keeping initial entry costs low.
    pub fn required_validator_bond(active_count: usize) -> u64 {
        let n = active_count as u64;
        VALIDATOR_BASE_BOND
            .saturating_add(VALIDATOR_BASE_BOND.saturating_mul(n) / BOND_SCALING_FACTOR)
    }

    /// Compute the deterministic fee from transaction shape.
    ///
    /// Every transfer transaction of the same shape (input count, message sizes)
    /// pays the exact same fee. This eliminates fee-based fingerprinting entirely.
    /// Output count is intentionally excluded — the cost of commitment tree
    /// insertion is trivial compared to STARK proof verification, and excluding
    /// it removes the circular dependency between fee and output count that
    /// would otherwise create an unsolvable "dead zone" in coin selection.
    ///
    /// `message_bytes` is the total ciphertext byte length across all messages.
    pub fn compute_weight_fee(num_inputs: usize, message_bytes: usize) -> u64 {
        let message_kb = message_bytes.div_ceil(1024) as u64;
        FEE_BASE + (num_inputs as u64) * FEE_PER_INPUT + message_kb * FEE_PER_MESSAGE_KB
    }

    /// Compute the chain ID for mainnet.
    pub fn chain_id() -> crate::Hash {
        crate::hash_domain(b"umbra.chain_id", b"umbra-mainnet-v1")
    }
}

/// 32-byte hash used throughout the protocol
pub type Hash = [u8; 32];

/// Serde helper for `[u8; 64]` arrays (bincode's serde doesn't support arrays >32).
pub mod serde_bytes64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        let v: Vec<u8> = data.to_vec();
        v.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        if v.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes for blake3_binding, got {}",
                v.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}

/// Compute a domain-separated BLAKE3 hash.
///
/// Takes `&[u8]` rather than `&str` for ergonomics with `b""` literals.
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
    if bytes.len() > constants::MAX_SNAPSHOT_DESERIALIZE_BYTES {
        return Err(bincode::error::DecodeError::LimitExceeded);
    }
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

    #[test]
    fn required_bond_scales_correctly() {
        use constants::*;

        // First validator pays base bond
        assert_eq!(required_validator_bond(0), VALIDATOR_BASE_BOND);

        // 10 validators: 1M + 1M * 10/100 = 1.1M
        assert_eq!(required_validator_bond(10), 1_100_000);

        // 100 validators: 1M + 1M * 100/100 = 2M
        assert_eq!(required_validator_bond(100), 2_000_000);

        // 500 validators: 1M + 1M * 500/100 = 6M
        assert_eq!(required_validator_bond(500), 6_000_000);

        // Verify monotonic increase
        for n in 0..1000 {
            assert!(required_validator_bond(n) <= required_validator_bond(n + 1));
        }
    }

    #[test]
    fn required_bond_no_overflow_at_extreme_count() {
        // At extreme counts, saturating arithmetic prevents wrapping
        let bond = constants::required_validator_bond(usize::MAX);
        // Should be a very large value, not wrapped to something small
        assert!(bond > constants::VALIDATOR_BASE_BOND);
        // u64::MAX / 100 + BASE_BOND
        assert!(bond > u64::MAX / 200);
    }

    #[test]
    fn compute_weight_fee_basic() {
        // 1 input, no messages: 100 + 100 = 200
        assert_eq!(constants::compute_weight_fee(1, 0), 200);
        // 2 inputs: 100 + 200 = 300
        assert_eq!(constants::compute_weight_fee(2, 0), 300);
    }

    #[test]
    fn compute_weight_fee_message_rounding() {
        // 1 byte of message rounds up to 1 KB
        assert_eq!(constants::compute_weight_fee(1, 1), 210);
        // 1024 bytes = exactly 1 KB
        assert_eq!(constants::compute_weight_fee(1, 1024), 210);
        // 1025 bytes rounds up to 2 KB
        assert_eq!(constants::compute_weight_fee(1, 1025), 220);
    }

    #[test]
    fn compute_weight_fee_max_tx() {
        // 16 inputs, 16 * 64 KiB messages
        let max_msg_bytes = 16 * 65_536;
        let fee = constants::compute_weight_fee(16, max_msg_bytes);
        // 100 + 16*100 + ceil(1048576/1024)*10 = 100 + 1600 + 10240 = 11940
        assert_eq!(fee, 11_940);
        assert!(fee <= constants::MAX_TX_FEE);
    }

    #[test]
    fn deserialize_snapshot_roundtrip() {
        let original: Vec<u8> = vec![10, 20, 30, 40, 50];
        let bytes = serialize(&original).unwrap();
        let restored: Vec<u8> = deserialize_snapshot(&bytes).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn deserialize_snapshot_accepts_large_data() {
        // Create a payload larger than MAX_NETWORK_MESSAGE_BYTES.
        // `deserialize` would reject this, but `deserialize_snapshot` should not.
        let large_vec: Vec<u8> = vec![0u8; constants::MAX_NETWORK_MESSAGE_BYTES + 1024];
        let bytes = serialize(&large_vec).unwrap();
        // Confirm deserialize rejects it
        assert!(deserialize::<Vec<u8>>(&bytes).is_err());
        // Confirm deserialize_snapshot accepts it
        let restored: Vec<u8> = deserialize_snapshot(&bytes).unwrap();
        assert_eq!(restored.len(), large_vec.len());
    }

    #[test]
    fn deserialize_snapshot_rejects_malformed() {
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = deserialize_snapshot::<Vec<u8>>(&garbage);
        assert!(result.is_err(), "malformed data should be rejected");
    }

    #[test]
    fn block_reward_epoch_zero() {
        assert_eq!(
            constants::block_reward_for_epoch(0),
            constants::INITIAL_BLOCK_REWARD
        );
    }

    #[test]
    fn block_reward_halving_at_interval() {
        // After epoch 500 (first halving): reward >> 1
        assert_eq!(
            constants::block_reward_for_epoch(constants::HALVING_INTERVAL_EPOCHS),
            constants::INITIAL_BLOCK_REWARD >> 1
        );
        // After epoch 1000 (second halving): reward >> 2
        assert_eq!(
            constants::block_reward_for_epoch(constants::HALVING_INTERVAL_EPOCHS * 2),
            constants::INITIAL_BLOCK_REWARD >> 2
        );
    }

    #[test]
    fn block_reward_zero_after_max_halvings() {
        // After 63 halvings (epoch 31500+), reward should be 0
        let epoch = constants::HALVING_INTERVAL_EPOCHS * (constants::MAX_HALVINGS as u64 + 1);
        assert_eq!(constants::block_reward_for_epoch(epoch), 0);
    }

    #[test]
    fn block_reward_no_overflow_large_epoch() {
        // Should not panic with u64::MAX
        let reward = constants::block_reward_for_epoch(u64::MAX);
        assert_eq!(reward, 0);
    }

    #[test]
    fn chain_id_deterministic() {
        let a = constants::chain_id();
        let b = constants::chain_id();
        assert_eq!(a, b);
    }

    #[test]
    fn chain_id_not_zero() {
        let id = constants::chain_id();
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn hash_domain_empty_domain() {
        let h = hash_domain(b"", b"data");
        // Should produce a valid 32-byte hash (not all zeros)
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn hash_domain_empty_data() {
        let h = hash_domain(b"umbra.test", b"");
        // Should produce a valid 32-byte hash (not all zeros)
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn hash_concat_empty_parts() {
        let a = hash_concat(&[]);
        let b = hash_concat(&[]);
        // Should produce a deterministic result
        assert_eq!(a, b);
    }

    #[test]
    fn hash_concat_single_part() {
        let h = hash_concat(&[b"single"]);
        // Should produce a valid 32-byte hash
        assert_ne!(h, [0u8; 32]);
        // Should be deterministic
        assert_eq!(h, hash_concat(&[b"single"]));
    }

    #[test]
    fn deserialize_exact_boundary() {
        // Create data that serializes to exactly MAX_NETWORK_MESSAGE_BYTES.
        // We serialize a Vec<u8> whose serialized form is at the boundary.
        // bincode legacy encodes Vec<u8> as: 8 bytes length prefix + payload.
        let payload_len = constants::MAX_NETWORK_MESSAGE_BYTES - 8;
        let data = vec![0u8; payload_len];
        let bytes = serialize(&data).unwrap();
        assert_eq!(bytes.len(), constants::MAX_NETWORK_MESSAGE_BYTES);
        // Should succeed since it is exactly at the limit, not exceeding it
        let restored: Vec<u8> = deserialize(&bytes).unwrap();
        assert_eq!(restored.len(), payload_len);
    }

    #[test]
    fn deserialize_empty_input() {
        let result = deserialize::<u64>(b"");
        assert!(result.is_err(), "empty input should fail to deserialize");
    }

    #[test]
    fn compute_weight_fee_zero_inputs() {
        // 0 inputs, 0 message bytes: just the base fee
        assert_eq!(constants::compute_weight_fee(0, 0), constants::FEE_BASE);
    }

    #[test]
    fn compute_weight_fee_at_max_io() {
        // MAX_TX_IO inputs, no messages
        let fee = constants::compute_weight_fee(constants::MAX_TX_IO, 0);
        let expected =
            constants::FEE_BASE + (constants::MAX_TX_IO as u64) * constants::FEE_PER_INPUT;
        assert_eq!(fee, expected);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn constants_bft_quorum_safety() {
        // Quorum must not exceed committee size
        assert!(
            constants::BFT_QUORUM <= constants::COMMITTEE_SIZE,
            "BFT_QUORUM ({}) must be <= COMMITTEE_SIZE ({})",
            constants::BFT_QUORUM,
            constants::COMMITTEE_SIZE
        );
        // Quorum must be strictly greater than 2/3 of committee size (Byzantine fault tolerance)
        assert!(
            constants::BFT_QUORUM > constants::COMMITTEE_SIZE * 2 / 3,
            "BFT_QUORUM ({}) must be > COMMITTEE_SIZE * 2 / 3 ({})",
            constants::BFT_QUORUM,
            constants::COMMITTEE_SIZE * 2 / 3
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn constants_min_committee_allows_bft() {
        // Need at least f=1 -> 3f+1=4 for BFT safety
        assert!(
            constants::MIN_COMMITTEE_SIZE >= 4,
            "MIN_COMMITTEE_SIZE ({}) must be >= 4 for BFT safety (f=1 requires 3f+1=4)",
            constants::MIN_COMMITTEE_SIZE
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn constants_snapshot_chunk_fits_network() {
        assert!(
            constants::SNAPSHOT_CHUNK_SIZE < constants::MAX_NETWORK_MESSAGE_BYTES,
            "SNAPSHOT_CHUNK_SIZE ({}) must be < MAX_NETWORK_MESSAGE_BYTES ({})",
            constants::SNAPSHOT_CHUNK_SIZE,
            constants::MAX_NETWORK_MESSAGE_BYTES
        );
    }

    #[test]
    fn constants_port_uniqueness() {
        assert_ne!(
            constants::DEFAULT_P2P_PORT,
            constants::DEFAULT_RPC_PORT,
            "P2P and RPC ports must be different"
        );
    }

    #[test]
    fn hash_domain_empty_data_still_differs_by_domain() {
        let h1 = hash_domain(b"domain.a", b"");
        let h2 = hash_domain(b"domain.b", b"");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_concat_order_matters() {
        let h1 = hash_concat(&[b"hello", b"world"]);
        let h2 = hash_concat(&[b"world", b"hello"]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer string"));
        assert!(!constant_time_eq(b"", b"notempty"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn serialize_deserialize_various_types() {
        // Test with u64
        let val: u64 = 42;
        let bytes = serialize(&val).unwrap();
        let restored: u64 = deserialize(&bytes).unwrap();
        assert_eq!(val, restored);

        // Test with Vec<u8>
        let val: Vec<u8> = vec![1, 2, 3, 4, 5];
        let bytes = serialize(&val).unwrap();
        let restored: Vec<u8> = deserialize(&bytes).unwrap();
        assert_eq!(val, restored);

        // Test with String
        let val = String::from("test string");
        let bytes = serialize(&val).unwrap();
        let restored: String = deserialize(&bytes).unwrap();
        assert_eq!(val, restored);
    }

    #[test]
    fn deserialize_snapshot_rejects_empty() {
        let result: Result<Vec<u8>, _> = deserialize_snapshot(b"");
        assert!(result.is_err());
    }

    #[test]
    fn blinding_factor_from_bytes_deterministic() {
        use crate::crypto::commitment::BlindingFactor;
        let b1 = BlindingFactor::from_bytes([42u8; 32]);
        let b2 = BlindingFactor::from_bytes([42u8; 32]);
        assert_eq!(b1.0, b2.0);
    }

    #[test]
    fn block_reward_decreases_with_halvings() {
        let r0 = constants::block_reward_for_epoch(0);
        let r1 = constants::block_reward_for_epoch(constants::HALVING_INTERVAL_EPOCHS);
        assert!(r1 < r0);
        assert_eq!(r1, r0 / 2);
    }

    #[test]
    fn required_bond_increases_with_validators() {
        let bond_10 = constants::required_validator_bond(10);
        let bond_100 = constants::required_validator_bond(100);
        assert!(bond_100 > bond_10);
    }

    #[test]
    fn compute_weight_fee_increases_with_inputs() {
        let fee1 = constants::compute_weight_fee(1, 0);
        let fee2 = constants::compute_weight_fee(2, 0);
        assert!(fee2 > fee1);
    }

    #[test]
    fn compute_weight_fee_increases_with_messages() {
        let fee1 = constants::compute_weight_fee(1, 0);
        let fee2 = constants::compute_weight_fee(1, 1000);
        assert!(fee2 > fee1);
    }

    #[test]
    fn hash_domain_different_data_different_hash() {
        let h1 = hash_domain(b"same.domain", b"data1");
        let h2 = hash_domain(b"same.domain", b"data2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_concat_no_parts() {
        // Empty slice should still produce a hash
        let h = hash_concat(&[]);
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn deserialize_truncated_input() {
        // Serialize a u64, then truncate
        let bytes = serialize(&42u64).unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        let result: Result<u64, _> = deserialize(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_wrong_type() {
        // Serialize a u64 then try to deserialize as bool
        let bytes = serialize(&42u64).unwrap();
        let result: Result<bool, _> = deserialize(&bytes);
        // May succeed or fail depending on bincode, but shouldn't panic
        let _ = result;
    }

    #[test]
    fn block_reward_exact_halving_boundary() {
        // At exactly the halving interval, reward should be half
        let r0 = constants::block_reward_for_epoch(0);
        let r_at_halving = constants::block_reward_for_epoch(constants::HALVING_INTERVAL_EPOCHS);
        assert_eq!(r_at_halving, r0 / 2);
        // One epoch before halving should still be full reward
        let r_before = constants::block_reward_for_epoch(constants::HALVING_INTERVAL_EPOCHS - 1);
        assert_eq!(r_before, r0);
    }

    #[test]
    fn block_reward_multiple_halvings() {
        let r0 = constants::block_reward_for_epoch(0);
        let r1 = constants::block_reward_for_epoch(constants::HALVING_INTERVAL_EPOCHS);
        let r2 = constants::block_reward_for_epoch(constants::HALVING_INTERVAL_EPOCHS * 2);
        assert_eq!(r1, r0 / 2);
        assert_eq!(r2, r0 / 4);
    }

    #[test]
    fn constant_time_eq_equal_arrays() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_different_arrays() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn chain_id_nonzero() {
        let id = constants::chain_id();
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn required_bond_zero_validators() {
        let bond = constants::required_validator_bond(0);
        assert!(bond > 0);
    }

    #[test]
    fn compute_weight_fee_single_input_no_messages() {
        let fee = constants::compute_weight_fee(1, 0);
        assert!(fee > 0);
    }

    #[test]
    fn protocol_constants_reasonable() {
        // Use runtime checks to avoid clippy::assertions_on_constants
        let max_tx_io = constants::MAX_TX_IO;
        let committee_size = constants::COMMITTEE_SIZE;
        let min_committee = constants::MIN_COMMITTEE_SIZE;
        let epoch_len = constants::EPOCH_LENGTH;
        let max_peers = constants::MAX_PEERS;
        let max_msg = constants::MAX_NETWORK_MESSAGE_BYTES;
        let protocol_ver = constants::PROTOCOL_VERSION_ID;

        assert!(max_tx_io > 0);
        assert!(max_tx_io <= 256);
        assert!(committee_size > 0);
        assert!(min_committee > 0);
        assert!(min_committee <= committee_size);
        assert!(epoch_len > 0);
        assert!(max_peers > 0);
        assert!(max_msg > 0);
        assert!(protocol_ver > 0);
    }
}
