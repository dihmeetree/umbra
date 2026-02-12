//! # Spectra
//!
//! A post-quantum private cryptocurrency with:
//! - **DAG-BFT consensus** — not PoW, not PoS; instant deterministic finality
//! - **Post-quantum security** — CRYSTALS-Dilithium signatures + CRYSTALS-Kyber KEM
//! - **Full privacy** — stealth addresses, nullifier-based spend privacy, confidential amounts
//! - **No trusted setup** — all proofs are transparent (zk-STARK compatible)
//! - **Encrypted messaging** — send arbitrary encrypted messages within transactions
//! - **Scalability** — DAG structure enables parallel transaction processing

pub mod consensus;
pub mod crypto;
pub mod mempool;
pub mod network;
pub mod node;
pub mod p2p;
pub mod rpc;
pub mod state;
pub mod storage;
pub mod transaction;
pub mod wallet;
pub mod wallet_cli;

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

    /// Minimum transaction fee (in base units).
    ///
    /// Enforced by `validate_structure()` to prevent zero-fee spam. Coinbase or
    /// genesis funding should add outputs directly to state rather than going
    /// through transaction validation.
    pub const MIN_TX_FEE: u64 = 1;

    /// Compute the chain ID for mainnet.
    pub fn chain_id() -> crate::Hash {
        crate::hash_domain(b"spectra.chain_id", b"spectra-mainnet-v1")
    }
}

/// 32-byte hash used throughout the protocol
pub type Hash = [u8; 32];

/// Compute a domain-separated BLAKE3 hash.
///
/// L1: Takes `&[u8]` rather than `&str` for ergonomics with `b""` literals.
/// The domain MUST be valid UTF-8 (all Spectra domains use ASCII).
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
/// This is acceptable because all Spectra uses compare fixed-size 32-byte hashes.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
