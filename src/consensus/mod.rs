//! # DAG-BFT Consensus: Proof of Verifiable Participation (PoVP)
//!
//! A novel consensus mechanism that is neither Proof of Work nor Proof of Stake.
//!
//! ## Design Principles
//!
//! 1. **Equal participation**: All validators post an identical constant bond.
//!    Unlike PoS, consensus power is NOT proportional to wealth.
//!    The bond exists solely for Sybil resistance.
//!
//! 2. **Random committee selection**: Each epoch, a committee of K validators
//!    is selected via VRF. Selection is uniform-random, not stake-weighted.
//!
//! 3. **DAG structure**: The ledger is a Directed Acyclic Graph, not a linear chain.
//!    Multiple vertices (blocks) can be produced in parallel, enabling high throughput.
//!
//! 4. **Instant finality**: The committee runs asynchronous BFT consensus.
//!    Once 2K/3 + 1 members certify a vertex, it is irreversibly final.
//!    No probabilistic finality, no confirmation delays.
//!
//! ## How It Works
//!
//! ```text
//! Epoch N:
//!   1. Epoch seed = H(previous_epoch_final_state)
//!   2. Each validator evaluates VRF(their_key, epoch_seed)
//!   3. Validators whose VRF output < threshold join the committee
//!   4. Committee members propose vertices containing transactions
//!   5. Each vertex references 1..MAX_PARENTS previous vertices (forming DAG)
//!   6. Committee runs BFT: members vote on vertex validity
//!   7. Once a vertex gets BFT_QUORUM votes, it achieves instant finality
//!   8. After EPOCH_LENGTH vertices, rotate to epoch N+1
//! ```
//!
//! ## Why Not PoW or PoS?
//!
//! - **vs PoW**: No energy waste. No mining hardware arms race. Instant finality.
//! - **vs PoS**: No wealth-proportional power. No "rich get richer" dynamics.
//!   All validators are equal regardless of bond amount (bond is constant).
//!   Selection is purely random, not weighted.
//!
//! ## Scalability
//!
//! - DAG allows parallel vertex production (not serial like a chain)
//! - Committee size K is fixed regardless of total validator count N
//! - BFT consensus is O(K²) messages, not O(N²)
//! - Throughput scales with committee bandwidth, not total network size

pub mod bft;
pub mod dag;
