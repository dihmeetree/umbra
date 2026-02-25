# Umbra — Claude Code Guide

## Project Overview

Umbra is a post-quantum private cryptocurrency with DAG-BFT consensus, written in Rust. ~35k lines across 45 source files with 924 tests. Single crate, no workspace.

## Build & Test

```bash
cargo build --release        # Full build (requires C compiler for PQClean backends)
cargo check                  # Fast type-check
cargo test --features fast-tests # Fast suite (~924 tests, ~1.5 min)
cargo test                       # Full suite (includes real SPHINCS+, ~3 hrs)
cargo test <module>::tests       # Run specific module tests (e.g., consensus::bft::tests)
cargo clippy --all-targets       # Lint — must be warning-free
cargo fmt                        # Format — must pass `cargo fmt -- --check`
```

Winterfell (STARK) and blake3 dependencies are compiled with `opt-level = 3` even in dev/test profile (see `Cargo.toml`), so proof generation is fast. The `fast-tests` feature skips SPHINCS+ signing/verification for further speedup. Use `cargo test <filter>` to run targeted subsets during development.

## Architecture

### Core modules (in dependency order)

| Module                            | File                     | Role                                                                                                                                                           |
| --------------------------------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lib.rs`                          | `src/lib.rs`             | Protocol constants, `Hash` type, `hash_domain`, `hash_concat`, serialization helpers                                                                           |
| `crypto/`                         | `src/crypto/*.rs`        | Post-quantum primitives: Dilithium5 signing, Kyber1024 KEM, stealth addresses, Rescue Prime commitments, nullifiers, Merkle proofs, VRF, encryption, zk-STARKs |
| `transaction/`                    | `src/transaction/mod.rs` | Transaction types, validation (`validate_structure`), `TxInput`/`TxOutput`                                                                                     |
| `transaction/builder.rs`          |                          | `TransactionBuilder` API for constructing transactions with STARK proofs                                                                                       |
| `consensus/dag.rs`                |                          | DAG data structure (vertices, tips, finalized ordering, pruning)                                                                                               |
| `consensus/bft.rs`                |                          | BFT voting, certificates, equivocation detection, VRF committee selection                                                                                      |
| `state.rs`                        | `src/state.rs`           | `ChainState` (validators, bonds, slashing, epoch management), `Ledger` (DAG + state + Merkle tree), `restore_from_storage`                                     |
| `storage.rs`                      | `src/storage.rs`         | `Storage` trait + `SledStorage` (sled embedded DB with 8 named trees)                                                                                          |
| `mempool.rs`                      | `src/mempool.rs`         | Fee-priority transaction pool with nullifier conflict detection                                                                                                |
| `network.rs`                      | `src/network.rs`         | Wire protocol `Message` enum, bincode encode/decode with size limits                                                                                           |
| `p2p.rs`                          | `src/p2p.rs`             | Encrypted TCP transport (Kyber KEM + Dilithium auth + ChaCha20-Poly1305 AEAD)                                                                                  |
| `node.rs`                         | `src/node.rs`            | Node orchestrator: event loop, sync state machine, consensus participation, Dandelion++                                                                        |
| `rpc.rs`                          | `src/rpc.rs`             | JSON HTTP API (axum)                                                                                                                                           |
| `wallet.rs`                       | `src/wallet.rs`          | Client-side key management, scanning, tx building, history                                                                                                     |
| `wallet_cli.rs` / `wallet_web.rs` |                          | CLI and web UI for the wallet                                                                                                                                  |

### Key patterns

- **Serialization**: `bincode` v2 with `serde` (legacy config). Use `crate::serialize`/`crate::deserialize` helpers.
- **Hashing**: BLAKE3 everywhere. `hash_domain(b"umbra.xxx", data)` for domain separation. `hash_concat(&[..])` for multi-part hashing with length prefixes.
- **Constants**: All protocol constants live in `lib.rs::constants` module.
- **Error types**: Each module has its own error enum using `thiserror`. State errors in `StateError`, storage in `StorageError`, etc.
- **Shared state**: `Node` uses `Arc<RwLock<NodeState>>` containing `Ledger`, `Mempool`, `SledStorage`, `BftState`.
- **P2P messages**: Add variants to `Message` enum in `network.rs`. Messages auto-derive `Serialize`/`Deserialize`. Always add a roundtrip test.
- **Gossip dedup**: Two-generation `seen_messages` sets (10k capacity each). Use `self.is_seen()` / `self.mark_seen()` in node.rs message handlers.
- **Testing**: Each module has `#[cfg(test)] mod tests` inline. Storage tests use `SledStorage::open_temporary()`.

## Conventions

- **Security-first**: All crypto comparisons use `constant_time_eq`. Secret keys are `zeroize`-on-drop. Validate at system boundaries.
- **No trusted setup**: All proofs are zk-STARKs (winterfell), not SNARKs.
- **Commit messages**: Imperative, concise summary line. Body explains "why" not "what".
- **Test counts**: Update README.md test count (`All N tests cover:`, `with **N tests**`, `expanding test coverage from 226 to N tests`) when adding tests.
- **TODO.md**: Check off items with `[x]` when implementing production roadmap features.
- **README security section**: Add a bullet when introducing security-relevant features.
- **No emojis** in code or documentation unless explicitly requested.
- **Comment style**: Comments should be plain descriptions only. Never prefix comments with severity tags, tracking codes, or issue IDs (e.g., no `S1:`, `H3:`, `L8:`, `Fix 7:`, `Critical:`, `M14:`).

## Gotchas

- `bincode` v2 API uses `bincode::serde::encode_to_vec` / `decode_from_slice` (not v1 style).
- `deserialize()` rejects inputs > 16 MiB (`MAX_NETWORK_MESSAGE_BYTES`). Use `deserialize_snapshot()` for assembled snapshot blobs.
- `finalize_vertex_inner` takes `&self` (not `&mut self`) — cannot call `mark_seen` from within it.
- STARK proof generation is expensive but mitigated by `[profile.dev.package]` optimizations in Cargo.toml.
- The `Signature` type wraps `Vec<u8>` — Dilithium5 signatures are 4627 bytes each.
- `VoteType` must be included when verifying vote signatures (`vote_sign_data` includes it).
