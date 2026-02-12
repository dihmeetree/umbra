# Spectra

A post-quantum private cryptocurrency with DAG-BFT consensus, written in Rust.

Spectra is designed from the ground up to be **anonymous**, **unlinkable**, **untraceable**, **quantum-resistant**, and **instantly final** — with no trusted setup required.

## Key Features

### Full Zero-Knowledge Privacy

- **Stealth addresses** — each transaction output uses a unique one-time address derived via Kyber KEM, making recipients unlinkable across transactions
- **Nullifier-based spending** — inputs reveal a deterministic nullifier derived from secret key material, preventing double-spends without revealing the spender's identity. Input commitments are never published — only a one-way `proof_link` is revealed, preventing graph analysis between inputs and outputs
- **Confidential amounts** — all values are hidden behind Rescue Prime commitments; validators verify correctness via zk-STARK proofs without learning any amounts
- **zk-STARK proofs** — balance and spend validity are proven in zero knowledge with no trusted setup and post-quantum security
- **Encrypted messaging** — arbitrary messages (up to 1 MiB) can be attached to transactions (max 16 per tx), encrypted so only the recipient can read them. All metadata including routing tags is inside the ciphertext — no plaintext metadata is exposed on-chain

### Quantum Resistance

All cryptographic primitives are post-quantum secure:

| Primitive | Algorithm | Security |
|-----------|-----------|----------|
| Signatures | CRYSTALS-Dilithium5 | NIST Level 5 (~256-bit classical) |
| Key encapsulation | CRYSTALS-Kyber1024 | NIST Level 5 |
| Commitments & Merkle tree | Rescue Prime (Rp64_256) | STARK-friendly, post-quantum |
| General hashing | BLAKE3 | 256-bit (128-bit quantum via Grover) |
| Zero-knowledge proofs | zk-STARKs (winterfell) | ~127-bit conjectured security |

No trusted setup is required. All proofs are transparent.

### Consensus: Proof of Verifiable Participation (PoVP)

A novel consensus mechanism that is **neither Proof of Work nor Proof of Stake**:

1. **Equal participation** — validators post an identical constant bond. Consensus power is *not* proportional to wealth. The bond exists solely for Sybil resistance.
2. **VRF committee selection** — each epoch, a committee of 21 validators is selected uniformly at random via a Verifiable Random Function. Selection is unbiased and unpredictable.
3. **DAG structure** — the ledger is a Directed Acyclic Graph, not a linear chain. Multiple vertices can be produced in parallel, enabling high throughput.
4. **Instant finality** — the committee runs asynchronous BFT. Once 2/3+1 members certify a vertex, it is irreversibly final. No probabilistic finality, no confirmation delays.

```
Epoch N:
  1. epoch_seed = H(previous_epoch_final_state)
  2. Each validator evaluates VRF(key, epoch_seed)
  3. Validators below threshold join the committee
  4. Committee members propose vertices containing transactions
  5. Vertices reference 1..8 parent vertices (forming the DAG)
  6. Committee runs BFT: 2/3+1 votes = instant finality
  7. After 1000 vertices, rotate to epoch N+1
```

**Why not PoW?** No energy waste. No mining hardware arms race. Instant finality instead of probabilistic.

**Why not PoS?** No wealth-proportional power. No "rich get richer" dynamics. All validators are equal. Selection is purely random, not stake-weighted.

## Project Structure

```
spectra/
  src/
    lib.rs                  Protocol constants, hashing utilities
    crypto/
      keys.rs               Dilithium5 signing + Kyber1024 KEM keypairs
      stealth.rs            Stealth address generation and detection
      commitment.rs         Rescue Prime commitments with field element conversions
      nullifier.rs          Nullifier derivation and double-spend tracking
      proof.rs              Merkle tree (Rescue Prime), depth-20 padding, canonical roots
      encryption.rs         Kyber KEM + BLAKE3 authenticated encryption
      vrf.rs                Verifiable Random Function for committee selection
      stark/
        mod.rs              STARK module root, proof options, type aliases
        convert.rs          Goldilocks field element conversion utilities
        rescue.rs           Rescue Prime round function, MDS/ARK constants
        types.rs            BalanceStarkProof, SpendStarkProof, witness types
        balance_air.rs      AIR for balance proofs (commitment openings + sum + range proofs)
        balance_prover.rs   Prover for balance STARK proofs
        spend_air.rs        AIR for spend proofs (nullifier + Merkle membership + proof_link)
        spend_prover.rs     Prover for spend STARK proofs
        verify.rs           STARK verification wrappers
    transaction/
      mod.rs                Transaction, TxType, TxInput, TxOutput types and validation
      builder.rs            TransactionBuilder API for constructing transactions
    consensus/
      mod.rs                PoVP design documentation
      dag.rs                DAG data structure (vertices with VRF proofs, tips, ancestors)
      bft.rs                BFT voting with VRF proofs, certification, committee selection
    mempool.rs              Fee-priority transaction pool with nullifier conflict detection
    storage.rs              Persistent storage trait + sled backend (vertices, txs, validators)
    p2p.rs                  Async TCP P2P networking with channel-based architecture
    node.rs                 Node orchestrator: active consensus, persistent keypair, BFT voting
    rpc.rs                  JSON HTTP API (axum): tx, state, peers, mempool, validators
    state.rs                Chain state (bonds, slashing, epoch seed), Ledger (two-phase vertex flow)
    network.rs              P2P protocol message types and serialization
    wallet.rs               Key management, output scanning, tx building, persistence
    wallet_cli.rs           Wallet CLI commands (init, send, balance, scan, messages)
    wallet_web.rs           Wallet web UI (askama templates, axum server)
    main.rs                 Node + wallet binary with clap subcommands
  templates/
    base.html               Base layout with navigation and CSS
    dashboard.html          Balance, outputs, chain state, scan button
    init.html               Wallet creation page
    address.html            Address display and export
    send.html               Transaction send form
    send_result.html        Transaction submission result
    messages.html           Encrypted message list
    error.html              Error display
```

**~14,500 lines of Rust** across 34 source files with **190 tests**.

## Building

Requires a C compiler (for the PQClean backends used by `pqcrypto-dilithium` and `pqcrypto-kyber`).

```bash
cargo build --release
```

## Running a Node

```bash
cargo run --release -- node [OPTIONS]
```

### CLI Options

The binary uses subcommands (`node`, `wallet`). Running without a subcommand defaults to node mode for backward compatibility.

**Global flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--data-dir` | `./spectra-data` | Data directory for persistent storage |
| `--rpc-addr` | `127.0.0.1:9733` | JSON RPC listen address (localhost by default for safety) |
| `--demo` | *(off)* | Run the protocol demo walkthrough instead |

**Node flags** (`spectra node`):

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-addr` | `0.0.0.0:9732` | P2P listen address |
| `--peers` | *(none)* | Comma-separated bootstrap peer addresses |
| `--genesis-validator` | *(off)* | Register as a genesis validator (for bootstrapping a new network) |

### Examples

```bash
# Start a node with default settings
cargo run --release

# Start as a genesis validator (bootstraps a new network)
cargo run --release -- node --genesis-validator

# Start with custom addresses and a bootstrap peer
cargo run --release -- node --listen-addr 127.0.0.1:9000 --rpc-addr 127.0.0.1:9001 --peers 192.168.1.10:9732

# Run the protocol demo
cargo run --release -- --demo
```

## Wallet CLI

The wallet runs client-side — it downloads finalized vertices from the node and scans them locally. The node never learns which outputs belong to the wallet.

```bash
cargo run --release -- wallet <command>
```

### Wallet Commands

| Command | Description |
|---------|-------------|
| `init` | Create a new wallet and export address file |
| `address` | Show wallet address ID and re-export address file |
| `balance` | Scan the chain and show current balance |
| `scan` | Scan the chain for new outputs (without showing balance) |
| `send` | Build and submit a transaction |
| `messages` | Show received encrypted messages |
| `export` | Export wallet address to a file for sharing |

### Wallet Examples

```bash
# Create a new wallet
cargo run --release -- wallet init

# Check balance (scans chain first)
cargo run --release -- wallet balance

# Send 1000 units to a recipient
cargo run --release -- wallet send --to ./bob.spectra-address --amount 1000 --fee 10

# Send with an encrypted message
cargo run --release -- wallet send --to ./bob.spectra-address --amount 500 --fee 10 --message "Payment for services"

# View received messages
cargo run --release -- wallet messages

# Export address for sharing
cargo run --release -- wallet export --file ./my-address.spectra-address

# Use a custom data directory
cargo run --release -- --data-dir ./my-wallet wallet balance
```

### Address Exchange

Wallets exchange addresses via `.spectra-address` files (hex-encoded bincode-serialized `PublicAddress`). The `init` and `address` commands automatically export this file to the data directory. Use `export` to save it elsewhere for sharing.

## Wallet Web UI

A browser-based wallet interface with the same capabilities as the CLI. The web server runs as a separate process and communicates with the node via HTTP RPC. The node never learns which outputs belong to the wallet.

```bash
# Start the wallet web UI (default: http://127.0.0.1:9734)
cargo run --release -- wallet web

# Custom host/port and node RPC
cargo run --release -- --rpc-addr 127.0.0.1:9733 wallet web --host 0.0.0.0 --port 8080
```

Open `http://127.0.0.1:9734` in your browser. If no wallet exists, you'll be prompted to create one.

**Pages:**
- **Dashboard** (`/`) — balance, output counts, chain state, scan button
- **Send** (`/send`) — build and submit transactions with optional encrypted messages
- **Messages** (`/messages`) — view received encrypted messages
- **Address** (`/address`) — view and export wallet address for sharing

## RPC API

The node exposes a JSON HTTP API (default `127.0.0.1:9733`, localhost-only for safety).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/tx` | Submit a hex-encoded bincode-serialized transaction |
| `GET` | `/tx/{id}` | Look up a transaction by ID (checks mempool then storage) |
| `GET` | `/state` | Query chain state (epoch, commitment/nullifier counts, roots) |
| `GET` | `/peers` | List connected peers |
| `GET` | `/mempool` | Get mempool statistics |
| `GET` | `/validators` | List all validators with bond and status |
| `GET` | `/validator/{id}` | Get a single validator's info |
| `GET` | `/vertices/finalized` | Paginated finalized vertices (`?after=N&limit=N`) |

### Example

```bash
# Query chain state
curl http://localhost:9733/state

# Check mempool stats
curl http://localhost:9733/mempool

# List all validators
curl http://localhost:9733/validators

# Look up a transaction
curl http://localhost:9733/tx/abc123...

# Get finalized vertices (paginated)
curl "http://localhost:9733/vertices/finalized?after=0&limit=100"
```

## Architecture

### Mempool

Fee-priority transaction pool with configurable limits:

- Transactions are ordered by fee (highest first) using a `BTreeMap` with negated fee keys
- Nullifier conflict detection prevents double-spend attempts within the pool
- When full, the lowest-fee transaction is evicted to make room for higher-fee submissions
- `drain_highest_fee(n)` extracts the top-*n* transactions for vertex proposal
- Configurable size limits: max 10,000 transactions / 50 MiB (default)

### Persistent Storage

`Storage` trait with a [sled](https://docs.rs/sled) embedded database backend:

- **7 named trees**: `vertices`, `transactions`, `nullifiers`, `chain_meta`, `commitment_levels`, `validators`, `finalized_index`
- All values are bincode-serialized; keys are raw 32-byte hashes (finalized_index uses big-endian sequence numbers)
- `ChainStateMeta` captures full chain state snapshots (epoch, roots, counts, finalized count) for persistence
- Commitment level storage enables Merkle tree reconstruction on restart
- Finalized vertex index supports paginated retrieval for wallet sync and state sync
- `open_temporary()` provides in-memory storage for testing

### P2P Networking

Async TCP transport built on tokio with channel-based architecture:

- `P2pHandle` — clone-friendly handle for sending commands (connect, broadcast, send, shutdown)
- `P2pEvent` — events received by the node (peer connected/disconnected, message received)
- Per-connection Hello handshake followed by spawned read/write tasks
- Uses the existing `network::encode_message/decode_message` framing (4-byte LE length prefix + bincode)
- Configurable max peers (default 64) and connection timeout (5 seconds)

### Node Orchestrator

The `Node` struct ties everything together with a `tokio::select!` event loop:

- **Persistent validator identity** — keypair is saved to `data_dir/validator.key` on first run and loaded on subsequent startups
- **Active consensus participation** — when selected for the committee via VRF, the node proposes vertices (draining high-fee transactions from the mempool) and casts BFT votes on incoming vertices
- **Two-phase vertex flow** — vertices are first inserted into the DAG (unfinalized), then finalized after receiving a BFT quorum certificate. Finalization applies transactions to state, purges conflicting mempool entries, persists to storage, and slashes equivocators
- **Epoch management** — after `EPOCH_LENGTH` finalized vertices, the epoch advances with a new VRF seed derived from the state root
- **State persistence** — every finalized vertex persists its transactions, nullifiers, Merkle tree nodes, finalized index, validators, and a `ChainStateMeta` snapshot to storage, then flushes. On restart the full chain state (Merkle tree, nullifier set, validators, epoch state) is restored from the snapshot
- **State sync** — new nodes joining the network request finalized vertices in batches from peers via `GetFinalizedVertices` / `FinalizedVerticesResponse` messages. A three-state machine (`NeedSync → Syncing → Synced`) tracks sync progress
- Shared state via `Arc<RwLock<NodeState>>` (ledger + mempool + storage + BFT state)
- Peer discovery via `GetPeers` / `PeersResponse` messages
- Genesis bootstrap via `--genesis-validator` flag (registers the node with bond escrowed, no funding tx required)

## Testing

```bash
cargo test
```

All 190 tests cover:

- **Core utilities** — hash_domain determinism, domain separation, hash_concat length-prefix ambiguity prevention, constant-time equality
- **Post-quantum crypto** — key generation, signing, KEM roundtrips
- **Stealth addresses** — generation, detection, multi-index scanning, spend auth derivation determinism, index-dependent key uniqueness
- **Rescue Prime** — commitments, field element conversions
- **Nullifiers** — determinism, double-spend detection
- **Merkle tree** — construction, path verification, depth-20 canonical padding, restore from stored level data, last-appended path coverage
- **Encryption** — message roundtrips, authentication, tamper detection
- **VRF** — evaluation, verification, committee selection statistics
- **DAG** — insertion, diamond merges, finalized ordering, tip tracking, duplicate rejection, finalization status, topological sort of complex graphs
- **BFT** — vote collection, leader rotation, duplicate rejection, cross-epoch replay prevention, equivocation detection/clearing, quorum certification, multi-round certificate tracking, round advancement
- **Network** — message serialization roundtrips, oversized message rejection, sync message roundtrips (GetFinalizedVertices, FinalizedVerticesResponse), peer discovery messages, epoch state responses
- **Transactions** — ID determinism, content hash determinism, estimated size, deregister sign data; validation of all error paths (no inputs/outputs, too many inputs/outputs, duplicate nullifiers, expired, fee too low, invalid binding, too many messages)
- **Transaction builder** — STARK proof generation, chain ID and expiry, multi-input/multi-output, input/output limit enforcement
- **RPC endpoints** — GET /state, /mempool, /validators, /validator/:id (found and not-found), /tx/:id (found and not-found), /vertices/finalized; POST /tx (valid submission, invalid hex rejection); full submit-and-retrieve roundtrip
- **Wallet** — scanning, balance tracking, spending with change, pending transaction confirm/cancel, balance excludes pending, keypair preservation; file save/load roundtrip (keys, outputs, messages, pending status)
- **Wallet CLI** — init (creates files, rejects duplicate), address display, export creates valid address file, messages on empty wallet
- **End-to-end** — fund, transfer, message decrypt, bystander non-detection
- **Mempool** — fee-priority ordering, nullifier conflict detection, eviction, drain
- **Storage** — vertex/transaction/nullifier/validator persistence, chain state meta roundtrips, finalized index roundtrip and batch retrieval
- **State** — genesis validator registration and query, bond slashing, epoch advancement (fee reset, seed rotation), inactive validator tracking, last-finalized tracking
- **P2P** — peer connection establishment, message exchange
- **Node** — persistent keypair load/save roundtrip
- **Chain state** — persist/restore roundtrip (Merkle tree, nullifiers, validators, epoch state), ledger restore from storage

## Demo

```bash
cargo run --release -- --demo
```

Runs an end-to-end demonstration:

1. Generates post-quantum keypairs for Alice and Bob
2. Funds Alice via a simulated coinbase transaction (with zk-STARK proofs)
3. Alice sends 25,000 units to Bob with an encrypted message
4. Bob scans and decrypts his payment and message
5. Eve (bystander) scans the same transaction and finds nothing
6. Creates 30 validators, selects a committee via VRF
7. Builds a DAG with parallel vertices and diamond merges
8. Applies transactions to chain state with Merkle tree tracking

## Transaction Model

Spectra uses a UTXO model with full zero-knowledge privacy:

```
Transaction {
    inputs:        [Nullifier + ProofLink + SpendStarkProof]
    outputs:       [Commitment + StealthAddress + EncryptedNote]
    fee:           u64 (public)
    chain_id:      Hash (replay protection across networks)
    expiry_epoch:  u64 (transaction expiration)
    balance_proof: BalanceStarkProof
    messages:      [EncryptedPayload]  (optional)
    tx_binding:    Hash (binds all fields together)
    tx_type:       Transfer | ValidatorRegister | ValidatorDeregister
}
```

- **Inputs** reveal a nullifier, a proof_link, and a zk-STARK spend proof. The proof demonstrates in zero knowledge that: (1) the nullifier is correctly derived from a secret spend key and a committed output, (2) that committed output exists in the global Merkle tree, and (3) the proof_link is correctly derived from the commitment and a random nonce. The actual commitment is never revealed — only the one-way proof_link is public, preventing graph analysis between inputs and outputs. No amounts or keys are revealed.
- **Outputs** contain a Rescue Prime commitment to the amount, a stealth address for the recipient, and the note data (amount + blinding factor) encrypted to the recipient's Kyber key.
- **Balance proof** is a zk-STARK proving that all input and output commitments open correctly and that sum(inputs) = sum(outputs) + fee. The proof is bound to the `tx_content_hash` to prevent proof transplant attacks. No values are revealed.
- **Replay protection** — each transaction includes a `chain_id` (network identifier) and `expiry_epoch` (after which the tx is invalid), preventing cross-chain and stale-transaction replay.
- **tx_binding** — the hash of all transaction content, included in proof challenges. Any modification to inputs, outputs, fee, chain_id, or expiry_epoch invalidates the balance proof.
- **Messages** are Kyber-encrypted payloads (with 24-byte nonce + BLAKE3 MAC) that only the recipient can decrypt.
- **Transaction types** — in addition to regular transfers, transactions can carry validator registration or deregistration operations:
  - `ValidatorRegister` — includes the validator's Dilithium5 signing key. The fee must be at least `VALIDATOR_BOND + MIN_TX_FEE`; the bond is escrowed in chain state, and only the remainder goes to epoch fees. No zk-STARK modifications are needed — the bond is carried through the existing fee field.
  - `ValidatorDeregister` — includes the validator ID, an auth signature proving ownership, and a `TxOutput` that receives the returned bond (added to the commitment tree). The bond return is secured by the STARK system: if the validator creates a wrong commitment, it will fail verification when they try to spend.

## Zero-Knowledge Proof System

Spectra uses **zk-STARKs** (via the [winterfell](https://github.com/facebook/winterfell) library) for all transaction validity proofs:

### Dual Hash Design

- **Rescue Prime** (`Rp64_256` over the Goldilocks field) — used for all values proven inside STARK circuits: commitments, nullifiers, Merkle tree nodes
- **BLAKE3** — used for non-proven operations: vertex IDs, transaction IDs, state roots, VRF, network hashing

### Balance Proof (1 per transaction)

Proves in zero knowledge:
1. Each input/output commitment opens correctly under Rescue Prime
2. Sum of input values = sum of output values + fee
3. All values are in [0, 2^59) — prevents inflation via field-arithmetic wraparound
4. Proof is bound to the transaction's content hash

### Spend Proof (1 per input)

Proves in zero knowledge:
1. The nullifier is correctly derived: `Rescue(spend_auth, commitment) == nullifier`
2. The commitment exists as a leaf in the depth-20 Merkle tree with the given root
3. The proof_link is correctly derived: `Rescue(commitment, link_nonce) == proof_link`

### Proof Characteristics

| Property | Value |
|----------|-------|
| Trusted setup | None (transparent) |
| Post-quantum | Yes (hash-based) |
| Field | Goldilocks (p = 2^64 - 2^32 + 1) |
| Hash in circuit | Rescue Prime (Rp64_256) |
| Security | ~127-bit conjectured (Goldilocks quadratic extension max) |
| Range proof | 59-bit via bit decomposition (integrated in balance AIR) |
| Balance proof size | ~40 KB |
| Spend proof size | ~33 KB |

## Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `COMMITTEE_SIZE` | 21 | BFT committee members per epoch |
| `MIN_COMMITTEE_SIZE` | 4 | Minimum committee for BFT safety |
| `BFT_QUORUM` | dynamic | `(committee_size * 2) / 3 + 1` votes for finality |
| `EPOCH_LENGTH` | 1,000 | Vertices per epoch before rotation |
| `MAX_PARENTS` | 8 | Max parent references per DAG vertex |
| `MAX_TXS_PER_VERTEX` | 10,000 | Max transactions per vertex |
| `VERTEX_INTERVAL_MS` | 500 | Target interval between vertices |
| `MAX_MESSAGES_PER_TX` | 16 | Max messages per transaction |
| `MAX_MESSAGE_SIZE` | 64 KiB | Max encrypted message per transaction |
| `MAX_ENCRYPT_PLAINTEXT` | 1 MiB | Max plaintext for Kyber encryption |
| `MAX_NETWORK_MESSAGE_BYTES` | 16 MiB | Max serialized network message |
| `VALIDATOR_BOND` | 1,000,000 | Constant bond for validator registration |
| `MERKLE_DEPTH` | 20 | Canonical commitment tree depth (~1M outputs) |
| `RANGE_BITS` | 59 | Bit width for value range proofs |
| `MAX_TX_IO` | 16 | Max inputs or outputs per transaction (range-proof safe) |
| `MIN_TX_FEE` | 1 | Minimum transaction fee (prevents zero-fee spam) |
| `MEMPOOL_MAX_TXS` | 10,000 | Maximum transactions in the mempool |
| `MEMPOOL_MAX_BYTES` | 50 MiB | Maximum total mempool size |
| `DEFAULT_P2P_PORT` | 9,732 | Default P2P listen port |
| `DEFAULT_RPC_PORT` | 9,733 | Default JSON RPC port |
| `MAX_PEERS` | 64 | Maximum connected peers |
| `PEER_CONNECT_TIMEOUT_MS` | 5,000 | Peer connection timeout |
| `VERTEX_MAX_DRAIN` | 1,000 | Max transactions drained per vertex proposal |
| `SYNC_BATCH_SIZE` | 100 | Finalized vertices per sync request batch |
| `SYNC_REQUEST_TIMEOUT_MS` | 30,000 | Timeout for sync requests |

## Dependencies

| Crate | Purpose |
|-------|---------|
| `pqcrypto-dilithium` | CRYSTALS-Dilithium5 post-quantum signatures |
| `pqcrypto-kyber` | CRYSTALS-Kyber1024 post-quantum key encapsulation |
| `pqcrypto-traits` | Trait definitions for PQ crypto types |
| `blake3` | Fast, quantum-secure hashing |
| `winterfell` | zk-STARK prover/verifier (Rescue Prime, Goldilocks field) |
| `zeroize` | Secure memory clearing for secret key material |
| `serde` + `bincode` | Serialization |
| `rand` | Cryptographic randomness |
| `hex` | Hex encoding for display |
| `thiserror` | Error type derivation |
| `tokio` | Async runtime (P2P networking, node event loop) |
| `sled` | Embedded database for persistent storage |
| `axum` | JSON HTTP API framework |
| `clap` | CLI argument parsing |
| `serde_json` | JSON serialization for RPC |
| `tracing` + `tracing-subscriber` | Structured logging |
| `subtle` | Constant-time comparison for cryptographic checks |
| `reqwest` | HTTP client (rustls) for wallet RPC communication |
| `askama` + `askama_web` | Type-safe compiled HTML templates for wallet web UI |

## Security Model

### Zero-Knowledge Proofs

All transaction validity is verified via zk-STARKs:

- **Full zero knowledge** — validators verify correctness without learning any secret values (amounts, keys, output identities)
- **Sound** — a forged proof cannot pass verification without breaking the underlying hash function
- **Transparent** — no trusted setup required, all proofs are publicly verifiable
- **Post-quantum** — STARK security is hash-based, not reliant on discrete log or factoring

### Security Hardening

- **Vertex signature verification** — every DAG vertex must carry a valid Dilithium5 signature from its proposer; unsigned vertices are rejected at insertion time
- **Full transaction validation on apply** — `apply_transaction()` calls `validate_structure()` before any state mutation, verifying all zk-STARK proofs (balance + spend) and structural integrity
- **VRF anti-grinding** — VRF outputs include a `proof_commitment` (hash of the proof) enabling a commit-reveal scheme that prevents validators from grinding on epoch seeds
- **Plaintext size limits** — `encrypt_with_shared_secret` rejects plaintexts exceeding `MAX_ENCRYPT_PLAINTEXT`, preventing memory exhaustion attacks
- **Secure memory clearing** — all secret key material (`SigningSecretKey`, `KemSecretKey`, `SharedSecret`, `BlindingFactor`, `StealthSpendInfo`) is zeroized on drop via the `zeroize` crate
- **Vote round validation** — BFT `receive_vote()` rejects votes for rounds other than the current round, preventing future-round injection attacks
- **Chain-bound vote signatures** — vote signatures include `chain_id`, preventing cross-chain vote replay attacks
- **Transaction expiry enforcement** — `validate_structure()` enforces `expiry_epoch`, rejecting stale transactions
- **127-bit STARK security** — proof verification requires at least 127-bit conjectured security (maximum for Goldilocks quadratic extension), up from the original 95-bit threshold
- **BLAKE3 keyed MAC** — authenticated encryption uses `blake3::Hasher::new_keyed()` (proper keyed mode) rather than feeding key material as data
- **No plaintext metadata** — `TxMessage` contains only the encrypted payload; all routing tags and metadata are inside the ciphertext, preventing traffic analysis
- **Message count limits** — transactions are limited to 16 messages (`MAX_MESSAGES_PER_TX`), enforced during validation
- **KEM reuse for note encryption** — stealth address KEM shared secret is reused for encrypting note data, avoiding a redundant second KEM encapsulation per output
- **Domain-separated address IDs** — `address_id()` uses `hash_domain` for proper domain separation
- **Constant-time comparison** — all cryptographic verification (nullifiers, MACs, proof challenges, VRF outputs, tx bindings, stealth address detection) uses constant-time equality checks to prevent timing side-channel attacks
- **Length-prefixed hashing** — `hash_concat` encodes the length of each input before hashing, preventing domain confusion from concatenation ambiguity
- **Proof-link-bound proofs** — spend and balance proofs both derive the same proof_link from the commitment, preventing proof mix-and-match attacks while keeping the commitment private
- **Proof transplant prevention** — balance proofs include `tx_content_hash` in their public inputs, preventing a valid proof from being reused in a different transaction
- **Epoch-bound votes** — BFT vote signatures include the epoch number, preventing cross-epoch replay attacks
- **Round monotonicity** — DAG vertices must have a strictly higher round number than all parents, preventing causal ordering violations
- **Minimum committee size** — committee selection falls back to all active validators if VRF selects fewer than `MIN_COMMITTEE_SIZE`, guaranteeing BFT safety
- **Canonical Merkle depth** — commitment tree is always padded to depth 20 with precomputed zero-subtree hashes, ensuring consistent STARK circuit verification regardless of tree size
- **Range proofs** — all committed values are proven to be in [0, 2^59) via bit decomposition within the balance AIR; with MAX_IO = 16 per side, the maximum sum is 16 * 2^59 = 2^63 < p (Goldilocks), preventing inflation via field-arithmetic wraparound
- **Network message limits** — serialized messages are rejected above `MAX_NETWORK_MESSAGE_BYTES`; bincode deserialization uses size-limited options to prevent allocation-based DoS from crafted internal length fields
- **Cryptographic type size validation** — public keys, signatures, and KEM ciphertexts are validated on deserialization, rejecting malformed or oversized payloads
- **Deserialization bounds** — public input deserialization rejects unreasonable counts (> 256 inputs/outputs) to prevent allocation DoS
- **Overflow protection** — all arithmetic uses `checked_add` to prevent overflow; fee accumulation overflow is an explicit error
- **Transaction I/O limits** — inputs and outputs are capped at `MAX_TX_IO` (16), ensuring range proof sums stay within the Goldilocks field (16 * 2^59 < p) and preventing inflation via field-arithmetic wraparound
- **Complete content hash binding** — `tx_content_hash` covers all encrypted payload fields including MACs and KEM ciphertexts, preventing undetected tampering of encrypted notes or messages
- **Domain-separated hashing** — all critical hashes (`tx_id`, `vertex_id`, stealth key derivation, content hash) use BLAKE3 `new_derive_key` for proper cryptographic domain separation
- **Chain ID enforcement** — `apply_transaction()` explicitly checks `chain_id` against the chain state, providing defense-in-depth beyond the implicit binding via balance proofs
- **Minimum transaction fee** — `validate_structure()` enforces `MIN_TX_FEE`, preventing zero-fee spam; coinbase funding bypasses validation by adding outputs directly to state
- **MAC boundary protection** — the encrypt-then-MAC construction length-prefixes each variable-length field (ciphertext, KEM ciphertext) before computing the MAC, preventing boundary-ambiguity attacks
- **Equivocation detection** — BFT tracks `(voter_id, round) → vertex_id` and records `EquivocationEvidence` when a validator votes for conflicting vertices in the same round
- **Pending transaction tracking** — wallet outputs use a three-state lifecycle (Unspent → Pending → Spent) with explicit `confirm_transaction` / `cancel_transaction` to prevent double-spend of outputs in unconfirmed transactions
- **VRF commitment verification** — `VrfOutput::verify()` requires a pre-registered proof commitment, enforcing the commit-reveal anti-grinding scheme; `verify_locally()` is available for self-checks only
- **VRF-proven vertices and votes** — every non-genesis vertex and BFT vote must include a VRF proof demonstrating the proposer/voter was selected for the epoch's committee; vertices and votes without valid VRF proofs are rejected
- **Validator bond escrow** — registration requires `fee >= VALIDATOR_BOND + MIN_TX_FEE`; the bond is escrowed in chain state and only the remainder goes to epoch fees. Prevents unbonded validators from participating
- **Slashing** — equivocation evidence (voting for conflicting vertices in the same round) triggers automatic bond forfeiture to epoch fees and permanent validator exclusion
- **Deregistration auth** — validator deregistration requires a signature over `"spectra.validator.deregister" || chain_id || validator_id || tx_content_hash`, preventing unauthorized bond withdrawal
- **Two-phase vertex finalization** — vertices are inserted into the DAG (unfinalized) first, then finalized only after BFT quorum certification, preventing premature state application
- **Persistent validator keypair** — the validator's Dilithium5 keypair is persisted to disk with raw byte serialization and validated on load, preventing key loss across restarts
- **Inbound connection timeout** — P2P inbound handshakes are wrapped in a configurable timeout (`PEER_CONNECT_TIMEOUT_MS`), preventing slowloris-style connection exhaustion
- **Merkle tree capacity enforcement** — the incremental Merkle tree rejects appends beyond `2^MERKLE_DEPTH` leaves, preventing silent overflow
- **Bounded DAG traversal** — ancestor queries are depth-bounded (default `2 * EPOCH_LENGTH`), preventing unbounded memory usage from deep graph exploration
- **Secret key encapsulation** — `SigningSecretKey` and `KemSecretKey` inner bytes are `pub(crate)`, preventing external crates from directly reading secret key material
- **RPC localhost binding** — the RPC server binds to `127.0.0.1` by default, requiring explicit opt-in (`--rpc-addr 0.0.0.0:9733`) for network exposure

## Production Roadmap

Spectra includes a full node implementation with P2P networking, persistent storage, state sync, mempool, RPC API, on-chain validator registration with bond escrow, active BFT consensus participation, VRF-proven committee membership, and a client-side wallet CLI. A production deployment would additionally require:

- **Post-quantum handshakes** — upgrade the P2P transport layer with Noise/Kyber for quantum-resistant peer connections
- **Peer reputation and discovery** — DHT-based peer discovery, reputation scoring, and ban management
- **Wallet GUI** — graphical interface for non-technical users
- **Formal security audit** — cryptographic protocol review and implementation audit

## License

MIT
