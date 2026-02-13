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
| Signatures | CRYSTALS-Dilithium5 (ML-DSA-87) | NIST Level 5 (~256-bit classical) |
| Key encapsulation | CRYSTALS-Kyber1024 (ML-KEM-1024) | NIST Level 5 |
| Commitments & Merkle tree | Rescue Prime (Rp64_256) | STARK-friendly, post-quantum |
| General hashing | BLAKE3 | 256-bit (128-bit quantum via Grover) |
| Zero-knowledge proofs | zk-STARKs (winterfell) | ~127-bit conjectured security |

No trusted setup is required. All proofs are transparent. The P2P transport layer uses the same post-quantum primitives (Kyber1024 for key exchange, Dilithium5 for mutual authentication, BLAKE3 for encryption and MACs), so all node-to-node communication is quantum-resistant.

### Coin Emission

- **Genesis mint** — the genesis validator receives an initial distribution of 100,000,000 units at network bootstrap, seeding the economy before block rewards begin
- **Block rewards** — each finalized vertex creates new coins for the proposer via a coinbase output (commitment + stealth address + encrypted note), the same format as any other output in the commitment tree
- **Halving schedule** — initial reward of 50,000 units per vertex, halving every 500 epochs (~500,000 vertices per phase), reaching zero after 63 halvings
- **Fee distribution** — transaction fees go to the vertex proposer via coinbase output and also accumulate in epoch-level accounting, added on top of the block reward
- **Deterministic blinding** — coinbase blinding factors are derived from `hash_domain("spectra.coinbase.blinding", vertex_id || epoch)`, making amounts publicly verifiable while maintaining consistent commitment tree format
- **Total supply tracking** — `total_minted` is tracked in the chain state and included in the state root hash, enabling consensus-verifiable supply accounting

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
    config.rs               TOML config file support (spectra.toml)
    bip39_words.rs          BIP39 English wordlist (2048 words) for wallet recovery
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
      dag.rs                DAG data structure (vertices with VRF proofs, protocol version, pruning)
      bft.rs                BFT voting with VRF proofs, certification, committee selection
    mempool.rs              Fee-priority transaction pool with nullifier conflict detection + fee estimation
    storage.rs              Persistent storage trait + sled backend (vertices, txs, validators)
    p2p.rs                  Encrypted P2P networking with peer reputation and connection diversity
    node.rs                 Node orchestrator: consensus, Dandelion++, peer discovery, protocol signaling
    rpc.rs                  JSON HTTP API: tx, state, health, metrics, fee-estimate, light client endpoints
    state.rs                Chain state (bonds, slashing, sled-backed nullifiers), Ledger, parallel verification
    network.rs              P2P wire protocol (message types, KEM handshake, auth messages)
    wallet.rs               Key management, scanning, tx building, history, recovery, consolidation
    wallet_cli.rs           Wallet CLI commands (init, send, balance, history, consolidate, recover)
    wallet_web.rs           Wallet web UI (askama templates, axum server)
    main.rs                 Node + wallet binary with clap subcommands and config file loading
  templates/
    base.html               Base layout with navigation and CSS
    dashboard.html          Balance, outputs, chain state, scan button
    init.html               Wallet creation page
    address.html            Address display and export
    send.html               Transaction send form
    send_result.html        Transaction submission result
    messages.html           Encrypted message list
    history.html            Transaction history table
    error.html              Error display
```

**~18,000 lines of Rust** across 36 source files with **294 tests**.

## Building

Requires a C compiler (for the PQClean backends used by `pqcrypto-dilithium` and `pqcrypto-kyber`).

```bash
cargo build --release
```

## Running a Node

```bash
cargo run --release -- node [OPTIONS]
```

### Configuration

The node loads `spectra.toml` from the data directory if present. CLI flags override config file values. If no config file exists, defaults are used.

```toml
# spectra.toml (optional)
[node]
p2p_host = "0.0.0.0"
p2p_port = 9732
rpc_host = "127.0.0.1"
rpc_port = 9733
bootstrap_peers = ["192.168.1.10:9732", "192.168.1.11:9732"]
genesis_validator = false
max_peers = 64

[wallet]
web_host = "127.0.0.1"
web_port = 9734
```

### CLI Options

The binary uses subcommands (`node`, `wallet`). Running without a subcommand defaults to node mode for backward compatibility.

**Global flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--data-dir` | `./spectra-data` | Data directory for persistent storage |
| `--rpc-host` | `127.0.0.1` | RPC listen host (localhost by default for safety) |
| `--rpc-port` | `9733` | RPC listen port |
| `--demo` | *(off)* | Run the protocol demo walkthrough instead |

**Node flags** (`spectra node`):

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` | P2P listen host |
| `--port` | `9732` | P2P listen port |
| `--peers` | *(none)* | Comma-separated bootstrap peer addresses |
| `--genesis-validator` | *(off)* | Register as a genesis validator (for bootstrapping a new network) |

### Examples

```bash
# Start a node with default settings
cargo run --release

# Start as a genesis validator (bootstraps a new network)
cargo run --release -- node --genesis-validator

# Start with custom addresses and a bootstrap peer
cargo run --release -- --rpc-host 127.0.0.1 --rpc-port 9001 node --host 127.0.0.1 --port 9000 --peers 192.168.1.10:9732

# Run the protocol demo
cargo run --release -- --demo
```

## Wallet CLI

The wallet runs client-side — it downloads finalized vertices (including coinbase outputs) from the node and scans them locally. The node never learns which outputs belong to the wallet.

```bash
cargo run --release -- wallet <command>
```

### Wallet Commands

| Command | Description |
|---------|-------------|
| `init` | Create a new wallet, display 24-word recovery phrase, and save encrypted backup |
| `address` | Show wallet address ID and re-export address file |
| `balance` | Scan the chain and show current balance |
| `scan` | Scan the chain for new outputs (without showing balance) |
| `send` | Build and submit a transaction |
| `messages` | Show received encrypted messages |
| `history` | Show transaction history (sends, receives, coinbase rewards) |
| `consolidate` | Merge all unspent outputs into a single output |
| `recover` | Recover a wallet from a 24-word mnemonic phrase and backup file |
| `export` | Export wallet address to a file for sharing |

### Wallet Examples

```bash
# Create a new wallet (displays 24-word recovery phrase — write it down!)
cargo run --release -- wallet init

# Check balance (scans chain first)
cargo run --release -- wallet balance

# Send 1000 units to a recipient
cargo run --release -- wallet send --to ./bob.spectra-address --amount 1000 --fee 10

# Send with an encrypted message
cargo run --release -- wallet send --to ./bob.spectra-address --amount 500 --fee 10 --message "Payment for services"

# View received messages
cargo run --release -- wallet messages

# View transaction history
cargo run --release -- wallet history

# Consolidate all UTXOs into one output
cargo run --release -- wallet consolidate --fee 10

# Recover a wallet from backup (requires wallet.recovery file in data dir)
cargo run --release -- wallet recover --phrase "abandon ability able about ..."

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
cargo run --release -- --rpc-host 127.0.0.1 --rpc-port 9733 wallet web --host 0.0.0.0 --port 8080
```

Open `http://127.0.0.1:9734` in your browser. If no wallet exists, you'll be prompted to create one.

**Pages:**
- **Dashboard** (`/`) — balance, output counts, chain state, scan button
- **Send** (`/send`) — build and submit transactions with optional encrypted messages
- **Messages** (`/messages`) — view received encrypted messages
- **History** (`/history`) — transaction history (sends, receives, coinbase rewards)
- **Address** (`/address`) — view and export wallet address for sharing

## RPC API

The node exposes a JSON HTTP API (default `127.0.0.1:9733`, localhost-only for safety).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/tx` | Submit a hex-encoded bincode-serialized transaction |
| `GET` | `/tx/{id}` | Look up a transaction by ID (checks mempool then storage) |
| `GET` | `/state` | Query chain state (epoch, counts, roots, total minted) |
| `GET` | `/peers` | List connected peers |
| `GET` | `/mempool` | Get mempool statistics |
| `GET` | `/validators` | List all validators with bond and status |
| `GET` | `/validator/{id}` | Get a single validator's info |
| `GET` | `/vertices/finalized` | Paginated finalized vertices with coinbase outputs (`?after=N&limit=N`) |
| `GET` | `/health` | Health check: status, version, uptime, peer count, epoch, sync state |
| `GET` | `/metrics` | Prometheus-format metrics: uptime, peers, epoch, mempool stats |
| `GET` | `/fee-estimate` | Fee estimation: percentiles (p10–p90), median, suggested fee |
| `GET` | `/vertex/{id}` | Look up a vertex by ID (checks DAG then storage) |
| `GET` | `/commitment-proof/{index}` | Merkle inclusion proof for a commitment at the given index |
| `GET` | `/state-summary` | Light client state summary: roots, epoch, counts, active validators |

### Example

```bash
# Query chain state
curl http://localhost:9733/state

# Health check
curl http://localhost:9733/health

# Prometheus metrics
curl http://localhost:9733/metrics

# Fee estimation
curl http://localhost:9733/fee-estimate

# Check mempool stats
curl http://localhost:9733/mempool

# List all validators
curl http://localhost:9733/validators

# Look up a transaction
curl http://localhost:9733/tx/abc123...

# Look up a vertex
curl http://localhost:9733/vertex/abc123...

# Light client state summary
curl http://localhost:9733/state-summary

# Merkle proof for commitment at index 42
curl http://localhost:9733/commitment-proof/42

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
- Expired transaction eviction — `evict_expired()` removes transactions past their `expiry_epoch`
- Configurable size limits: max 10,000 transactions / 50 MiB (default)

### Persistent Storage

`Storage` trait with a [sled](https://docs.rs/sled) embedded database backend:

- **8 named trees**: `vertices`, `transactions`, `nullifiers`, `chain_meta`, `commitment_levels`, `validators`, `finalized_index`, `coinbase_outputs`
- All values are bincode-serialized; keys are raw 32-byte hashes (finalized_index and coinbase_outputs use big-endian sequence numbers)
- `ChainStateMeta` captures full chain state snapshots (epoch, roots, counts, finalized count, total minted) for persistence
- Commitment level storage enables Merkle tree reconstruction on restart
- Finalized vertex index supports paginated retrieval for wallet sync and state sync
- `open_temporary()` provides in-memory storage for testing

### P2P Networking

Async TCP transport built on tokio with post-quantum encrypted channels:

- `P2pHandle` — clone-friendly handle for sending commands (connect, broadcast, send, shutdown)
- `P2pEvent` — events received by the node (peer connected/disconnected, message received)
- **Encrypted transport** — all peer connections are encrypted and mutually authenticated:
  1. Hello exchange (plaintext) — version check + Kyber1024 public key exchange
  2. Kyber1024 KEM handshake — initiator encapsulates to responder's KEM public key
  3. Dilithium5 mutual authentication — both sides sign a transcript hash binding peer IDs + KEM ciphertext
  4. BLAKE3-based XOR keystream cipher with counter-based nonces for all subsequent messages
  5. Keyed-BLAKE3 MAC on every encrypted frame; counter-based replay protection
  6. Domain-separated session key derivation — initiator and responder derive mirrored send/recv keys from the shared secret
- **Per-peer rate limiting** — token-bucket rate limiter (100 msgs/sec refill, 200 burst); peers exceeding limits are warned and disconnected after 5 violations
- Configurable max peers (default 64) and connection timeout (5 seconds)

### Node Orchestrator

The `Node` struct ties everything together with a `tokio::select!` event loop:

- **Persistent validator identity** — signing and KEM keypairs are saved to `data_dir/validator.key` on first run and loaded on subsequent startups (legacy key files without KEM are auto-upgraded)
- **Active consensus participation** — when selected for the committee via VRF, the node proposes vertices (draining high-fee transactions from the mempool) and casts BFT votes on incoming vertices
- **Liveness guarantee** — vertices are proposed even when the mempool is empty, ensuring epoch advancement and coinbase emission regardless of transaction volume
- **Two-phase vertex flow** — vertices are first inserted into the DAG (unfinalized), then finalized after receiving a BFT quorum certificate. Finalization applies transactions to state, creates a coinbase output for the proposer, purges conflicting mempool entries, persists to storage, and slashes equivocators
- **Epoch management** — after `EPOCH_LENGTH` finalized vertices, the epoch advances with a new VRF seed derived from the state root. Newly registered validators activate in the next epoch (activation delay prevents mid-epoch committee manipulation)
- **State persistence** — every finalized vertex persists its transactions, nullifiers, Merkle tree nodes, finalized index, coinbase output, validators, and a `ChainStateMeta` snapshot to storage, then flushes. On restart the full chain state (Merkle tree, nullifier set, validators, epoch state, total minted) is restored from the snapshot
- **Graceful shutdown** — accepts a `CancellationToken`; Ctrl-C triggers clean shutdown (flush storage, shutdown P2P, log exit)
- **Dandelion++ transaction relay** — new transactions enter a stem phase (forwarded to one random peer for `DANDELION_STEM_HOPS` hops), then fluff (broadcast to all) after hops exhaust or `DANDELION_TIMEOUT_MS` expires, providing sender anonymity
- **Peer discovery gossip** — periodic `GetPeers` / `PeersResponse` exchange (every `PEER_EXCHANGE_INTERVAL_MS`) discovers up to `PEER_DISCOVERY_MAX` new peers per round
- **Protocol version signaling** — vertices carry a `protocol_version` field; the node tracks version signals per epoch and logs activation when a version exceeds 75% threshold (effective epoch+2)
- **DAG memory pruning** — on epoch transition, finalized vertices older than `PRUNING_RETAIN_EPOCHS` are pruned from in-memory maps (retained in sled for sync)
- **State sync with timeout/retry** — new nodes joining the network request finalized vertices in batches from peers via `GetFinalizedVertices` / `FinalizedVerticesResponse` messages. A three-state machine (`NeedSync → Syncing → Synced`) tracks sync progress. Unresponsive peers are timed out after `SYNC_REQUEST_TIMEOUT_MS` and placed on cooldown before retrying with another peer
- **Fork resolution** — if no vertex is finalized for `VIEW_CHANGE_TIMEOUT_INTERVALS` proposal ticks or peers report rounds more than `MAX_ROUND_LAG` ahead, the node broadcasts `GetTips` and `GetEpochState` to discover and fetch missing vertices
- **Mempool expiry eviction** — expired transactions are periodically evicted from the mempool (every ~50 seconds and on epoch transitions)
- Shared state via `Arc<RwLock<NodeState>>` (ledger + mempool + storage + BFT state)
- Genesis bootstrap via `--genesis-validator` flag (registers the node with bond escrowed and KEM key for coinbase, no funding tx required)

## Testing

```bash
cargo test
```

All 294 tests cover:

- **Core utilities** — hash_domain determinism, domain separation, hash_concat length-prefix ambiguity prevention, constant-time equality
- **Post-quantum crypto** — key generation, signing, KEM roundtrips
- **Stealth addresses** — generation, detection, multi-index scanning, spend auth derivation determinism, index-dependent key uniqueness
- **Rescue Prime** — commitments, field element conversions
- **Nullifiers** — determinism, double-spend detection
- **Merkle tree** — construction, path verification, depth-20 canonical padding, restore from stored level data, last-appended path coverage
- **Encryption** — message roundtrips, authentication, tamper detection
- **VRF** — evaluation, verification, committee selection statistics
- **DAG** — insertion, diamond merges, finalized ordering, tip tracking, duplicate rejection, finalization status, topological sort of complex graphs, finalized count tracking, pruning of old finalized vertices; validation of too many parents, too many transactions, duplicate parents, no parents on non-genesis, too many unfinalized (DoS limit); finalized order excludes non-finalized vertices; finalize unknown vertex returns false; safe indexing after pruning (regression)
- **BFT** — vote collection, leader rotation, duplicate rejection, cross-epoch replay prevention, equivocation detection/clearing, quorum certification, multi-round certificate tracking, round advancement; wrong-round vote rejection, non-committee voter rejection, invalid signature rejection, reject votes don't count toward quorum, committee-of-one certification, fallback preserves all validators without truncation (regression), rejection_count accuracy, advance_epoch clears all state
- **Network** — message serialization roundtrips, oversized message rejection, sync message roundtrips (GetFinalizedVertices, FinalizedVerticesResponse), peer discovery messages, epoch state responses
- **Transactions** — ID determinism, content hash determinism, estimated size, deregister sign data; validation of all error paths (no inputs/outputs, too many inputs/outputs, duplicate nullifiers, expired, fee too low, invalid binding, too many messages, message too large, insufficient bond, invalid validator key size (regression), invalid KEM key size, zero bond return commitment, proof link cross-check mismatch (regression), no-expiry passthrough, expiry boundary epoch)
- **Transaction builder** — STARK proof generation, chain ID and expiry, multi-input/multi-output, input/output limit enforcement
- **RPC endpoints** — GET /state, /mempool, /validators, /validator/:id (found and not-found), /tx/:id (found, not-found, invalid hex, wrong length), /vertices/finalized, /peers; POST /tx (valid submission, invalid hex, valid hex with invalid bincode, duplicate submission, oversized payload); full submit-and-retrieve roundtrip
- **Wallet** — scanning, balance tracking, spending with change, pending transaction confirm/cancel, balance excludes pending, keypair preservation; file save/load roundtrip (keys, outputs, messages, pending status, history); transaction history recording (send, receive, coinbase); mnemonic generation and roundtrip with checksum validation; recovery backup encrypt/decrypt; UTXO consolidation (success path with history, fee exceeds total); pending output expiry (basic, not-yet-expired, exact boundary epoch); insufficient funds and arithmetic overflow; saturating balance addition; history cap enforcement; coinbase output scanning
- **Wallet CLI** — init with recovery phrase (creates wallet + backup files), recover from mnemonic + backup, history display, address display, export creates valid address file, messages on empty wallet
- **End-to-end** — fund, transfer, message decrypt, bystander non-detection
- **Mempool** — fee-priority ordering, nullifier conflict detection, eviction, drain, expired transaction eviction, fee percentile estimation (empty, single-tx edge case, populated pools); byte-limit eviction with total_bytes tracking, fee boundary rejection (equal fee rejected), drain cleans nullifier index, epoch-based expiry on insert, total_bytes accuracy across insert/remove/drain
- **Storage** — vertex/transaction/nullifier/validator/coinbase persistence and roundtrips, not-found returns None, vertex overwrite, chain state meta roundtrips (including total_minted), finalized index roundtrip and batch retrieval
- **State** — genesis validator registration and query, bond slashing, epoch advancement (fee reset, seed rotation), inactive validator tracking, last-finalized tracking, sled-backed nullifier lookups, nullifier migration from memory to sled; apply_vertex (basic state transition, too many transactions, intra-vertex duplicate nullifier, epoch fee accumulation regression); validate_transaction (wrong chain_id, double spend, already registered); record_nullifier Result return type (regression); coinbase output creation (with and without KEM key); eligible_validators activation epoch filtering
- **P2P** — encrypted peer connection establishment, Kyber KEM handshake + Dilithium5 mutual auth, encrypted message exchange, session key symmetry, encrypted transport roundtrip, token-bucket rate limiting (burst, refill, over-burst rejection); peer reputation penalize-to-ban, ban expiry, reward recovery; MAC verification failure on corrupted frames; counter replay rejection; self-connection detection
- **Node** — persistent signing + KEM keypair load/save roundtrip
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
  - `ValidatorRegister` — includes the validator's Dilithium5 signing key and Kyber1024 KEM public key (required for receiving coinbase rewards). The fee must be at least `VALIDATOR_BOND + MIN_TX_FEE`; the bond is escrowed in chain state, and only the remainder goes to epoch fees. No zk-STARK modifications are needed — the bond is carried through the existing fee field.
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
| `INITIAL_BLOCK_REWARD` | 50,000 | Coinbase reward per vertex (halves over time) |
| `HALVING_INTERVAL_EPOCHS` | 500 | Epochs between each reward halving |
| `MAX_HALVINGS` | 63 | Halvings before reward reaches zero |
| `GENESIS_MINT` | 100,000,000 | Initial coin distribution to the genesis validator |
| `MEMPOOL_MAX_TXS` | 10,000 | Maximum transactions in the mempool |
| `MEMPOOL_MAX_BYTES` | 50 MiB | Maximum total mempool size |
| `DEFAULT_P2P_PORT` | 9,732 | Default P2P listen port |
| `DEFAULT_RPC_PORT` | 9,733 | Default JSON RPC port |
| `MAX_PEERS` | 64 | Maximum connected peers |
| `PEER_CONNECT_TIMEOUT_MS` | 5,000 | Peer connection timeout |
| `VERTEX_MAX_DRAIN` | 1,000 | Max transactions drained per vertex proposal |
| `SYNC_BATCH_SIZE` | 100 | Finalized vertices per sync request batch |
| `SYNC_REQUEST_TIMEOUT_MS` | 30,000 | Timeout for sync requests |
| `SYNC_PEER_COOLDOWN_MS` | 60,000 | Cooldown before retrying a failed sync peer |
| `PEER_MSG_RATE_LIMIT` | 100.0 | Per-peer message rate limit (msgs/sec refill) |
| `PEER_MSG_BURST` | 200.0 | Per-peer max burst messages |
| `PEER_RATE_LIMIT_STRIKES` | 5 | Rate violations before disconnecting peer |
| `VIEW_CHANGE_TIMEOUT_INTERVALS` | 10 | Proposal ticks without finalization before fork resolution |
| `MAX_ROUND_LAG` | 5 | Max rounds behind peers before triggering view change |
| `PEER_EXCHANGE_INTERVAL_MS` | 60,000 | Interval between peer discovery gossip rounds |
| `PEER_DISCOVERY_MAX` | 5 | Max new peers to connect per discovery round |
| `DANDELION_STEM_HOPS` | 2 | Stem-phase hops before fluff broadcast |
| `DANDELION_TIMEOUT_MS` | 5,000 | Max stem phase duration before forced fluff |
| `PEER_INITIAL_REPUTATION` | 100 | Starting reputation score for new peers |
| `PEER_BAN_THRESHOLD` | 20 | Reputation below which peers are temp-banned |
| `PEER_BAN_DURATION_SECS` | 3,600 | Duration of temporary peer ban (1 hour) |
| `PEER_PENALTY_RATE_LIMIT` | 10 | Reputation penalty for rate limit violation |
| `PEER_PENALTY_INVALID_MSG` | 20 | Reputation penalty for invalid message |
| `PEER_PENALTY_HANDSHAKE_FAIL` | 30 | Reputation penalty for handshake failure |
| `PRUNING_RETAIN_EPOCHS` | 100 | Epochs of finalized vertices retained in memory |
| `PROTOCOL_VERSION_ID` | 1 | Current protocol version for vertex signaling |
| `UPGRADE_THRESHOLD` | 75% | Signal threshold for protocol upgrade activation |

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
| `tokio-util` | Graceful shutdown via `CancellationToken` |
| `toml` | TOML config file parsing |
| `rayon` | Parallel proof verification for vertex validation |

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
- **Deserialization bounds** — public input deserialization rejects counts exceeding `MAX_TX_IO` (16 inputs/outputs) to prevent allocation DoS
- **Overflow protection** — all arithmetic uses `checked_add` to prevent overflow; fee accumulation overflow is an explicit error
- **Transaction I/O limits** — inputs and outputs are capped at `MAX_TX_IO` (16), ensuring range proof sums stay within the Goldilocks field (16 * 2^59 < p) and preventing inflation via field-arithmetic wraparound
- **Complete content hash binding** — `tx_content_hash` covers all encrypted payload fields including MACs and KEM ciphertexts, preventing undetected tampering of encrypted notes or messages
- **Domain-separated hashing** — all critical hashes (`tx_id`, `vertex_id`, stealth key derivation, content hash) use BLAKE3 `new_derive_key` for proper cryptographic domain separation
- **Chain ID enforcement** — `apply_transaction()` explicitly checks `chain_id` against the chain state, providing defense-in-depth beyond the implicit binding via balance proofs
- **Minimum transaction fee** — `validate_structure()` enforces `MIN_TX_FEE`, preventing zero-fee spam; coinbase funding bypasses validation by adding outputs directly to state
- **MAC boundary protection** — the encrypt-then-MAC construction length-prefixes each variable-length field (ciphertext, KEM ciphertext) before computing the MAC, preventing boundary-ambiguity attacks
- **Equivocation detection** — BFT tracks `(voter_id, round) → vertex_id` and records `EquivocationEvidence` when a validator votes for conflicting vertices in the same round
- **Pending transaction tracking** — wallet outputs use a three-state lifecycle (Unspent → Pending → Spent) with explicit `confirm_transaction` / `cancel_transaction` and automatic expiry after `PENDING_EXPIRY_EPOCHS` to prevent double-spend of outputs in unconfirmed transactions and recover stuck funds
- **VRF commitment verification** — `VrfOutput::verify()` requires a pre-registered proof commitment, enforcing the commit-reveal anti-grinding scheme; `verify_locally()` is available for self-checks only
- **VRF-proven vertices and votes** — every non-genesis vertex and BFT vote must include a VRF proof demonstrating the proposer/voter was selected for the epoch's committee; vertices and votes without valid VRF proofs are rejected
- **Validator bond escrow** — registration requires `fee >= VALIDATOR_BOND + MIN_TX_FEE`; the bond is escrowed in chain state and only the remainder goes to epoch fees. Prevents unbonded validators from participating
- **Slashing** — equivocation evidence (voting for conflicting vertices in the same round) triggers automatic bond forfeiture to epoch fees and permanent validator exclusion
- **Deregistration auth** — validator deregistration requires a signature over `"spectra.validator.deregister" || chain_id || validator_id || tx_content_hash`, preventing unauthorized bond withdrawal
- **Two-phase vertex finalization** — vertices are inserted into the DAG (unfinalized) first, then finalized only after BFT quorum certification, preventing premature state application
- **Persistent validator keypair** — the validator's Dilithium5 signing and Kyber1024 KEM keypairs are persisted to disk with raw byte serialization and validated on load, preventing key loss across restarts
- **Deterministic coinbase blinding** — coinbase output blinding factors are derived from `hash_domain("spectra.coinbase.blinding", vertex_id || epoch)`, making amounts publicly verifiable while using the same commitment format as private outputs
- **Consensus-verifiable supply** — `total_minted` is included in the state root hash, so any disagreement on emission is detected by state root divergence
- **Fee redirection fallback** — if a vertex proposer lacks a KEM key (cannot receive coinbase), fees are returned to the epoch fee pool rather than being lost
- **Post-quantum encrypted transport** — all P2P connections use Kyber1024 KEM for key exchange and Dilithium5 for mutual authentication, followed by BLAKE3-based XOR keystream encryption with keyed-BLAKE3 MACs, providing quantum-resistant confidentiality and integrity for all inter-node communication
- **Transport replay protection** — encrypted frames include monotonic counters; out-of-order or replayed frames are rejected
- **Transcript-bound authentication** — handshake auth signatures cover a transcript hash binding both peer IDs and the KEM ciphertext, preventing relay and MITM attacks
- **Per-peer rate limiting** — token-bucket rate limiter per connection (100 msgs/sec refill, 200 burst); peers exceeding limits are warned and disconnected after 5 strikes, preventing message-flooding DoS
- **Sync timeout and peer cooldown** — sync requests that receive no response within `SYNC_REQUEST_TIMEOUT_MS` trigger a fallback to another peer; failed peers are placed on a 60-second cooldown to prevent retry storms
- **Fork resolution / view change** — if no vertex is finalized for a configurable timeout or peers report rounds significantly ahead, the node proactively requests tips and missing vertices to rejoin consensus
- **Epoch committee activation delay** — newly registered validators only become eligible for committee selection in the epoch after registration, preventing mid-epoch committee manipulation
- **Mempool expiry eviction** — transactions past their `expiry_epoch` are periodically removed from the mempool, preventing stale transaction accumulation
- **Liveness guarantee** — empty vertices (no transactions) are proposed when the mempool is empty, ensuring epochs advance and coinbase emission continues
- **Inbound connection timeout** — P2P inbound handshakes are wrapped in a configurable timeout (`PEER_CONNECT_TIMEOUT_MS`), preventing slowloris-style connection exhaustion
- **Merkle tree capacity enforcement** — the incremental Merkle tree rejects appends beyond `2^MERKLE_DEPTH` leaves, preventing silent overflow
- **Bounded DAG traversal** — ancestor queries are depth-bounded (default `2 * EPOCH_LENGTH`), preventing unbounded memory usage from deep graph exploration
- **Secret key encapsulation** — `SigningSecretKey` and `KemSecretKey` inner bytes are `pub(crate)`, preventing external crates from directly reading secret key material
- **RPC localhost binding** — the RPC server binds to `127.0.0.1` by default, requiring explicit opt-in (`--rpc-host 0.0.0.0`) for network exposure
- **Wallet recovery phrases** — 24-word BIP39 mnemonic with BLAKE3 checksum; key material encrypted with a BLAKE3-derived keystream. Both the phrase and the encrypted backup file are required for recovery, preventing single-point-of-failure key loss
- **Sled-backed nullifier storage** — nullifier lookups check in-memory set first, then fall back to sled, allowing the nullifier set to scale beyond available RAM
- **Parallel proof verification** — vertex validation uses `rayon::par_iter()` for independent transaction proof verification, with sequential state mutation, maintaining correctness while improving throughput
- **Dandelion++ sender privacy** — new transactions propagate through a stem phase (private forwarding to single peers) before fluff (broadcast), obscuring the originating node
- **Connection diversity** — inbound and outbound peer slots are tracked separately, reserving half of max peers for each direction, preventing eclipse attacks via inbound slot exhaustion
- **Peer reputation and banning** — peers accumulate reputation penalties for rate limit violations, invalid messages, and handshake failures; peers below threshold are temporarily banned (1 hour) with bans persisted to storage
- **DAG memory pruning** — finalized vertices older than `PRUNING_RETAIN_EPOCHS` are pruned from in-memory maps on epoch transition, preventing unbounded memory growth while retaining data in sled for sync
- **Protocol version signaling** — vertices carry a protocol version; upgrade activation requires 75% of signals in an epoch, with a two-epoch grace period before enforcement
- **Intra-vertex double-spend prevention** — before validating a vertex's transactions, all nullifiers within the vertex are checked for duplicates, preventing cross-transaction double-spends within a single vertex
- **Duplicate validator operation prevention** — a vertex cannot contain multiple `ValidatorRegister` or `ValidatorDeregister` operations for the same validator, preventing state confusion from duplicate operations
- **Unfinalized vertex limit** — the DAG rejects new vertices when unfinalized count exceeds 10,000, preventing memory exhaustion from spam vertices that never achieve BFT certification
- **VRF safe arithmetic** — committee selection threshold uses u128 cross-multiplication to prevent integer overflow that could bias selection probability
- **RPC body size limit** — all RPC requests are capped at 2 MB via `DefaultBodyLimit`, preventing memory exhaustion from oversized payloads
- **Transaction hex validation** — `POST /tx` rejects hex payloads exceeding `2 * MAX_NETWORK_MESSAGE_BYTES` before attempting deserialization, preventing allocation-based DoS
- **Sync vertex validation** — vertices received during state sync are validated through `apply_finalized_vertex()` (full signature verification + DAG insertion), not applied directly to state
- **Gossip deduplication** — a two-generation `seen_messages` scheme (10K capacity per generation) prevents re-processing and re-broadcasting of duplicate vertices, votes, and certificates without bulk-clearing recently seen entries
- **Sync bounds checking** — sync is cancelled after 1,000 rounds or if a peer claims an unreasonably high finalized count, preventing infinite sync attacks from malicious peers
- **Self-connection prevention** — P2P connections to the node's own peer ID are rejected on establishment
- **Handshake concurrency limit** — a semaphore limits concurrent P2P handshakes to 64, preventing resource exhaustion from handshake flooding
- **Deferred stem mempool insertion** — Dandelion++ stem-phase transactions are forwarded without being added to the local mempool, preventing timing analysis that could deanonymize the transaction origin
- **Wallet web security headers** — the wallet web UI sets `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, and `Content-Security-Policy` on all responses
- **Atomic wallet file writes** — wallet data is written to a temporary file then atomically renamed, preventing data loss from interrupted writes
- **Non-blocking wallet I/O** — synchronous wallet file operations are wrapped in `spawn_blocking()` to avoid blocking the async runtime
- **XOR keystream per-block derivation** — the BLAKE3 keystream incorporates the block index into each `derive_key` call, ensuring unique keystream blocks for wallet recovery encryption
- **Error message sanitization** — wallet CLI error messages do not expose internal file paths to users; details are logged server-side via `tracing::error!`
- **Mnemonic zeroization** — recovery phrase words are zeroized from memory immediately after display to minimize secret exposure window
- **Multi-transaction mempool eviction** — when the mempool is full, lowest-fee transactions are evicted in a loop until space is available, rather than evicting only one
- **Cached finalized vertex count** — `finalized_vertex_count()` uses an `AtomicU64` cache instead of scanning the sled tree, improving performance for health and metrics endpoints
- **Validator key size validation** — `ValidatorRegister` transactions validate that signing keys are exactly 2592 bytes (Dilithium5) and KEM keys are exactly 1568 bytes (Kyber1024), rejecting malformed keys
- **Nullifier persistence propagation** — sled write failures in `record_nullifier()` propagate as errors through `apply_vertex()`, preventing silent state desynchronization between memory and storage that could allow double-spends after restart
- **Sync epoch validation** — finalized vertices received during sync are rejected if their epoch exceeds the sync peer's claimed epoch + 1, preventing malicious peers from advancing local state to fabricated future epochs
- **Proof link cross-validation** — each spend proof's `proof_link` is cross-checked against the corresponding entry in the balance proof's `input_proof_links`, providing defense-in-depth against proof_link tampering
- **Web message size validation** — the wallet web UI validates message size against `MAX_MESSAGE_SIZE` before building transactions, preventing unnecessary proof generation for oversized messages
- **Concurrent wallet mutation lock** — the wallet web UI serializes send and scan operations via a tokio Mutex, preventing race conditions that could cause double-spending from concurrent requests
- **DAG safe indexing** — `finalized_order()` uses fallible `.get()` lookups instead of panicking `[]` indexing, gracefully handling edge cases where finalized vertices may be missing from the in-memory map after pruning

## Production Roadmap

Spectra includes a full node implementation with encrypted P2P networking (Kyber1024 + Dilithium5), persistent storage, state sync with timeout/retry, fee-priority mempool with fee estimation and expiry eviction, health/metrics endpoints, TOML configuration, graceful shutdown, Dandelion++ transaction relay, peer discovery gossip, peer reputation with ban persistence, connection diversity, protocol version signaling, DAG memory pruning, sled-backed nullifier storage, parallel proof verification, light client RPC endpoints, RPC API, on-chain validator registration with bond escrow, active BFT consensus participation, VRF-proven committee membership with epoch activation delay, fork resolution, coin emission with halving schedule, per-peer rate limiting, and a client-side wallet (CLI + web UI) with transaction history, UTXO consolidation, and mnemonic recovery phrases. A production deployment would additionally require:

- **Wallet GUI** — graphical interface for non-technical users
- **External security audit** — independent cryptographic protocol review and penetration testing (three internal audits have been completed, addressing 47+ findings across all severity levels and expanding test coverage from 226 to 294 tests with targeted state correctness, validation bypass, and regression tests)

## License

MIT
