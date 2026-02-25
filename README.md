<p align="center">
  <img src="assets/umbra-header.jpg?v=3" alt="Umbra" width="850">
</p>

Umbra is a post-quantum private cryptocurrency with zk-STARKs and DAG-BFT consensus — **anonymous**, **unlinkable**, **untraceable**, **quantum-resistant**, and **instantly final**, with no trusted setup required.

> [!WARNING]
> While Umbra implements cryptographic algorithms standardized by NIST, this software has not undergone a formal security audit. A formal audit is planned once the design and APIs have stabilized.
> This project is under active development and is considered experimental. Features may change, and not all functionality is production-ready.
> If you discover bugs, security vulnerabilities, or have feature requests, please open an issue on [GitHub](https://github.com/dihmeetree/umbra/issues).

## Key Features

### Full Zero-Knowledge Privacy

- **Stealth addresses** — each transaction output uses a unique one-time address derived via Kyber KEM, making recipients unlinkable across transactions
- **Nullifier-based spending** — inputs reveal a deterministic nullifier derived from secret key material, preventing double-spends without revealing the spender's identity. Input commitments are never published — only a one-way `proof_link` is revealed, preventing graph analysis between inputs and outputs
- **Confidential amounts** — all values are hidden behind Rescue Prime commitments; validators verify correctness via zk-STARK proofs without learning any amounts
- **zk-STARK proofs** — balance and spend validity are proven in zero knowledge with no trusted setup and post-quantum security
- **Encrypted messaging** — arbitrary messages (up to 1 MiB) can be attached to transactions (max 16 per tx), encrypted so only the recipient can read them. All metadata including routing tags is inside the ciphertext — no plaintext metadata is exposed on-chain

### Quantum Resistance

All cryptographic primitives are post-quantum secure:

| Primitive                 | Algorithm                                          | Security                             |
| ------------------------- | -------------------------------------------------- | ------------------------------------ |
| Signatures                | Dilithium5 + SPHINCS+-SHAKE-256s (hybrid AND)      | ~256-bit quantum (dual-scheme)       |
| Key encapsulation         | CRYSTALS-Kyber1024 (ML-KEM-1024) + periodic rekey  | NIST Level 5, forward secrecy        |
| Commitments               | Rescue Prime (Rp64_256) + BLAKE3-512 (hybrid)      | ~256-bit quantum preimage            |
| Merkle tree               | Rescue Prime (Rp64_256)                            | STARK-friendly, post-quantum         |
| General hashing           | BLAKE3                                             | 256-bit (128-bit quantum via Grover) |
| Zero-knowledge proofs     | zk-STARKs (winterfell)                             | ~128-bit conjectured security        |
| Authenticated encryption  | XChaCha20-Poly1305 / ChaCha20-Poly1305             | 256-bit key, standard AEAD           |

No trusted setup is required. All proofs are transparent. Signatures use AND composition: both Dilithium5 and SPHINCS+ must verify, providing redundancy against single-scheme breaks. Commitments are dual-bound: Rescue Prime for STARK circuits, BLAKE3-512 (XOF mode) for ~256-bit quantum preimage resistance. The P2P transport layer uses Kyber1024 for key exchange with periodic rekeying for forward secrecy, Dilithium5 + SPHINCS+ for mutual authentication, and ChaCha20-Poly1305 AEAD, so all node-to-node communication is quantum-resistant.

### Coin Emission

- **Genesis mint** — the genesis validator receives an initial distribution of 100,000,000 units at network bootstrap, seeding the economy before block rewards begin
- **Block rewards** — each finalized vertex creates new coins for the proposer via a coinbase output (commitment + stealth address + encrypted note), the same format as any other output in the commitment tree
- **Halving schedule** — initial reward of 50,000 units per vertex, halving every 500 epochs (~500,000 vertices per phase), reaching zero after 63 halvings
- **Fee distribution** — transaction fees go to the vertex proposer via coinbase output and also accumulate in epoch-level accounting, added on top of the block reward
- **Deterministic blinding** — coinbase blinding factors are derived from `hash_domain("umbra.coinbase.blinding", vertex_id || epoch)`, making amounts publicly verifiable while maintaining consistent commitment tree format
- **Total supply tracking** — `total_minted` is tracked in the chain state and included in the state root hash, enabling consensus-verifiable supply accounting

### Consensus: Proof of Verifiable Participation (PoVP)

A novel consensus mechanism that is **neither Proof of Work nor Proof of Stake**:

1. **Superlinear Sybil resistance** — validator bonds scale with network size (`required_bond = BASE_BOND * (1 + n / SCALING_FACTOR)`), making mass registration superlinearly expensive while keeping initial entry affordable. Consensus power is _not_ proportional to wealth.
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
umbra/
  src/
    lib.rs                  Protocol constants, hashing utilities
    config.rs               TOML config file support (umbra.toml)
    demo.rs                 Interactive protocol demonstration
    state.rs                Chain state (bonds, slashing, sled-backed nullifiers), Ledger, parallel verification
    main.rs                 Node + wallet binary with clap subcommands and config file loading
    crypto/
      keys.rs               Hybrid signing (Dilithium5 + SPHINCS+) + Kyber1024 KEM keypairs
      stealth.rs            Stealth address generation and detection
      commitment.rs         Rescue Prime commitments with field element conversions
      nullifier.rs          Nullifier derivation and double-spend tracking
      proof.rs              Merkle tree (Rescue Prime), depth-20 padding, canonical roots
      encryption.rs         Kyber KEM + XChaCha20-Poly1305 authenticated encryption
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
    node/
      mod.rs                Node module root
      core.rs               Node orchestrator: consensus, Dandelion++, peer discovery, protocol signaling
      rpc.rs                JSON HTTP API: tx, state, health, metrics, fee-estimate, light client endpoints
      mempool.rs            Fee-priority transaction pool with nullifier conflict detection + fee estimation
      storage.rs            Persistent storage trait + sled backend (vertices, txs, validators)
    network/
      mod.rs                Network module root
      protocol.rs           P2P wire protocol (message types, KEM handshake, auth messages)
      p2p.rs                Encrypted P2P networking with peer reputation and connection diversity
      nat.rs                NAT traversal: UPnP mapping, observed address voting, hole punching
    wallet/
      mod.rs                Wallet module root
      core.rs               Key management, scanning, tx building, history, recovery, consolidation
      cli.rs                Wallet CLI commands (init, send, balance, history, consolidate, recover)
      web.rs                Wallet web UI (askama templates, axum server)
      bip39_words.rs        BIP39 English wordlist (2048 words) for wallet recovery
    bin/
      simulator.rs          Network simulator: multi-node BFT consensus, traffic, attack scenarios
  tests/
    e2e.rs                  End-to-end integration tests (25 tests across 3 groups)
    consensus_properties.rs Consensus property tests: BFT safety, liveness, consistency (12 tests)
    stark_constraints.rs    AIR constraint soundness verification (44 adversarial tests)
  fuzz/
    Cargo.toml              Fuzz crate configuration (cargo-fuzz / libfuzzer-sys)
    fuzz_targets/
      fuzz_decode_message.rs          Network message deserialization fuzzing
      fuzz_deserialize_transaction.rs Transaction deserialization fuzzing
      fuzz_deserialize_vertex.rs      DAG vertex deserialization fuzzing
      fuzz_transaction_validate.rs    Transaction method fuzzing (non-STARK)
  .github/
    workflows/
      rust.yml              CI pipeline: build, clippy, fmt, tests, cargo-audit
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

**~35,000 lines of Rust** across 45 source files with **977 tests**.

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

The node loads `umbra.toml` from the data directory if present. CLI flags override config file values. If no config file exists, defaults are used.

```toml
# umbra.toml (optional)
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

# Optional: NAT traversal configuration
# [node.nat]
# external_addr = "203.0.113.5:9732"  # Manual external address (for nodes behind NAT)
# upnp = true                          # Enable UPnP port mapping (default: true)

# Optional: mTLS for non-localhost RPC (see TLS section below)
# [node.tls]
# cert_file = "./tls/server.crt"
# key_file = "./tls/server.key"
# ca_cert_file = "./tls/ca.crt"
#
# [wallet.tls]
# client_cert_file = "./tls/client.crt"
# client_key_file = "./tls/client.key"
# ca_cert_file = "./tls/ca.crt"
```

### CLI Options

The binary uses subcommands (`node`, `wallet`). Running without a subcommand defaults to node mode for backward compatibility.

**Global flags:**

| Flag                | Default        | Description                                                      |
| ------------------- | -------------- | ---------------------------------------------------------------- |
| `--data-dir`        | `./umbra-data` | Data directory for persistent storage                            |
| `--rpc-host`        | `127.0.0.1`    | RPC listen host (localhost by default for safety)                |
| `--rpc-port`        | `9733`         | RPC listen port                                                  |
| `--demo`            | _(off)_        | Run the protocol demo walkthrough instead                        |
| `--tls-cert`        | _(none)_       | Server TLS certificate file (PEM)                                |
| `--tls-key`         | _(none)_       | Server TLS private key file (PEM)                                |
| `--tls-ca-cert`     | _(none)_       | CA certificate for client verification (PEM)                     |
| `--tls-client-cert` | _(none)_       | Wallet client TLS certificate (PEM)                              |
| `--tls-client-key`  | _(none)_       | Wallet client TLS private key (PEM)                              |
| `--external-addr`   | _(none)_       | Manually specify external address (IP:port) for nodes behind NAT |
| `--no-upnp`         | _(off)_        | Disable UPnP port mapping                                        |

**Node flags** (`umbra node`):

| Flag                  | Default   | Description                                                       |
| --------------------- | --------- | ----------------------------------------------------------------- |
| `--host`              | `0.0.0.0` | P2P listen host                                                   |
| `--port`              | `9732`    | P2P listen port                                                   |
| `--peers`             | _(none)_  | Comma-separated bootstrap peer addresses                          |
| `--genesis-validator` | _(off)_   | Register as a genesis validator (for bootstrapping a new network) |

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

| Command       | Description                                                                     |
| ------------- | ------------------------------------------------------------------------------- |
| `init`        | Create a new wallet, display 24-word recovery phrase, and save encrypted backup |
| `address`     | Show wallet address ID and re-export address file                               |
| `balance`     | Scan the chain and show current balance                                         |
| `scan`        | Scan the chain for new outputs (without showing balance)                        |
| `send`        | Build and submit a transaction                                                  |
| `messages`    | Show received encrypted messages                                                |
| `history`     | Show transaction history (sends, receives, coinbase rewards)                    |
| `consolidate` | Merge all unspent outputs into a single output                                  |
| `recover`     | Recover a wallet from a 24-word mnemonic phrase and backup file                 |
| `export`      | Export wallet address to a file for sharing                                     |

### Wallet Examples

```bash
# Create a new wallet (displays 24-word recovery phrase — write it down!)
cargo run --release -- wallet init

# Check balance (scans chain first)
cargo run --release -- wallet balance

# Send 1000 units to a recipient
cargo run --release -- wallet send --to ./bob.umbra-address --amount 1000

# Send with an encrypted message
cargo run --release -- wallet send --to ./bob.umbra-address --amount 500 --message "Payment for services"

# View received messages
cargo run --release -- wallet messages

# View transaction history
cargo run --release -- wallet history

# Consolidate all UTXOs into one output
cargo run --release -- wallet consolidate

# Recover a wallet from backup (requires wallet.recovery file in data dir)
cargo run --release -- wallet recover --phrase "abandon ability able about ..."

# Export address for sharing
cargo run --release -- wallet export --file ./my-address.umbra-address

# Use a custom data directory
cargo run --release -- --data-dir ./my-wallet wallet balance
```

### Address Exchange

Wallets exchange addresses via `.umbra-address` files (hex-encoded bincode-serialized `PublicAddress`). The `init` and `address` commands automatically export this file to the data directory. Use `export` to save it elsewhere for sharing.

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

## TLS / mTLS Configuration

The RPC server binds to `127.0.0.1` by default (localhost-only). For non-localhost deployments, mutual TLS (mTLS) is **required** — the node refuses to start on a non-loopback address without TLS configured.

### Generating Certificates

```bash
# Create a CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout tls/ca.key -out tls/ca.crt -days 3650 -nodes -subj "/CN=Umbra CA"

# Server certificate (use node's hostname or IP as CN/SAN)
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout tls/server.key -out tls/server.csr -nodes -subj "/CN=umbra-node"
openssl x509 -req -in tls/server.csr -CA tls/ca.crt -CAkey tls/ca.key \
  -CAcreateserial -out tls/server.crt -days 365

# Client certificate (for wallet)
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout tls/client.key -out tls/client.csr -nodes -subj "/CN=umbra-wallet"
openssl x509 -req -in tls/client.csr -CA tls/ca.crt -CAkey tls/ca.key \
  -CAcreateserial -out tls/client.crt -days 365
```

### Starting the Node with mTLS

```bash
# Via CLI flags
cargo run --release -- --rpc-host 0.0.0.0 \
  --tls-cert tls/server.crt --tls-key tls/server.key --tls-ca-cert tls/ca.crt \
  node --genesis-validator

# Via config file (umbra.toml)
# [node]
# rpc_host = "0.0.0.0"
# [node.tls]
# cert_file = "./tls/server.crt"
# key_file = "./tls/server.key"
# ca_cert_file = "./tls/ca.crt"
```

### Wallet Commands with mTLS

```bash
cargo run --release -- \
  --tls-client-cert tls/client.crt --tls-client-key tls/client.key --tls-ca-cert tls/ca.crt \
  wallet balance

# Or via config file:
# [wallet.tls]
# client_cert_file = "./tls/client.crt"
# client_key_file = "./tls/client.key"
# ca_cert_file = "./tls/ca.crt"
```

### Testing with curl

```bash
curl --cacert tls/ca.crt --cert tls/client.crt --key tls/client.key \
  https://your-node:9733/health
```

Without a valid client certificate, the connection is rejected at the TLS layer.

## RPC API

The node exposes a JSON HTTP API (default `127.0.0.1:9733`, localhost-only for safety). For non-localhost deployments, mTLS is required (see [TLS section](#tls--mtls-configuration) above).

| Method | Endpoint                    | Description                                                             |
| ------ | --------------------------- | ----------------------------------------------------------------------- |
| `POST` | `/tx`                       | Submit a hex-encoded bincode-serialized transaction                     |
| `GET`  | `/tx/{id}`                  | Look up a transaction by ID (checks mempool then storage)               |
| `GET`  | `/state`                    | Query chain state (epoch, counts, roots, total minted)                  |
| `GET`  | `/peers`                    | List connected peers                                                    |
| `GET`  | `/mempool`                  | Get mempool statistics                                                  |
| `GET`  | `/validators`               | List all validators with bond and status                                |
| `GET`  | `/validator/{id}`           | Get a single validator's info                                           |
| `GET`  | `/vertices/finalized`       | Paginated finalized vertices with coinbase outputs (`?after=N&limit=N`) |
| `GET`  | `/health`                   | Health check: status, version, uptime, peer count, epoch, sync state    |
| `GET`  | `/metrics`                  | Prometheus-format metrics: uptime, peers, epoch, mempool stats          |
| `GET`  | `/fee-estimate`             | Fee estimation: percentiles (p10–p90), median, suggested fee            |
| `GET`  | `/vertex/{id}`              | Look up a vertex by ID (checks DAG then storage)                        |
| `GET`  | `/commitment-proof/{index}` | Merkle inclusion proof for a commitment at the given index              |
| `GET`  | `/state-summary`            | Light client state summary: roots, epoch, counts, active validators     |

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
- `drain_highest_fee(n)` extracts the top-_n_ transactions for vertex proposal
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
  3. Dilithium5 + SPHINCS+ hybrid mutual authentication — both sides sign a transcript hash binding peer IDs + KEM ciphertext
  4. ChaCha20-Poly1305 AEAD for all subsequent messages (counter-based nonces, TLS 1.3 style)
  5. Authenticated encryption with replay protection via monotonic counters
  6. Domain-separated session key derivation — initiator and responder derive mirrored send/recv keys from the shared secret
  7. Periodic KEM rekeying — fresh Kyber encapsulation every 10,000 messages or 5 minutes, mixing old and new key material for forward secrecy
- **Per-peer rate limiting** — token-bucket rate limiter (100 msgs/sec refill, 200 burst); peers exceeding limits are warned and disconnected after 5 violations
- **DDoS protections** — per-IP connection limits (max 4), /16 subnet concentration limits (max 8 inbound) for eclipse attack mitigation, snapshot chunk request rate limiting, bounded peer discovery sets, and snapshot buffer OOM prevention
- Configurable max peers (default 64) and connection timeout (5 seconds)
- **NAT traversal** — three-layer external address detection:
  1. Manual configuration via `--external-addr` or config file
  2. UPnP port mapping via the local router (automatic lease renewal)
  3. Observed address voting — peers report the IP they see; after 3 unique peers agree, the address is adopted
- **TCP hole punching** — rendezvous-based coordination: requester asks a mutual peer to notify the target, which then connects back through the NAT with retries
- **NatInfo exchange** — peers exchange external addresses and observed IPs over the encrypted channel after handshake (backward-compatible with v2 peers)

### Node Orchestrator

The `Node` struct ties everything together with a `tokio::select!` event loop:

- **Persistent validator identity** — signing and KEM keypairs are saved to `data_dir/validator.key` on first run and loaded on subsequent startups (legacy key files are detected and regenerated as fresh hybrid keypairs)
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
- **Snapshot sync** — nodes far behind (or joining for the first time) download a compact state snapshot instead of replaying every vertex from genesis. The snapshot includes validators, commitment tree, and nullifiers, transferred in 4 MiB chunks. After import, the node verifies the state root and catches up remaining vertices via incremental sync
- **Fork resolution** — if no vertex is finalized for `VIEW_CHANGE_TIMEOUT_INTERVALS` proposal ticks or peers report rounds more than `MAX_ROUND_LAG` ahead, the node broadcasts `GetTips` and `GetEpochState` to discover and fetch missing vertices
- **Mempool expiry eviction** — expired transactions are periodically evicted from the mempool (every ~50 seconds and on epoch transitions)
- **NAT traversal** — on startup, the node resolves its external address via manual configuration, UPnP port mapping (with automatic lease renewal every ~50 minutes), or peer-observed address voting. External addresses are advertised to peers via `NatInfo` exchange and used in peer discovery responses. On shutdown, UPnP mappings are cleaned up
- Shared state via `Arc<RwLock<NodeState>>` (ledger + mempool + storage + BFT state)
- Genesis bootstrap via `--genesis-validator` flag (registers the node with bond escrowed and KEM key for coinbase, no funding tx required)

## Testing

```bash
cargo test                       # Full suite (~977 tests)
cargo test --features fast-tests # Skip SPHINCS+ signing/verification (~5-20x faster)
```

The `fast-tests` feature skips SPHINCS+ (the expensive redundant signature layer) while keeping all Dilithium5 signing and verification. Production builds MUST NOT use this flag.

All 977 tests cover:

- **Configuration** — default config validation, TOML parsing (with and without TLS sections, with and without NAT sections), missing config file fallback, bootstrap peer parsing, rpc_is_loopback detection, TLS file validation (server + wallet), default NatConfig values
- **Core utilities** — hash_domain determinism, domain separation, hash_concat length-prefix ambiguity prevention, constant-time equality
- **Post-quantum crypto** — hybrid key generation (Dilithium5 + SPHINCS+), hybrid signing and verification (AND composition), KEM roundtrips, fingerprint determinism and uniqueness (signing + KEM), Signature/KemCiphertext byte access, deserialization validation (wrong-size rejection for Signature, SigningPublicKey, KemPublicKey, KemCiphertext, wrong-SPHINCS+-size rejection), PublicAddress address_id determinism and uniqueness, verify with empty signature, tampered Dilithium component fails verify, tampered SPHINCS+ component fails verify, verify with wrong public key fails, Signature/SigningPublicKey/PublicAddress serialize-deserialize roundtrips
- **Stealth addresses** — generation, detection, multi-index scanning, spend auth derivation determinism, index-dependent key uniqueness, per-output spend auth uniqueness
- **Rescue Prime + BLAKE3-512** — commitments, hybrid blake3_512_binding generation and verification, field element conversions, state_digest_to_hash extraction, hash_to_felts large value reduction, felts_to_hash field-native preservation, exp7 zero and one edge cases
- **Nullifiers** — determinism, double-spend detection, to_felts roundtrip, as_bytes, NullifierSet len/is_empty/contains/remove/iter
- **Merkle tree** — construction, path verification, depth-20 canonical padding, restore from stored level data, last-appended path coverage, truncate_to_zero, truncate_partial (root matches fresh build), truncate_noop_when_larger, truncate_then_reappend, build_merkle_tree_empty, level_len, path_out_of_bounds
- **Encryption** — message roundtrips, authentication, tamper detection, exact block boundary (32 bytes), cross-block boundary (33 bytes), oversized shared secret rejected, AEAD tag tampering, decrypt with wrong shared secret, encrypt at max limit
- **VRF** — evaluation, verification, committee selection statistics, Dilithium5 signing determinism, sort_key determinism, sort_key matches first 8 bytes, epoch_seed vrf_input determinism/differs by validator/differs by epoch, is_selected edge cases (total_validators=0, committee>=total), tampered value/commitment fails verify
- **DAG** — insertion, diamond merges, finalized ordering, tip tracking, duplicate rejection, finalization status, topological sort of complex graphs, finalized count tracking, pruning of old finalized vertices; validation of too many parents, too many transactions, duplicate parents, no parents on non-genesis, too many unfinalized (DoS limit); finalized order excludes non-finalized vertices; finalize unknown vertex returns false; safe indexing after pruning (regression); ancestors_basic/diamond/bounded/genesis, advance_round_and_epoch, genesis_vertex_is_well_formed, tx_root_empty_transactions, get_returns_none_for_unknown
- **BFT** — vote collection, leader rotation, duplicate rejection, cross-epoch replay prevention, equivocation detection/clearing, equivocation evidence verification (valid, wrong epoch, non-committee, same vertex, bad signature) and serialization roundtrip, quorum certification, multi-round certificate tracking, round advancement; wrong-round vote rejection, non-committee voter rejection, invalid signature rejection, reject votes don't count toward quorum, committee-of-one certification, fallback preserves all validators without truncation (regression), rejection_count accuracy, advance_epoch clears all state; create_vote standalone with signature verification, create_vote reject, is_vote_accepted tracking, leader_none_for_empty_committee, committee_member/vote without keypair, dynamic quorum values, validator activation epoch, inactive validators excluded from committee
- **Network** — message serialization roundtrips, oversized message rejection, sync message roundtrips (GetFinalizedVertices, FinalizedVerticesResponse), peer discovery messages, epoch state responses, snapshot sync messages (manifest, chunks), equivocation evidence; BFT vote/key exchange/auth response roundtrips, get_vertex/get_tips/get_transaction roundtrips, RekeyRequest/RekeyAck roundtrips, decode empty/short/truncated/corrupted buffer returns None, NatInfo/NatPunchRequest/NatPunchNotify serialization roundtrips
- **NAT traversal** — external addr with no info returns None, manual addr has highest priority, UPnP overrides observed, observed quorum required (3 peers), minority IP ignored, same peer not double-counted, record_observed returns true on quorum change, is_reachable reflects external addr
- **Transactions** — ID determinism, content hash determinism, estimated size accuracy (within range of serialized), deregister sign data; validation of all error paths (no inputs/outputs, too many inputs/outputs, duplicate nullifiers, expired, fee too low, wrong deterministic fee, invalid binding, too many messages, message too large, insufficient bond, invalid validator key size (regression), invalid KEM key size, zero bond return commitment, proof link cross-check mismatch (regression), no-expiry passthrough, expiry boundary epoch)
- **Transaction builder** — STARK proof generation, chain ID and expiry, multi-input/multi-output, input/output limit enforcement, deterministic fee auto-computation
- **STARK formal verification** — 44 adversarial tests proving AIR constraint soundness: 5 positive baselines (all 154 balance + 52 spend constraints zero on honest traces, boundary assertions match), 3 inflation resistance (output value increase, commitment forgery, field wraparound), 4 range proof attacks (non-boolean bits, wrong reconstruction, 2^59 overflow, mid-block bit change), 2 commitment binding (wrong value/blinding), 2 proof_link integrity (wrong digest/nonce), 2 digest chaining (broken chain, wrong chain_flag), 2 fee integrity (wrong final fee, nonzero initial), 2 vanishing constraint safety (confirms C25/C87 vanish at padding is safe, nonzero block_value caught by C26), 2 padding safety (nonzero value/state[4]), 2 balance equation (multi-IO corruption, off-by-one fee), 1 tx_content_hash Fiat-Shamir binding (full prove+verify), 2 nullifier binding (wrong spend_auth/commitment), 5 Merkle attacks (wrong sibling/root, bit flip, non-boolean bit, level skip), 2 proof_link consistency (wrong commitment register/nonce), 1 register invariance (mid-trace mutation), 4 domain separation (wrong nullifier/proof_link/merge domain, chained merge domain via constraint 32), 2 cross-proof (proof_link mismatch, proof transplant rejection)
- **RPC endpoints** — GET /state, /mempool, /validators, /validator/:id (found and not-found), /tx/:id (found, not-found, invalid hex, wrong length), /vertices/finalized, /peers; POST /tx (valid submission, invalid hex, valid hex with invalid bincode, duplicate submission, oversized payload); full submit-and-retrieve roundtrip
- **Wallet** — scanning, balance tracking, spending with change, pending transaction confirm/cancel, balance excludes pending, keypair preservation; file save/load roundtrip (keys, outputs, messages, pending status, history); encrypted file save/load roundtrip (wrong password rejected, no password on encrypted file rejected, unencrypted backward compatibility); transaction history recording (send, receive, coinbase); mnemonic generation and roundtrip with checksum validation; recovery backup encrypt/decrypt, nonce uniqueness; UTXO consolidation (success path with history, fee exceeds total); pending output expiry (basic, not-yet-expired, exact boundary epoch); insufficient funds and arithmetic overflow; saturating balance addition; history cap enforcement; coinbase output scanning; blake3_binding mismatch rejection
- **Wallet CLI** — init with recovery phrase (creates wallet + backup files), recover from mnemonic + backup, history display, address display, export creates valid address file, messages on empty wallet; RPC client creation (HTTP, mTLS missing files), wallet_path/address_path helpers, load_wallet_from_nonexistent_path, cmd_export_fails_without_init
- **End-to-end** — fund, transfer, message decrypt, bystander non-detection
- **Mempool** — fee-priority ordering, nullifier conflict detection, eviction, drain, expired transaction eviction, fee percentile estimation (empty, single-tx edge case, populated pools); byte-limit eviction with total_bytes tracking, fee boundary rejection (equal fee rejected), drain cleans nullifier index, epoch-based expiry on insert, total_bytes accuracy across insert/remove/drain
- **Storage** — vertex/transaction/nullifier/validator/coinbase persistence and roundtrips, not-found returns None, vertex overwrite, chain state meta roundtrips (including total_minted), finalized index roundtrip and batch retrieval, commitment level bulk retrieval, snapshot import tree clearing
- **State** — genesis validator registration and query, bond slashing, epoch advancement (fee reset, seed rotation), inactive validator tracking, last-finalized tracking, sled-backed nullifier lookups, nullifier migration from memory to sled; apply_vertex (basic state transition, too many transactions, intra-vertex duplicate nullifier, epoch fee accumulation regression); validate_transaction (wrong chain_id, double spend, already registered); record_nullifier Result return type (regression); coinbase output creation (with and without KEM key); eligible_validators activation epoch filtering
- **P2P** — encrypted peer connection establishment, Kyber KEM handshake + Dilithium5 mutual auth, encrypted message exchange, session key symmetry, encrypted transport roundtrip, token-bucket rate limiting (burst, refill, over-burst rejection); peer reputation penalize-to-ban, ban expiry, reward recovery; AEAD tamper detection on corrupted frames; counter replay rejection; self-connection detection; subnet prefix extraction (IPv4 /16, IPv6 fallback); KEM rekey derive symmetry (initiator/responder key agreement), rekey changes all keys, different rekey secrets produce different keys, sequential rekeys produce unique keys
- **Node** — persistent signing + KEM keypair load/save roundtrip, creates data directory, rejects too-short/truncated key files, legacy key file upgrade adds KEM, file permissions restricted (unix), NodeConfig struct fields, NodeError display
- **Chain state** — persist/restore roundtrip (Merkle tree, nullifiers, validators, epoch state), ledger restore from storage, snapshot export/import roundtrip with state root verification; genesis coinbase creation and deterministic blinding
- **Wallet web** — WalletWebState construction and cache behavior, wallet_exists (present/absent), RPC client without TLS, invalidate_cache clears loaded wallet, load_wallet returns None when no file, load_wallet caches on first load, save_wallet updates cache, error_page sets message; CSRF token validation (constant-time comparison, init rejects invalid CSRF, scan rejects invalid CSRF); HTTP handler tests via axum oneshot: dashboard redirects to init, init page 200/redirect, init action creates wallet+address files, security headers (X-Frame-Options, X-Content-Type-Options, Cache-Control, CSP), send/messages/history/address pages redirect without wallet, 404 for nonexistent routes

## Network Simulator

A standalone binary that exercises the full Umbra stack end-to-end with real nodes, real P2P networking, DAG-BFT consensus, wallet transactions, and adversarial attack scenarios.

```bash
cargo run --release --bin simulator
```

### What It Tests

The simulator runs 6 phases with 41 automated checks:

1. **Bootstrap Network** — starts 3 validator nodes on localhost with real P2P connections and BFT consensus
2. **Genesis Funding** — creates wallets for Alice and Bob, funds each with 10M coins from the genesis coinbase via proper transactions with full zk-STARK proofs
3. **Normal Traffic** — 5 rounds of Alice/Bob transactions with balance conservation verification after each round
4. **Chaos Agent (Mallory)** — 25 attack scenarios across 5 categories, each verified to be rejected:
   - **Transaction structure**: corrupted proof, wrong chain ID, overflow fee, zero fee, empty transaction, duplicate nullifier, oversized message, too many inputs, too many outputs, too many messages, duplicate output commitments, invalid tx_binding, expired transaction
   - **Proof manipulation**: proof transplant (swap proofs between txs), proof_link tampering, nullifier tampering
   - **Validator operations**: insufficient bond, invalid key sizes, zero bond return in deregister
   - **Double-spend & replay**: mempool nullifier conflict, duplicate transaction, cross-chain replay via state validation, state-level double-spend with already-spent nullifier
   - **Timing & resilience**: mempool expiry eviction, no-expiry tx survives eviction
5. **State Integrity** — verifies chain state is uncorrupted after all attacks
6. **Monitoring** — checks node health, epoch state, commitment tree, validator set, mempool, and validator health across all nodes

All transactions use full-security `default_proof_options()` (not lightweight test proofs). The simulator prints a colored pass/fail summary and exits with code 0 on success.

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

Umbra uses a UTXO model with full zero-knowledge privacy:

```
Transaction {
    inputs:        [Nullifier + ProofLink + SpendStarkProof]
    outputs:       [Commitment + StealthAddress + EncryptedNote]
    fee:           u64 (public, deterministic for transfers)
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
- **Messages** are Kyber-encrypted payloads (XChaCha20-Poly1305 AEAD with 24-byte nonce) that only the recipient can decrypt.
- **Transaction types** — in addition to regular transfers, transactions can carry validator registration or deregistration operations:
  - `ValidatorRegister` — includes the validator's Dilithium5 signing key and Kyber1024 KEM public key (required for receiving coinbase rewards). The fee must be at least `required_validator_bond(active_count) + MIN_TX_FEE`; the bond is escrowed in chain state, and only the remainder goes to epoch fees. The bond scales superlinearly with the number of active validators for Sybil resistance. No zk-STARK modifications are needed — the bond is carried through the existing fee field.
  - `ValidatorDeregister` — includes the validator ID, an auth signature proving ownership, and a `TxOutput` that receives the returned bond (added to the commitment tree). The bond return is secured by the STARK system: if the validator creates a wrong commitment, it will fail verification when they try to spend.

## Zero-Knowledge Proof System

Umbra uses **zk-STARKs** (via the [winterfell](https://github.com/facebook/winterfell) library) for all transaction validity proofs:

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

| Property           | Value                                                     |
| ------------------ | --------------------------------------------------------- |
| Trusted setup      | None (transparent)                                        |
| Post-quantum       | Yes (hash-based)                                          |
| Field              | Goldilocks (p = 2^64 - 2^32 + 1)                          |
| Hash in circuit    | Rescue Prime (Rp64_256)                                   |
| Security           | ~128-bit conjectured (capped by Rp64_256 collision resistance) |
| Range proof        | 59-bit via bit decomposition (integrated in balance AIR)  |
| Balance proof size | ~40 KB                                                    |
| Spend proof size   | ~33 KB                                                    |

## Protocol Constants

| Constant                             | Value       | Description                                                     |
| ------------------------------------ | ----------- | --------------------------------------------------------------- |
| `COMMITTEE_SIZE`                     | 21          | BFT committee members per epoch                                 |
| `MIN_COMMITTEE_SIZE`                 | 4           | Minimum committee for BFT safety                                |
| `BFT_QUORUM`                         | dynamic     | `(committee_size * 2) / 3 + 1` votes for finality               |
| `EPOCH_LENGTH`                       | 1,000       | Vertices per epoch before rotation                              |
| `MAX_PARENTS`                        | 8           | Max parent references per DAG vertex                            |
| `MAX_TXS_PER_VERTEX`                 | 10,000      | Max transactions per vertex                                     |
| `VERTEX_INTERVAL_MS`                 | 500         | Target interval between vertices                                |
| `MAX_MESSAGES_PER_TX`                | 16          | Max messages per transaction                                    |
| `MAX_MESSAGE_SIZE`                   | 64 KiB      | Max encrypted message per transaction                           |
| `MAX_ENCRYPT_PLAINTEXT`              | 1 MiB       | Max plaintext for Kyber encryption                              |
| `MAX_NETWORK_MESSAGE_BYTES`          | 16 MiB      | Max serialized network message                                  |
| `VALIDATOR_BASE_BOND`                | 1,000,000   | Base bond for validator registration (scales with network size) |
| `BOND_SCALING_FACTOR`                | 100         | Scaling factor for superlinear bonding curve                    |
| `MERKLE_DEPTH`                       | 20          | Canonical commitment tree depth (~1M outputs)                   |
| `RANGE_BITS`                         | 59          | Bit width for value range proofs                                |
| `MAX_TX_IO`                          | 16          | Max inputs or outputs per transaction (range-proof safe)        |
| `MIN_TX_FEE`                         | 1           | Minimum transaction fee (prevents zero-fee spam)                |
| `FEE_BASE`                           | 100         | Base component of deterministic fee formula                     |
| `FEE_PER_INPUT`                      | 100         | Per-input component of deterministic fee formula                |
| `FEE_PER_MESSAGE_KB`                 | 10          | Per-KB message component of deterministic fee formula           |
| `INITIAL_BLOCK_REWARD`               | 50,000      | Coinbase reward per vertex (halves over time)                   |
| `HALVING_INTERVAL_EPOCHS`            | 500         | Epochs between each reward halving                              |
| `MAX_HALVINGS`                       | 63          | Halvings before reward reaches zero                             |
| `GENESIS_MINT`                       | 100,000,000 | Initial coin distribution to the genesis validator              |
| `MEMPOOL_MAX_TXS`                    | 10,000      | Maximum transactions in the mempool                             |
| `MEMPOOL_MAX_BYTES`                  | 50 MiB      | Maximum total mempool size                                      |
| `DEFAULT_P2P_PORT`                   | 9,732       | Default P2P listen port                                         |
| `DEFAULT_RPC_PORT`                   | 9,733       | Default JSON RPC port                                           |
| `MAX_PEERS`                          | 64          | Maximum connected peers                                         |
| `PEER_CONNECT_TIMEOUT_MS`            | 5,000       | Peer connection timeout                                         |
| `VERTEX_MAX_DRAIN`                   | 1,000       | Max transactions drained per vertex proposal                    |
| `SYNC_BATCH_SIZE`                    | 100         | Finalized vertices per sync request batch                       |
| `SYNC_REQUEST_TIMEOUT_MS`            | 30,000      | Timeout for sync requests                                       |
| `SYNC_PEER_COOLDOWN_MS`              | 60,000      | Cooldown before retrying a failed sync peer                     |
| `SNAPSHOT_CHUNK_SIZE`                | 4 MiB       | Chunk size for snapshot transfer                                |
| `SNAPSHOT_SYNC_THRESHOLD`            | 500         | Minimum gap before preferring snapshot sync                     |
| `SNAPSHOT_CACHE_TTL_SECS`            | 120         | TTL for cached snapshot on serving node                         |
| `PEER_MSG_RATE_LIMIT`                | 100.0       | Per-peer message rate limit (msgs/sec refill)                   |
| `PEER_MSG_BURST`                     | 200.0       | Per-peer max burst messages                                     |
| `PEER_RATE_LIMIT_STRIKES`            | 5           | Rate violations before disconnecting peer                       |
| `VIEW_CHANGE_TIMEOUT_INTERVALS`      | 10          | Proposal ticks without finalization before fork resolution      |
| `MAX_ROUND_LAG`                      | 5           | Max rounds behind peers before triggering view change           |
| `PEER_EXCHANGE_INTERVAL_MS`          | 60,000      | Interval between peer discovery gossip rounds                   |
| `PEER_DISCOVERY_MAX`                 | 5           | Max new peers to connect per discovery round                    |
| `DANDELION_STEM_HOPS`                | 2           | Stem-phase hops before fluff broadcast                          |
| `DANDELION_TIMEOUT_MS`               | 5,000       | Max stem phase duration before forced fluff                     |
| `PEER_INITIAL_REPUTATION`            | 100         | Starting reputation score for new peers                         |
| `PEER_BAN_THRESHOLD`                 | 20          | Reputation below which peers are temp-banned                    |
| `PEER_BAN_DURATION_SECS`             | 3,600       | Duration of temporary peer ban (1 hour)                         |
| `PEER_PENALTY_RATE_LIMIT`            | 10          | Reputation penalty for rate limit violation                     |
| `PEER_PENALTY_INVALID_MSG`           | 20          | Reputation penalty for invalid message                          |
| `PEER_PENALTY_HANDSHAKE_FAIL`        | 30          | Reputation penalty for handshake failure                        |
| `PRUNING_RETAIN_EPOCHS`              | 100         | Epochs of finalized vertices retained in memory                 |
| `PROTOCOL_VERSION`                   | 3           | Current protocol version for vertex signaling                   |
| `UPGRADE_THRESHOLD`                  | 75%         | Signal threshold for protocol upgrade activation                |
| `UPNP_TIMEOUT_MS`                    | 5,000       | UPnP gateway discovery timeout                                  |
| `UPNP_LEASE_DURATION_SECS`           | 3,600       | UPnP port mapping lease duration (1 hour)                       |
| `UPNP_RENEWAL_INTERVAL_SECS`         | 3,000       | UPnP lease renewal interval (~50 minutes)                       |
| `NAT_OBSERVED_ADDR_QUORUM`           | 3           | Unique peers required to trust an observed IP                   |
| `HOLE_PUNCH_TIMEOUT_MS`              | 5,000       | TCP hole punch connection timeout                               |
| `HOLE_PUNCH_RETRY_DELAY_MS`          | 500         | Delay between hole punch retry attempts                         |
| `HOLE_PUNCH_MAX_ATTEMPTS`            | 3           | Maximum hole punch retry attempts                               |
| `P2P_REKEY_INTERVAL`                 | 10,000      | Messages between KEM rekeying for forward secrecy               |
| `P2P_REKEY_TIME_SECS`                | 300         | Maximum seconds between KEM rekeying (5 minutes)                |
| `MAX_CONNECTIONS_PER_IP`             | 4           | Maximum connections from a single IP address                    |
| `MAX_PEERS_PER_SUBNET`               | 8           | Maximum inbound peers from the same /16 subnet                  |
| `MAX_RECENTLY_ATTEMPTED`             | 1,000       | Maximum tracked recently-attempted peer addresses               |
| `MAX_SNAPSHOT_CHUNKS`                | 256         | Maximum snapshot chunks (caps buffer allocation)                |
| `SNAPSHOT_CHUNK_REQUEST_INTERVAL_MS` | 100         | Minimum interval between chunk requests per peer                |

## Dependencies

| Crate                            | Purpose                                                   |
| -------------------------------- | --------------------------------------------------------- |
| `pqcrypto-dilithium`             | CRYSTALS-Dilithium5 post-quantum signatures               |
| `pqcrypto-kyber`                 | CRYSTALS-Kyber1024 post-quantum key encapsulation         |
| `pqcrypto-sphincsplus`           | SPHINCS+-SHAKE-256s post-quantum hash-based signatures    |
| `pqcrypto-traits`                | Trait definitions for PQ crypto types                     |
| `blake3`                         | Fast, quantum-secure hashing                              |
| `chacha20poly1305`               | Standard AEAD (XChaCha20-Poly1305 / ChaCha20-Poly1305)   |
| `winterfell`                     | zk-STARK prover/verifier (Rescue Prime, Goldilocks field) |
| `argon2`                         | Memory-hard password hashing for wallet file encryption   |
| `zeroize`                        | Secure memory clearing for secret key material            |
| `serde` + `bincode`              | Serialization                                             |
| `rand`                           | Cryptographic randomness                                  |
| `hex`                            | Hex encoding for display                                  |
| `thiserror`                      | Error type derivation                                     |
| `tokio`                          | Async runtime (P2P networking, node event loop)           |
| `sled`                           | Embedded database for persistent storage                  |
| `axum`                           | JSON HTTP API framework                                   |
| `axum-server`                    | TLS server support (mTLS for RPC)                         |
| `rustls` + `rustls-pemfile`      | Pure-Rust TLS with PEM parsing                            |
| `clap`                           | CLI argument parsing                                      |
| `serde_json`                     | JSON serialization for RPC                                |
| `tracing` + `tracing-subscriber` | Structured logging                                        |
| `subtle`                         | Constant-time comparison for cryptographic checks         |
| `reqwest`                        | HTTP client (rustls) for wallet RPC communication         |
| `askama` + `askama_web`          | Type-safe compiled HTML templates for wallet web UI       |
| `tokio-util`                     | Graceful shutdown via `CancellationToken`                 |
| `toml`                           | TOML config file parsing                                  |
| `rayon`                          | Parallel proof verification for vertex validation         |
| `tempfile`                       | Temporary directories for simulator and testing           |
| `colored`                        | Terminal color output for simulator results               |
| `igd-next`                       | UPnP port mapping for NAT traversal                       |

## Security Model

### Zero-Knowledge Proofs

All transaction validity is verified via zk-STARKs:

- **Full zero knowledge** — validators verify correctness without learning any secret values (amounts, keys, output identities)
- **Sound** — a forged proof cannot pass verification without breaking the underlying hash function
- **Transparent** — no trusted setup required, all proofs are publicly verifiable
- **Post-quantum** — STARK security is hash-based, not reliant on discrete log or factoring

### Security Hardening

- **Vertex signature verification** — every DAG vertex must carry a valid hybrid signature (Dilithium5 + SPHINCS+) from its proposer; unsigned vertices are rejected at insertion time
- **Full transaction validation on apply** — `apply_transaction()` calls `validate_structure()` before any state mutation, verifying all zk-STARK proofs (balance + spend) and structural integrity
- **VRF anti-grinding** — VRF outputs include a `proof_commitment` (hash of the proof) enabling a commit-reveal scheme that prevents validators from grinding on epoch seeds
- **Plaintext size limits** — `encrypt_with_shared_secret` rejects plaintexts exceeding `MAX_ENCRYPT_PLAINTEXT`, preventing memory exhaustion attacks
- **Secure memory clearing** — all secret key material (`SigningSecretKey`, `KemSecretKey`, `SharedSecret`, `BlindingFactor`, `StealthSpendInfo`, `BalanceWitness`, `SpendWitness`) is zeroized on drop via the `zeroize` crate and volatile writes; derived AEAD keys are explicitly zeroized after use
- **Vote round validation** — BFT `receive_vote()` rejects votes for rounds other than the current round, preventing future-round injection attacks
- **Chain-bound vote signatures** — vote signatures include `chain_id`, preventing cross-chain vote replay attacks
- **Transaction expiry enforcement** — `validate_structure()` enforces `expiry_epoch`, rejecting stale transactions
- **128-bit STARK security** — proof verification requires at least 127-bit conjectured security; cubic field extension (p^3 ~ 2^192) ensures the field is not the bottleneck, while Rp64_256 hash collision resistance (128 bits) caps the overall conjectured security
- **Standard AEAD** — all authenticated encryption uses XChaCha20-Poly1305 (transactions, wallet) or ChaCha20-Poly1305 (P2P transport) instead of custom constructions
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
- **Range proofs** — all committed values are proven to be in [0, 2^59) via bit decomposition within the balance AIR; with MAX_IO = 16 per side, the maximum sum is 16 \* 2^59 = 2^63 < p (Goldilocks), preventing inflation via field-arithmetic wraparound
- **Network message limits** — serialized messages are rejected above `MAX_NETWORK_MESSAGE_BYTES`; bincode deserialization uses size-limited options to prevent allocation-based DoS from crafted internal length fields
- **Cryptographic type size validation** — public keys, signatures, and KEM ciphertexts are validated on deserialization, rejecting malformed or oversized payloads
- **Deserialization bounds** — public input deserialization rejects counts exceeding `MAX_TX_IO` (16 inputs/outputs) to prevent allocation DoS
- **Overflow protection** — all arithmetic uses `checked_add` to prevent overflow; fee accumulation overflow is an explicit error
- **Transaction I/O limits** — inputs and outputs are capped at `MAX_TX_IO` (16), ensuring range proof sums stay within the Goldilocks field (16 \* 2^59 < p) and preventing inflation via field-arithmetic wraparound
- **Complete content hash binding** — `tx_content_hash` covers all encrypted payload fields including MACs and KEM ciphertexts, preventing undetected tampering of encrypted notes or messages
- **Domain-separated hashing** — all critical hashes (`tx_id`, `vertex_id`, stealth key derivation, content hash) use BLAKE3 `new_derive_key` for proper cryptographic domain separation
- **Rescue sponge domain separation** — all four Rescue Prime hash functions use distinct nonzero domain tags in the sponge capacity: `commitment` (`"commit"`), `nullifier` (`"null"`), `proof_link` (`"link"`), and `merge` (`"merge"`). This prevents cross-function collisions regardless of rate inputs, enforced in the STARK AIR via boundary assertions and transition constraints
- **Chain ID enforcement** — `apply_transaction()` explicitly checks `chain_id` against the chain state, providing defense-in-depth beyond the implicit binding via balance proofs
- **Minimum transaction fee** — `validate_structure()` enforces `MIN_TX_FEE`, preventing zero-fee spam; transfer fees are deterministic from transaction shape (see above); coinbase funding bypasses validation by adding outputs directly to state
- **AEAD ciphertext binding** — XChaCha20-Poly1305 encrypts with the KEM ciphertext as Associated Authenticated Data (AAD), binding the ephemeral key exchange to the encrypted payload and preventing ciphertext transplant attacks
- **Equivocation detection** — BFT tracks `(voter_id, round) → vertex_id` and records `EquivocationEvidence` when a validator votes for conflicting vertices in the same round
- **Pending transaction tracking** — wallet outputs use a three-state lifecycle (Unspent → Pending → Spent) with explicit `confirm_transaction` / `cancel_transaction` and automatic expiry after `PENDING_EXPIRY_EPOCHS` to prevent double-spend of outputs in unconfirmed transactions and recover stuck funds
- **VRF commitment verification** — `VrfOutput::verify()` requires a pre-registered proof commitment, enforcing the commit-reveal anti-grinding scheme; `verify_locally()` is available for self-checks only
- **VRF-proven vertices and votes** — every non-genesis vertex and BFT vote must include a VRF proof demonstrating the proposer/voter was selected for the epoch's committee; vertices and votes without valid VRF proofs are rejected
- **Superlinear validator bond** — registration requires `fee >= required_validator_bond(active_count) + MIN_TX_FEE`, where the bond scales as `BASE_BOND * (1 + n / SCALING_FACTOR)`. Makes Sybil attacks superlinearly expensive (e.g., adding 500 validators to a 100-validator network costs ~2.25B vs 150M for the first 100). Each validator's actual bond is escrowed and returned on deregistration
- **Slashing** — equivocation evidence (voting for conflicting vertices in the same round) triggers automatic bond forfeiture to epoch fees and permanent validator exclusion
- **Deregistration auth** — validator deregistration requires a signature over `"umbra.validator.deregister" || chain_id || validator_id || tx_content_hash`, preventing unauthorized bond withdrawal
- **Two-phase vertex finalization** — vertices are inserted into the DAG (unfinalized) first, then finalized only after BFT quorum certification, preventing premature state application
- **Persistent validator keypair** — the validator's Dilithium5 signing and Kyber1024 KEM keypairs are persisted to disk with raw byte serialization and validated on load, preventing key loss across restarts
- **Deterministic coinbase blinding** — coinbase output blinding factors are derived from `hash_domain("umbra.coinbase.blinding", vertex_id || epoch)`, making amounts publicly verifiable while using the same commitment format as private outputs
- **Consensus-verifiable supply** — `total_minted` is included in the state root hash, so any disagreement on emission is detected by state root divergence
- **Fee redirection fallback** — if a vertex proposer lacks a KEM key (cannot receive coinbase), fees are returned to the epoch fee pool rather than being lost
- **Post-quantum encrypted transport** — all P2P connections use Kyber1024 KEM for key exchange and Dilithium5 for mutual authentication, followed by ChaCha20-Poly1305 AEAD with counter-based nonces, providing quantum-resistant confidentiality and integrity for all inter-node communication
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
- **Wallet recovery phrases** — 24-word BIP39 mnemonic with BLAKE3 checksum; key material encrypted with XChaCha20-Poly1305. Both the phrase and the encrypted backup file are required for recovery, preventing single-point-of-failure key loss
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
- **AEAD recovery encryption** — wallet recovery backups use XChaCha20-Poly1305 with a BLAKE3-derived key and random nonce, providing authenticated encryption even if the same mnemonic is reused
- **Error message sanitization** — wallet CLI error messages do not expose internal file paths to users; details are logged server-side via `tracing::error!`
- **Mnemonic zeroization** — recovery phrase words are zeroized from memory immediately after display to minimize secret exposure window
- **Multi-transaction mempool eviction** — when the mempool is full, lowest-fee transactions are evicted in a loop until space is available, rather than evicting only one
- **Cached finalized vertex count** — `finalized_vertex_count()` uses an `AtomicU64` cache instead of scanning the sled tree, improving performance for health and metrics endpoints
- **Validator key size validation** — `ValidatorRegister` transactions validate that signing keys are exactly 2592 bytes (Dilithium5) + 64 bytes (SPHINCS+) and KEM keys are exactly 1568 bytes (Kyber1024), rejecting malformed keys
- **Nullifier persistence propagation** — sled write failures in `record_nullifier()` propagate as errors through `apply_vertex()`, preventing silent state desynchronization between memory and storage that could allow double-spends after restart
- **Sync epoch validation** — finalized vertices received during sync are rejected if their epoch exceeds the sync peer's claimed epoch + 1, preventing malicious peers from advancing local state to fabricated future epochs
- **Proof link cross-validation** — each spend proof's `proof_link` is cross-checked against the corresponding entry in the balance proof's `input_proof_links`, providing defense-in-depth against proof_link tampering
- **Web message size validation** — the wallet web UI validates message size against `MAX_MESSAGE_SIZE` before building transactions, preventing unnecessary proof generation for oversized messages
- **Concurrent wallet mutation lock** — the wallet web UI serializes send and scan operations via a tokio Mutex, preventing race conditions that could cause double-spending from concurrent requests
- **DAG safe indexing** — `finalized_order()` uses fallible `.get()` lookups instead of panicking `[]` indexing, gracefully handling edge cases where finalized vertices may be missing from the in-memory map after pruning
- **P2P frame padding** — encrypted P2P frames are padded to 1024-byte bucket boundaries, preventing traffic analysis from distinguishing message types by size
- **Dandelion++ timing jitter** — stem-phase forwarding adds exponentially-distributed random delays before relaying to the next hop, preventing timing decomposition attacks for sender deanonymization
- **Stealth detection timing equalization** — stealth address scanning performs dummy key derivation and constant-time comparison on KEM decapsulation failure, equalizing timing with the success path
- **Deterministic weight-based fees** — transfer fees are computed deterministically from transaction shape (`fee = FEE_BASE + inputs * FEE_PER_INPUT + ceil(message_bytes / 1024) * FEE_PER_MESSAGE_KB`), eliminating fee-based fingerprinting entirely since every transaction of the same shape pays the exact same fee with no user choice involved
- **RPC rate limiting** — commitment-proof queries are rate-limited per IP (60 requests per 60-second window) to prevent Merkle tree enumeration attacks that could map wallet activity to commitment indices
- **Peer address redaction** — peer discovery responses and RPC endpoints strip IP addresses, preventing validator deanonymization via address correlation
- **NatInfo privacy** — NatInfo messages send empty observed addresses, preventing peers from learning their own externally-visible IP through the P2P layer
- **Per-output spend authorization** — `derive_spend_auth` includes the output index, producing unique spend authorization keys per output and preventing cross-output linkability for the same recipient
- **Encrypted payload padding** — encrypted notes and messages are padded to 64-byte bucket boundaries with random fill, preventing plaintext length inference from ciphertext size
- **Gossip dedup randomization** — the `seen_messages` rotation threshold includes random jitter, preventing spy nodes from probing dedup state transitions to infer message origination timing
- **Log redaction** — validator key fingerprints and peer identifiers are redacted from all log output, preventing information leakage through log analysis
- **VRF determinism verification** — node startup asserts Dilithium5 signing determinism at runtime, preventing silent VRF correctness failures from non-deterministic implementations
- **Recovery backup nonce** — wallet recovery backups include a 24-byte random nonce in the keystream derivation, preventing keystream reuse if the same mnemonic entropy is used for multiple backups
- **Vertex timestamp enforcement** — vertices with timestamps more than 60 seconds in the future are rejected on insertion, preventing timestamp manipulation by malicious proposers while allowing historical vertex sync
- **Snapshot state root verification** — after importing a snapshot from a peer, the node recomputes the state root from the restored state and rejects snapshots where the computed root does not match the claimed root, preventing state corruption from malicious peers
- **Slashing evidence propagation** — when a node detects equivocation (a validator voting for two different vertices in the same round), it broadcasts cryptographic proof (both conflicting signatures) to all peers. Receiving nodes independently verify both signatures, apply slashing locally, and re-gossip, ensuring all nodes converge on the same slashed validator state
- **RPC mutual TLS (mTLS)** — the RPC server supports mutual TLS authentication for non-localhost deployments. The server requires client certificates signed by a trusted CA, and refuses to start on non-loopback addresses without TLS configured. Both server and client authenticate via X.509 certificates, preventing unauthorized access to the RPC API
- **Observed address quorum** — external address detection via peer observation requires 3 independent peers agreeing on the same IP, preventing single-peer address poisoning
- **NAT info over encrypted channel** — external address claims and observed addresses are exchanged via `NatInfo` messages over the encrypted post-handshake channel, not in the plaintext `Hello`
- **Hole punch via authenticated peers** — `NatPunchRequest` is only forwarded to already-authenticated peers; the target initiates a full KEM + auth handshake on connect-back, preventing reflection attacks
- **Per-IP connection limits** — inbound connections from a single IP address are capped at `MAX_CONNECTIONS_PER_IP` (4), preventing Sybil attacks where one attacker fills all inbound slots with multiple peer IDs
- **Subnet eclipse mitigation** — inbound connections from a single /16 subnet are capped at `MAX_PEERS_PER_SUBNET` (8), limiting an attacker's ability to dominate the peer table from a single network range
- **Snapshot chunk buffer OOM prevention** — `SnapshotManifest` rejects manifests with more than `MAX_SNAPSHOT_CHUNKS` (256) chunks and validates chunk count consistency against snapshot size, preventing memory exhaustion from malicious manifests
- **Bounded peer discovery** — the `recently_attempted` set is capped at `MAX_RECENTLY_ATTEMPTED` (1,000 entries), preventing unbounded memory growth from peer discovery gossip
- **Fuzz testing** — 4 cargo-fuzz targets exercise serialization boundaries: network message decoding (30+ variants with 4-byte length prefix), transaction deserialization (nested STARK proofs, stealth addresses, encrypted payloads), vertex deserialization (DAG structure with transaction vectors), and transaction method fuzzing (tx_id, content hash, fee computation on malformed inputs)
- **Consensus property verification** — 12 property tests formally verify BFT safety (no conflicting certificates, quorum intersection for all committee sizes, epoch/chain vote isolation), liveness (honest majority certification, round-robin leader fairness, round advancement), and consistency (deterministic finalization order across different insertion orders, symmetric certificate and equivocation evidence verification)
- **Snapshot chunk rate limiting** — chunk requests from the same peer are throttled to one per `SNAPSHOT_CHUNK_REQUEST_INTERVAL_MS` (100ms), preventing CPU exhaustion from rapid chunk request spam
- **Peer ID verification** — P2P handshake verifies that the remote peer's public key fingerprint matches the expected peer ID for both inbound and outbound connections, preventing MITM impersonation
- **Deterministic DAG finalization** — `finalized_order()` BFS uses deterministic tie-breaking `(round, vertex_id)` when ordering siblings, ensuring all nodes produce identical finalization sequences
- **Snapshot integrity verification** — snapshot import verifies nullifier count, nullifier hash, validator count, and commitment tree root in memory before persisting to storage, preventing state corruption from malicious snapshots
- **Nullifier rollback on failure** — if vertex application fails after recording nullifiers to sled, the nullifiers are rolled back to maintain storage consistency
- **Wallet file encryption** — wallet private keys can be encrypted at rest using a password-derived key (Argon2id memory-hard key derivation with 64 MiB / 3 iterations, random 32-byte salt and 24-byte nonce, XChaCha20-Poly1305 AEAD)
- **CSRF protection** — wallet web UI forms include per-session CSRF tokens validated with constant-time comparison on all state-mutating POST requests, preventing cross-site request forgery
- **Mempool proof verification** — mempool can optionally verify zk-STARK balance and spend proofs on insertion, preventing invalid transactions from consuming pool capacity
- **Mempool finalized nullifier checking** — mempool insertion checks nullifiers against finalized chain state via an external callback, rejecting transactions that attempt to spend already-finalized outputs
- **DAG pruned parent acceptance** — the DAG tracks IDs of pruned finalized vertices, allowing new vertices to reference parents that have been pruned from memory without spurious rejection
- **Bond re-validation at apply time** — validator registration re-checks the bond requirement at state application time, preventing TOCTOU races where concurrent registrations could change the required bond between validation and application
- **Non-loopback binding warning** — the wallet web server logs a warning when bound to a non-loopback address, alerting operators to potential network exposure

## Production Roadmap

Umbra includes a full node implementation with encrypted P2P networking (Kyber1024 + Dilithium5), persistent storage, state sync with timeout/retry, fee-priority mempool with fee estimation and expiry eviction, health/metrics endpoints, TOML configuration, graceful shutdown, Dandelion++ transaction relay, peer discovery gossip, peer reputation with ban persistence, connection diversity, protocol version signaling, DAG memory pruning, sled-backed nullifier storage, parallel proof verification, light client RPC endpoints, RPC API with mTLS authentication, on-chain validator registration with bond escrow, active BFT consensus participation, VRF-proven committee membership with epoch activation delay, fork resolution, coin emission with halving schedule, per-peer rate limiting, DDoS protections (per-IP limits, subnet eclipse mitigation, snapshot OOM prevention, chunk rate limiting), NAT traversal with UPnP and hole punching, and a client-side wallet (CLI + web UI) with transaction history, UTXO consolidation, and mnemonic recovery phrases. A production deployment would additionally require:

- **Wallet GUI** — graphical interface for non-technical users
- **External security audit** — independent cryptographic protocol review and penetration testing (four internal audits have been completed, addressing 55+ findings across all severity levels and expanding test coverage from 226 to 977 tests with targeted state correctness, validation bypass, regression tests, cryptographic hardening, comprehensive unit test coverage across all modules, formal verification of all 206 AIR constraints, 25 end-to-end integration tests covering transaction lifecycle, BFT certification, equivocation slashing, epoch management, snapshot round-trips, wallet flows, validator registration, and multi-hop transfers, 12 consensus property tests verifying BFT safety (no conflicting certificates, quorum intersection, epoch/chain isolation), liveness (honest majority certification, leader fairness, round advancement), and consistency (deterministic finalization order, symmetric verification), and 4 fuzz targets for serialization boundaries (network messages, transactions, vertices); a full-stack network simulator validates multi-node BFT consensus, transaction flow, and attack rejection)

## License

MIT
