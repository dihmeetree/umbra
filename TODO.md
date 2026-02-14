# Umbra — Production Roadmap

## Consensus & Networking

- [ ] **Multi-node testnet** — deploy across real machines with actual network latency, partitions, and clock skew
- [x] **Snapshot/checkpoint sync** — allow new nodes to bootstrap from a recent checkpoint instead of replaying from genesis
- [x] **NAT traversal / hole punching** — enable inbound P2P connections for nodes behind NATs
- [ ] **Persistent peer address book** — save known peers to disk so they survive restarts
- [x] **Timestamp enforcement** — reject vertices with far-future timestamps; detect clock skew between peers

## Cryptography & Privacy

- [ ] **External security audit** — independent cryptographer review of custom BLAKE3 AEAD, Rescue Prime parameters, and STARK AIR constraints
- [x] **Formal verification of AIR constraints** — prove that the 154 balance and 52 spend constraints are sufficient for soundness
- [ ] **Tor/I2P integration** — route P2P traffic through an anonymity network for real sender privacy beyond Dandelion++

## Operations & Infrastructure

- [x] **RPC authentication** — mTLS support for non-localhost deployments (server + client certificates, auto-detect, safety net)
- [ ] **Monitoring & alerting** — Grafana dashboards, consensus stall alerts, disk usage tracking
- [ ] **Log rotation / structured logging** — log management for long-running nodes
- [ ] **Database evaluation** — benchmark sled at scale; evaluate RocksDB or similar if needed
- [ ] **Configuration validation** — reject conflicting or dangerous `umbra.toml` settings at startup

## Wallet

- [ ] **Wallet GUI** — desktop/mobile graphical interface for non-technical users
- [ ] **Multi-wallet support** — manage multiple wallets from a single node
- [ ] **Hardware wallet integration** — support external signing devices
- [ ] **Address book / contacts** — save and label recipient addresses
- [ ] **Auto fee suggestion** — wallet queries `/fee-estimate` and suggests a fee in the send flow

## Protocol

- [ ] **Governance mechanism** — define a process for deciding what protocol upgrades get signaled
- [x] **Slashing evidence propagation** — broadcast equivocation evidence to all nodes, not just detect locally
- [ ] **Light client verification** — SPV-style proofs that light clients can verify independently
- [ ] **Cross-chain bridges** — interoperability with other networks

## Testing

- [ ] **Chaos/fault injection testing** — simulate network partitions, disk failures, OOM conditions
- [ ] **Fuzz targets** — fuzz deserialization, proof verification, and transaction validation
- [ ] **Load/performance benchmarks** — measure proof generation time, TPS throughput, and memory usage at scale
