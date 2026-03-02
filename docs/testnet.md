# Umbra Testnet Guide

This guide covers running and interacting with the Umbra testnet.

## Quick Start

### Option 1: Docker Compose (recommended)

```bash
# Start a 3-validator testnet with faucet
./scripts/launch-testnet.sh

# Or manually:
docker compose -f docker-compose.testnet.yml up -d
```

This starts:
- 3 genesis validators (`validator-1`, `validator-2`, `validator-3`)
- A faucet service on port 9744

### Option 2: Local Binary

```bash
# Build
cargo build --release

# Start a genesis validator on testnet
cargo run --release -- --network testnet node --genesis-validator

# Start a second node, connecting to the first
cargo run --release -- --network testnet node --peers 127.0.0.1:9742
```

## Network Parameters

| Parameter | Testnet | Mainnet |
|-----------|---------|---------|
| P2P port (default) | 9742 | 9732 |
| RPC port (default) | 9743 | 9733 |
| Epoch length | 100 vertices | 1000 vertices |
| Genesis mint | 1,000,000,000 | 100,000,000 |
| Validator base bond | 100,000 | 1,000,000 |
| Chain ID domain | `umbra-testnet-v1` | `umbra-mainnet-v1` |

Testnet and mainnet use different chain IDs, so transactions cannot replay across networks and peers on different networks will reject each other during the P2P handshake.

## Running a Validator

### With Docker

Each validator in `docker-compose.testnet.yml` runs with `--genesis-validator`, which means it creates a new keypair and registers itself as a validator at genesis.

Data is persisted in Docker named volumes (`validator1-data`, `validator2-data`, `validator3-data`).

### Without Docker

```bash
# Start as a genesis validator with custom data directory
cargo run --release -- --network testnet node \
  --genesis-validator \
  --host 0.0.0.0 \
  --port 9742 \
  --rpc-host 0.0.0.0 \
  --rpc-port 9743 \
  --data-dir ./my-validator-data

# Or use a config file
cargo run --release -- --network testnet --config testnet.example.toml node --genesis-validator
```

### Joining an Existing Testnet

To join an existing testnet (not as a genesis validator), omit `--genesis-validator` and provide bootstrap peer addresses:

```bash
cargo run --release -- --network testnet node \
  --peers seed1.example.com:9742,seed2.example.com:9742
```

## Using the Faucet

The faucet distributes test coins to new users. It is rate-limited to 1 request per IP per hour.

### Request Coins

```bash
# Export your wallet address first
cargo run --release -- --network testnet wallet export-address

# Request coins (provide the hex-encoded address file content)
curl -X POST http://localhost:9744/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "<hex-encoded-address>"}'
```

### Check Faucet Status

```bash
curl http://localhost:9744/faucet/status
```

Returns:
```json
{
  "rpc_addr": "validator-1:9743",
  "amount_per_request": 10000000,
  "cooldown_secs": 3600,
  "total_distributed": 0,
  "requests_served": 0
}
```

## Configuration

See `testnet.example.toml` in the repository root for a documented example configuration file. Key settings:

```toml
network = "testnet"

[node]
host = "0.0.0.0"
port = 9742
rpc_host = "0.0.0.0"
rpc_port = 9743
peers = ["seed1.example.com:9742"]
data_dir = "./umbra-testnet-data"
```

## Monitoring

### Prometheus Metrics

Each validator exposes a Prometheus-compatible metrics endpoint:

```bash
curl http://localhost:9743/metrics
```

Metrics include:
- `umbra_finalized_vertices` -- total finalized vertices
- `umbra_peer_count` -- connected peers
- `umbra_mempool_txs` -- pending transactions in mempool
- `umbra_epoch` -- current epoch number
- `umbra_validator_count` -- registered validators
- `umbra_commitment_count` -- total commitments in Merkle tree
- `umbra_nullifier_count` -- spent nullifiers
- `umbra_total_minted` -- total coins minted
- `umbra_network_info{network="testnet"}` -- network identifier

### Grafana Dashboard

Start the monitoring stack with:

```bash
docker compose -f docker-compose.testnet.yml --profile monitoring up -d
```

This adds:
- **Prometheus** on port 9090 (scrapes all 3 validators)
- **Grafana** on port 3000 (default password: `umbra`)

A pre-built dashboard is at `monitoring/grafana-dashboard.json`. Import it into Grafana via the dashboard import UI.

## RPC API

The testnet exposes the same RPC API as mainnet. Common endpoints:

```bash
# Health check
curl http://localhost:9743/health

# Chain state
curl http://localhost:9743/state

# List validators
curl http://localhost:9743/validators

# Prometheus metrics
curl http://localhost:9743/metrics
```

See the main README for the full RPC API reference.

## Wallet Usage

```bash
# Initialize a new wallet
cargo run --release -- --network testnet wallet init

# Check balance
cargo run --release -- --network testnet wallet balance \
  --rpc-host localhost --rpc-port 9743

# Send a transaction
cargo run --release -- --network testnet wallet send \
  --to <address-file> --amount 1000 \
  --rpc-host localhost --rpc-port 9743
```

## Troubleshooting

**Peers not connecting**: Verify both nodes use `--network testnet`. Nodes on different networks (testnet vs mainnet) will reject each other at the P2P handshake due to chain ID mismatch.

**Port conflicts**: The default testnet ports (9742/9743) differ from mainnet (9732/9733), so you can run both simultaneously.

**Stale data**: To reset a validator and start fresh, delete its data directory:
```bash
# Local
rm -rf ./umbra-testnet-data

# Docker
docker compose -f docker-compose.testnet.yml down -v
```

**Faucet rate limited**: The faucet allows 1 request per IP per hour. Wait for the cooldown or adjust the `--cooldown` flag.

## Resetting the Testnet

To completely reset the Docker testnet:

```bash
docker compose -f docker-compose.testnet.yml down -v
docker compose -f docker-compose.testnet.yml up -d
```

The `-v` flag removes all named volumes, wiping validator state and starting a fresh chain.
