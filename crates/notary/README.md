# Statera Notary

TLSNotary notary service for verifying TLS sessions and generating attestations.

## Overview

The notary crate provides functionality for a notary to:
1. Participate in MPC-TLS protocol with a prover
2. Verify TLS session transcripts
3. Generate signed attestations

The notary runs as a TCP server that accepts connections from provers.

## Running

```bash
# Set environment variables
export NOTARY_SIGNING_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# Run the notary service
cargo run --bin statera-notary
```

The notary will start listening on `0.0.0.0:7047` by default.

## How It Works

The notary acts as a trusted third party in the TLSNotary protocol:

1. **MPC-TLS Session** - The notary participates in multi-party computation with the prover during the TLS handshake and data exchange
2. **Verification** - After the session, the notary verifies the transcript commitments
3. **Attestation** - The notary signs an attestation confirming the authenticity of the TLS session

## Connection Protocol

The notary accepts two TCP connections per proving session:

1. **MPC Connection** (type `0`) - Used for the MPC-TLS verification protocol
2. **Attestation Connection** (type `1`) - Used for attestation request/response exchange

### Handshake

Each connection sends a 9-byte header:
```
[type: u8][session_id: u64]
```

- **New session**: Prover sends `type=0, session_id=0`. Notary assigns a session ID and sends it back.
- **Attestation connection**: Prover sends `type=1, session_id=<assigned_id>`.

Once both connections are established for a session, the notary begins the protocol.

### Attestation Exchange

Over the attestation socket, length-prefixed bincode is used:
- Request: `[length: u32][bincode-encoded AttestationRequest]`
- Response: `[length: u32][bincode-encoded Attestation]`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Host to bind the server |
| `PORT` | `7047` | Port to bind the server |
| `NOTARY_SIGNING_KEY` | **Required** | Hex-encoded 32-byte secp256k1 signing key |

You can also use a `.env` file in the working directory.

Example `.env`:
```bash
NOTARY_SIGNING_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

## Configuration

### NotaryConfig

```rust
use statera_notary::NotaryConfig;

// Create with explicit signing key
let config = NotaryConfig::new([0u8; 32]);

// Or load from environment
let config = NotaryConfig::from_env()?;

// Customize settings
let config = NotaryConfig::new(signing_key)
    .with_max_sent_data(8192)
    .with_max_recv_data(32768);
```

## Usage as a Library

```rust
use statera_notary::{run_notary, NotaryConfig};

let config = NotaryConfig::from_env()?;

// mpc_socket: TCP stream for MPC-TLS protocol
// attestation_socket: TCP stream for attestation exchange
run_notary(mpc_socket, attestation_socket, config).await?;
```

## API

### `run_notary`

```rust
pub async fn run_notary<S1, S2>(
    mpc_socket: S1,
    attestation_socket: S2,
    config: NotaryConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S1: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    S2: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
```

**Parameters:**
- `mpc_socket` - Async read/write stream for MPC-TLS communication with prover
- `attestation_socket` - Async read/write stream for attestation request/response
- `config` - Notary configuration including signing key and root certificates

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_SENT_DATA` | 4096 bytes | Default maximum data prover can send to server |
| `MAX_RECV_DATA` | 16384 bytes | Default maximum data prover can receive from server |

## TLS Certificates

By default, the notary uses Mozilla's trusted root certificates (via `webpki-root-certs`) for TLS verification. Custom root certificate stores can be configured via `NotaryConfig::with_root_store()`.

## Security

The notary uses secp256k1 ECDSA signatures for attestations. The signing key should be:
- Generated securely (e.g., using a cryptographically secure random number generator)
- Stored securely (e.g., in a hardware security module or secrets manager)
- Never committed to version control

The notary's public key should be published for verifiers to validate attestations.

## Dependencies

- `tlsn` - TLSNotary core library
- `k256` - secp256k1 elliptic curve cryptography
- `webpki-root-certs` - Mozilla trusted root certificates
