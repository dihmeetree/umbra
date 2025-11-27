# Statera Prover

Axum-based API for TLSNotary attestation proving with selective disclosure.

## Overview

The prover crate provides a single HTTP endpoint that:
1. Proves a URL via MPC-TLS with a remote notary
2. Creates a presentation with selective disclosure
3. Returns the verifiable presentation

## Running

```bash
# Set environment variables
export NOTARY_HOST=127.0.0.1
export NOTARY_PORT=7047

# Run the prover API
cargo run --bin statera-prover
```

The prover API will start on `0.0.0.0:3000` by default.

## API Endpoints

### `GET /health`
Health check endpoint.

**Response:** `"OK"`

### `POST /prove`
Prove an HTTP request and create a verifiable presentation.

**Request:**
```json
{
  "url": "https://api.example.com/user/123",
  "headers": [
    { "name": "Authorization", "value": "Bearer token" }
  ],
  "redact_headers": ["Cookie"],
  "reveal_body": false,
  "reveal_body_keys": ["name", "balance"]
}
```

**Response:**
```json
{
  "presentation": [/* bincode-serialized presentation bytes */],
  "server_name": "api.example.com",
  "sent": "GET /user/123 HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: XXXXXXXXXXXX\r\n...",
  "recv": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\": XXXXXXXXX, \"name\": \"Alice\", \"balance\": 1000, \"secret\": XXXXXXXX}",
  "data": {
    "name": "Alice",
    "balance": 1000
  }
}
```

- `sent` / `recv` - HTTP request/response with redacted values replaced with `X`. The JSON structure (keys, braces, colons) is always visible; only the **values** of non-revealed keys are redacted.
- `data` - Extracted JSON object containing only the revealed keys (or full body if `reveal_body` is true)

## Request Options

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | **Required.** The URL to prove |
| `headers` | array | Additional headers to send with the request |
| `redact_headers` | array | Request headers to redact (values hidden in presentation) |
| `reveal_body` | boolean | If `true`, reveals the entire response body |
| `reveal_body_keys` | array | For JSON responses, specific keys to reveal |

**Default redactions:** `User-Agent` and `Authorization` headers are always redacted.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Host to bind the API server |
| `PORT` | `3000` | Port to bind the API server |
| `NOTARY_HOST` | `127.0.0.1` | Remote notary service host |
| `NOTARY_PORT` | `7047` | Remote notary service port |

You can also use a `.env` file in the working directory.

## Architecture

The prover communicates with the notary using two TCP connections per request:

1. **MPC Socket** - Used for the MPC-TLS verification protocol
2. **Attestation Socket** - Used to send attestation request and receive the signed attestation

### Connection Protocol

1. Prover connects to notary and sends: `[type: u8][session_id: u64]`
   - Type `0` = MPC connection (session_id `0` for new session)
   - Type `1` = Attestation connection (with assigned session_id)
2. Notary assigns a session ID and sends it back: `[session_id: u64]`
3. Prover opens second connection with the assigned session ID
4. Once both connections are established, the protocol proceeds

## Usage as a Library

```rust
use statera_prover::{create_router, AppState};

#[tokio::main]
async fn main() {
    let state = AppState::default();
    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## TLS Certificates

The prover uses Mozilla's trusted root certificates (via `webpki-root-certs`) for TLS verification, enabling connections to any publicly trusted HTTPS server.

## Dependencies

- `tlsn` - TLSNotary core library
- `axum` - Web framework
- `webpki-root-certs` - Mozilla trusted root certificates
