// Prover API crate for TLSNotary attestation
//
// This crate provides an Axum API with a single endpoint that:
// 1. Proves a URL via MPC-TLS
// 2. Creates a presentation with selective disclosure

use std::env;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use http_body_util::Empty;
use hyper::{body::Bytes, header, Request};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use spansy::Spanned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use tlsn::{
    attestation::{
        presentation::Presentation,
        request::{Request as AttestationRequest, RequestConfig},
        Attestation, CryptoProvider, Secrets,
    },
    config::{CertificateDer, ProtocolConfig, RootCertStore},
    connection::{HandshakeData, ServerName},
    prover::{state::Committed, ProveConfig, Prover, ProverConfig, ProverOutput, TlsConfig},
    transcript::TranscriptCommitConfig,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};

// Re-export signature types from notary
pub use statera_notary::{JubJubSignature, SignatureResponse};

// Maximum number of bytes that can be sent from prover to server.
pub const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server.
pub const MAX_RECV_DATA: usize = 1 << 14;

const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

// Request/Response types for the API

#[derive(Debug, Deserialize)]
pub struct ProveRequest {
    /// URL to prove
    pub url: String,
    /// Additional headers to send with the request
    #[serde(default)]
    pub headers: Vec<Header>,
    /// Request headers to redact in the presentation (values hidden)
    #[serde(default)]
    pub redact_headers: Vec<String>,
    /// If true, reveals the entire response body
    #[serde(default)]
    pub reveal_body: bool,
    /// For JSON responses, list of keys to selectively reveal
    #[serde(default)]
    pub reveal_body_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct ProveResponse {
    /// The presentation (bincode-serialized)
    pub presentation: Vec<u8>,
    /// The server name/domain that was proven
    pub server_name: Option<String>,
    /// The revealed sent data (HTTP request) - unauthenticated parts are redacted as "XXXX"
    pub sent: String,
    /// The revealed received data (HTTP response) - unauthenticated parts are redacted as "XXXX"
    pub recv: String,
    /// Extracted JSON data from the revealed body keys
    pub data: serde_json::Value,
    /// JubJub Schnorr signature from the notary over the revealed data (for Midnight/Compact verification)
    pub notary_signature: Option<SignatureResponse>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// Application state
#[derive(Clone)]
pub struct AppState {
    pub notary_host: String,
    pub notary_port: u16,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            notary_host: env::var("NOTARY_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            notary_port: env::var("NOTARY_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(7047),
        }
    }
}

/// Create the Axum router for the prover API
pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/health", get(health_check))
        .route("/prove", post(prove_handler))
        .layer(cors)
        .with_state(state)
}

async fn health_check() -> &'static str {
    "OK"
}

async fn prove_handler(
    State(state): State<AppState>,
    Json(request): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Received prove request for URL: {}", request.url);

    // Parse the URL to extract host, port, and path
    let url = url::Url::parse(&request.url).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid URL: {e}"),
            }),
        )
    })?;

    let host = url.host_str().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "URL must have a host".to_string(),
            }),
        )
    })?;

    let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let path = url.path();

    // Connect to remote notary for MPC-TLS
    let notary_addr = format!("{}:{}", state.notary_host, state.notary_port);
    info!("Connecting to notary at {}", notary_addr);

    let mut mpc_socket = tokio::net::TcpStream::connect(&notary_addr).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to connect to notary: {e}"),
            }),
        )
    })?;

    // Send connection type (0 = MPC) and session ID (0 = new session)
    mpc_socket.write_u8(0).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to send connection type: {e}"),
            }),
        )
    })?;
    mpc_socket.write_u64(0).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to send session ID: {e}"),
            }),
        )
    })?;

    // Receive assigned session ID
    let session_id = mpc_socket.read_u64().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to receive session ID: {e}"),
            }),
        )
    })?;
    info!("Got session ID {} from notary", session_id);

    // Connect attestation socket
    let mut attestation_socket = tokio::net::TcpStream::connect(&notary_addr).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to connect attestation socket to notary: {e}"),
            }),
        )
    })?;

    // Send connection type (1 = attestation) and session ID
    attestation_socket.write_u8(1).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to send attestation connection type: {e}"),
            }),
        )
    })?;
    attestation_socket.write_u64(session_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to send attestation session ID: {e}"),
            }),
        )
    })?;

    let extra_headers: Vec<(&str, &str)> = request
        .headers
        .iter()
        .map(|h| (h.name.as_str(), h.value.as_str()))
        .collect();

    let (attestation, secrets, attestation_socket) = run_prover(
        mpc_socket,
        attestation_socket,
        host,
        port,
        path,
        extra_headers,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Prove failed: {e}"),
            }),
        )
    })?;

    // Create presentation with selective disclosure
    let (presentation, data) = create_presentation(
        attestation,
        secrets,
        &request.redact_headers,
        request.reveal_body,
        &request.reveal_body_keys,
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to create presentation: {e}"),
            }),
        )
    })?;

    let presentation_bytes = bincode::serialize(&presentation).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to serialize presentation: {e}"),
            }),
        )
    })?;

    // Send presentation to notary for BIP-340 signing
    let notary_signature = get_notary_signature(attestation_socket, &presentation_bytes)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to get notary signature: {e}"),
                }),
            )
        })?;

    // Verify the presentation to extract the revealed data
    // We need to deserialize a copy since verify() consumes the presentation
    let presentation_for_verify: Presentation = bincode::deserialize(&presentation_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to deserialize presentation for verification: {e}"),
            }),
        )
    })?;

    let provider = CryptoProvider::default();
    let output = presentation_for_verify.verify(&provider).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to verify presentation: {e}"),
            }),
        )
    })?;

    // Extract server name
    let server_name = output.server_name.map(|name| match name {
        ServerName::Dns(dns) => dns.as_str().to_string(),
    });

    // Extract transcript data with redaction markers
    let (sent, recv) = if let Some(mut transcript) = output.transcript {
        // Set unauthenticated bytes to 'X' for display
        transcript.set_unauthed(b'X');

        let sent = String::from_utf8_lossy(transcript.sent_unsafe()).to_string();
        let recv = String::from_utf8_lossy(transcript.received_unsafe()).to_string();

        (sent, recv)
    } else {
        (String::new(), String::new())
    };

    info!("Presentation created successfully ({} bytes)", presentation_bytes.len());

    Ok(Json(ProveResponse {
        presentation: presentation_bytes,
        server_name,
        sent,
        recv,
        data,
        notary_signature: Some(notary_signature),
    }))
}

fn create_presentation(
    attestation: Attestation,
    secrets: Secrets,
    redact_headers: &[String],
    reveal_body: bool,
    reveal_body_keys: &[String],
) -> Result<(Presentation, serde_json::Value), Box<dyn std::error::Error + Send + Sync>> {
    let transcript = HttpTranscript::parse(secrets.transcript())?;

    let mut builder = secrets.transcript_proof_builder();

    // Process request
    let request = &transcript.requests[0];
    builder.reveal_sent(&request.without_data())?;
    builder.reveal_sent(&request.request.target)?;

    // Reveal request headers, redacting specified ones
    for hdr in &request.headers {
        let should_redact = redact_headers.iter().any(|name| {
            hdr.name.as_str().eq_ignore_ascii_case(name)
        }) || hdr.name.as_str().eq_ignore_ascii_case(header::USER_AGENT.as_str())
            || hdr.name.as_str().eq_ignore_ascii_case(header::AUTHORIZATION.as_str());

        if should_redact {
            builder.reveal_sent(&hdr.without_value())?;
        } else {
            builder.reveal_sent(hdr)?;
        }
    }

    // Process response
    let response = &transcript.responses[0];
    builder.reveal_recv(&response.without_data())?;

    // Reveal all response headers
    for hdr in &response.headers {
        builder.reveal_recv(hdr)?;
    }

    // Extract revealed data from the original transcript
    let mut revealed_data = serde_json::Value::Null;

    // Reveal body content
    if let Some(body) = &response.body {
        let content = &body.content;
        match content {
            tlsn_formats::http::BodyContent::Json(json) => {
                if reveal_body {
                    builder.reveal_recv(response)?;
                    // Extract full body as JSON
                    let body_bytes = content.span().data();
                    let body_str = std::str::from_utf8(body_bytes).unwrap_or("");
                    revealed_data = serde_json::from_str(body_str).unwrap_or(serde_json::Value::Null);
                } else {
                    // Reveal the JSON structure with selective value disclosure
                    // This shows the full JSON structure but only reveals values for specified keys
                    let mut result_map = serde_json::Map::new();

                    if let tlsn_formats::json::JsonValue::Object(obj) = json {
                        // Reveal the object braces {}
                        builder.reveal_recv(&obj.without_pairs())?;

                        // For each key-value pair in the object
                        for kv in &obj.elems {
                            // Get key as string from the span bytes
                            let key_bytes = kv.key.span().data();
                            let key_str = std::str::from_utf8(key_bytes).unwrap_or("");
                            // Remove quotes from key
                            let key_str = key_str.trim_matches('"');

                            // Always reveal the key and colon (e.g., `"price":`)
                            builder.reveal_recv(&kv.without_value())?;

                            // Only reveal the value if it's in our reveal list
                            if reveal_body_keys.iter().any(|k| k.eq_ignore_ascii_case(key_str)) {
                                builder.reveal_recv(&kv.value)?;

                                // Extract the value for the data field
                                let value_bytes = kv.value.span().data();
                                let value_str = std::str::from_utf8(value_bytes).unwrap_or("");
                                if let Ok(parsed_value) = serde_json::from_str::<serde_json::Value>(&value_str) {
                                    result_map.insert(key_str.to_string(), parsed_value);
                                }
                            }
                        }
                    } else {
                        // Not an object, just reveal specified keys if any
                        for key in reveal_body_keys {
                            if let Some(value) = json.get(key) {
                                builder.reveal_recv(value)?;

                                // Extract the value for the data field
                                let value_bytes = value.span().data();
                                let value_str = std::str::from_utf8(value_bytes).unwrap_or("");
                                if let Ok(parsed_value) = serde_json::from_str::<serde_json::Value>(&value_str) {
                                    result_map.insert(key.clone(), parsed_value);
                                }
                            }
                        }
                    }

                    if !result_map.is_empty() {
                        revealed_data = serde_json::Value::Object(result_map);
                    }
                }
            }
            tlsn_formats::http::BodyContent::Unknown(span) => {
                if reveal_body {
                    builder.reveal_recv(span)?;
                    // For unknown content, just return the raw string
                    let body_str = std::str::from_utf8(span.data()).unwrap_or("");
                    revealed_data = serde_json::Value::String(body_str.to_string());
                }
            }
            _ => {}
        }
    }

    let transcript_proof = builder.build()?;

    let provider = CryptoProvider::default();
    let mut builder = attestation.presentation_builder(&provider);

    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);

    let presentation = builder.build()?;

    Ok((presentation, revealed_data))
}

/// Run the prover to establish an MPC-TLS connection and request attestation
///
/// This function uses two sockets to communicate with the notary:
/// - `mpc_socket`: Used for the MPC-TLS protocol
/// - `attestation_socket`: Used to send attestation request and receive attestation
///
/// Returns the attestation, secrets, and the attestation socket (for subsequent signing).
pub async fn run_prover<S1, S2>(
    mpc_socket: S1,
    attestation_socket: S2,
    server_host: &str,
    server_port: u16,
    uri: &str,
    extra_headers: Vec<(&str, &str)>,
) -> Result<(Attestation, Secrets, S2), Box<dyn std::error::Error + Send + Sync>>
where
    S1: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    S2: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    // Use system root certificates for TLS
    let mut root_store = RootCertStore::empty();

    // Load webpki root certificates
    for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        root_store.roots.push(CertificateDer(cert.to_vec()));
    }

    let mut tls_config_builder = TlsConfig::builder();
    tls_config_builder.root_store(root_store);

    let tls_config = tls_config_builder.build().unwrap();

    let mut prover_config_builder = ProverConfig::builder();
    prover_config_builder
        .server_name(ServerName::Dns(server_host.try_into().map_err(|e| format!("Invalid server name: {e}"))?))
        .tls_config(tls_config)
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        );

    let prover_config = prover_config_builder.build()?;

    let prover = Prover::new(prover_config).setup(mpc_socket.compat()).await?;

    // Connect to the target server
    let client_socket = tokio::net::TcpStream::connect((server_host, server_port)).await?;

    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    tokio::spawn(connection);

    let request_builder = Request::builder()
        .uri(uri)
        .header("Host", server_host)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT);

    let mut request_builder = request_builder;
    for (key, value) in extra_headers {
        request_builder = request_builder.header(key, value);
    }
    let request = request_builder.body(Empty::<Bytes>::new())?;

    info!("Starting an MPC TLS connection with the server");

    let response = request_sender.send_request(request).await?;

    info!("Got a response from the server: {}", response.status());

    if response.status() != hyper::StatusCode::OK {
        return Err(format!("Server returned status: {}", response.status()).into());
    }

    let prover = prover_task.await??;

    let transcript = HttpTranscript::parse(prover.transcript())?;

    let body_content = &transcript.responses[0].body.as_ref().unwrap().content;
    let body = String::from_utf8_lossy(body_content.span().as_bytes());

    match body_content {
        tlsn_formats::http::BodyContent::Json(_json) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&body)?;
            info!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        tlsn_formats::http::BodyContent::Unknown(_span) => {
            info!("{}", &body);
        }
        _ => {}
    }

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;

    let transcript_commit = builder.build()?;

    let mut builder = RequestConfig::builder();
    builder.transcript_commit(transcript_commit);

    let request_config = builder.build()?;

    let (attestation, secrets, attestation_socket) = notarize(prover, &request_config, server_host, attestation_socket).await?;

    Ok((attestation, secrets, attestation_socket))
}

async fn notarize<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    mut prover: Prover<Committed>,
    config: &RequestConfig,
    server_host: &str,
    mut attestation_socket: S,
) -> Result<(Attestation, Secrets, S), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = ProveConfig::builder(prover.transcript());

    if let Some(config) = config.transcript_commit() {
        builder.transcript_commit(config.clone());
    }

    let disclosure_config = builder.build()?;

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&disclosure_config).await?;

    let transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    let mut builder = AttestationRequest::builder(config);

    builder
        .server_name(ServerName::Dns(server_host.try_into().map_err(|e| format!("Invalid server name: {e}"))?))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .expect("server cert chain is present")
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .expect("server signature is present")
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);

    let (request, secrets) = builder.build(&CryptoProvider::default())?;

    // Send attestation request over the socket
    // Protocol: 4-byte length prefix (big-endian) followed by bincode-encoded request
    let request_bytes = bincode::serialize(&request)?;
    info!("Sending attestation request ({} bytes)", request_bytes.len());
    attestation_socket.write_u32(request_bytes.len() as u32).await?;
    attestation_socket.write_all(&request_bytes).await?;
    attestation_socket.flush().await?;

    // Receive attestation from notary
    // Protocol: 4-byte length prefix (big-endian) followed by bincode-encoded attestation
    let attestation_len = attestation_socket.read_u32().await? as usize;
    info!("Receiving attestation ({} bytes)", attestation_len);
    let mut attestation_bytes = vec![0u8; attestation_len];
    attestation_socket.read_exact(&mut attestation_bytes).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)?;

    request.validate(&attestation)?;
    info!("Attestation validated successfully");

    // Return the socket so caller can send presentation for signing
    Ok((attestation, secrets, attestation_socket))
}

/// Send presentation to notary for JubJub signing
async fn get_notary_signature<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    mut attestation_socket: S,
    presentation_bytes: &[u8],
) -> Result<SignatureResponse, Box<dyn std::error::Error + Send + Sync>> {
    // Send presentation to notary for verification and signing
    info!("Sending presentation for signing ({} bytes)", presentation_bytes.len());
    attestation_socket.write_u32(presentation_bytes.len() as u32).await?;
    attestation_socket.write_all(presentation_bytes).await?;
    attestation_socket.flush().await?;

    // Receive JubJub signature from notary
    let sig_len = attestation_socket.read_u32().await? as usize;
    info!("Receiving JubJub signature ({} bytes)", sig_len);
    let mut sig_bytes = vec![0u8; sig_len];
    attestation_socket.read_exact(&mut sig_bytes).await?;
    let signature_response: SignatureResponse = bincode::deserialize(&sig_bytes)?;

    info!("JubJub signature received successfully");
    Ok(signature_response)
}
