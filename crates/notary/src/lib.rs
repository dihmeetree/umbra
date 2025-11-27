// Notary crate for TLSNotary attestation
//
// This crate provides functionality for a notary to verify TLS sessions and
// generate attestations. The notary participates in the MPC protocol with the
// prover and signs the resulting attestation.

use std::env;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::info;

pub mod jubjub_signer;
pub mod persistent_hash;

pub use jubjub_signer::{JubJubSignature, JubJubSigningKey};
pub use persistent_hash::{persistent_hash_bytes, persistent_hash_challenge_input};

use tlsn::{
    attestation::{
        request::Request as AttestationRequest,
        signing::Secp256k1Signer,
        Attestation, AttestationConfig, CryptoProvider,
    },
    config::{CertificateDer, ProtocolConfigValidator, RootCertStore},
    connection::{ConnectionInfo, TranscriptLength},
    transcript::ContentType,
    verifier::{Verifier, VerifierConfig, VerifierOutput, VerifyConfig},
};

/// JubJub signature response for Midnight/Compact compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureResponse {
    /// The JubJub signature
    pub signature: JubJubSignature,
    /// The raw data that was signed (e.g., JSON bytes)
    pub data: Vec<u8>,
}

// Maximum number of bytes that can be sent from prover to server.
pub const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server.
pub const MAX_RECV_DATA: usize = 1 << 14;

/// Configuration for the notary
#[derive(Clone)]
pub struct NotaryConfig {
    /// Signing key bytes (32 bytes)
    pub signing_key: [u8; 32],
    /// Root certificate store for TLS verification
    pub root_store: RootCertStore,
    /// Maximum sent data size
    pub max_sent_data: usize,
    /// Maximum received data size
    pub max_recv_data: usize,
}

impl NotaryConfig {
    /// Create a new NotaryConfig with the given signing key
    pub fn new(signing_key: [u8; 32]) -> Self {
        // Load webpki root certificates by default
        let mut root_store = RootCertStore::empty();
        for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            root_store.roots.push(CertificateDer(cert.to_vec()));
        }

        Self {
            signing_key,
            root_store,
            max_sent_data: MAX_SENT_DATA,
            max_recv_data: MAX_RECV_DATA,
        }
    }

    /// Create config from environment variable NOTARY_SIGNING_KEY (hex-encoded)
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let key_hex = env::var("NOTARY_SIGNING_KEY")
            .map_err(|_| "NOTARY_SIGNING_KEY environment variable not set")?;

        let key_bytes = hex::decode(&key_hex)
            .map_err(|e| format!("Invalid hex in NOTARY_SIGNING_KEY: {e}"))?;

        if key_bytes.len() != 32 {
            return Err(format!(
                "NOTARY_SIGNING_KEY must be 32 bytes, got {}",
                key_bytes.len()
            )
            .into());
        }

        let mut signing_key = [0u8; 32];
        signing_key.copy_from_slice(&key_bytes);

        Ok(Self::new(signing_key))
    }

    /// Set custom root certificate store
    pub fn with_root_store(mut self, root_store: RootCertStore) -> Self {
        self.root_store = root_store;
        self
    }

    /// Set maximum sent data size
    pub fn with_max_sent_data(mut self, max_sent_data: usize) -> Self {
        self.max_sent_data = max_sent_data;
        self
    }

    /// Set maximum received data size
    pub fn with_max_recv_data(mut self, max_recv_data: usize) -> Self {
        self.max_recv_data = max_recv_data;
        self
    }
}

/// Run the notary to verify a TLS session and generate an attestation
///
/// This function handles both the MPC-TLS protocol and the attestation exchange.
/// It takes two sockets:
/// - `mpc_socket`: Used for the MPC-TLS verification protocol
/// - `attestation_socket`: Used to receive attestation request and send back attestation
///
/// The protocol is:
/// 1. MPC-TLS verification (handled by tlsn Verifier) over mpc_socket
/// 2. Receive attestation request from prover (length-prefixed bincode) over attestation_socket
/// 3. Sign and send attestation back to prover (length-prefixed bincode) over attestation_socket
pub async fn run_notary<S1, S2>(
    mpc_socket: S1,
    mut attestation_socket: S2,
    config: NotaryConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S1: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
    S2: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static,
{
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(config.max_sent_data)
        .max_recv_data(config.max_recv_data)
        .build()
        .unwrap();

    let verifier_config = VerifierConfig::builder()
        .root_store(config.root_store.clone())
        .protocol_config_validator(config_validator)
        .build()
        .unwrap();

    let mut verifier = Verifier::new(verifier_config)
        .setup(mpc_socket.compat())
        .await?
        .run()
        .await?;

    let VerifierOutput {
        transcript_commitments,
        encoder_secret,
        ..
    } = verifier.verify(&VerifyConfig::default()).await?;

    let tls_transcript = verifier.tls_transcript().clone();

    verifier.close().await?;

    let sent_len = tls_transcript
        .sent()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    let recv_len = tls_transcript
        .recv()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    info!("MPC-TLS verification complete, waiting for attestation request");

    // Receive attestation request from prover over the attestation socket
    // Protocol: 4-byte length prefix (big-endian) followed by bincode-encoded request
    let request_len = attestation_socket.read_u32().await? as usize;
    info!("Receiving attestation request ({} bytes)", request_len);
    let mut request_bytes = vec![0u8; request_len];
    attestation_socket.read_exact(&mut request_bytes).await?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)?;
    info!("Received attestation request");

    // Create signer from configured signing key (for TLSNotary attestation)
    let signing_key = k256::ecdsa::SigningKey::from_bytes(&config.signing_key.into())?;
    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    // Build an attestation.
    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let att_config = att_config_builder.build()?;

    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: (*tls_transcript.version()),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(tls_transcript.server_ephemeral_key().clone())
        .transcript_commitments(transcript_commitments);

    if let Some(encoder_secret) = encoder_secret {
        builder.encoder_secret(encoder_secret);
    }

    let attestation = builder.build(&provider)?;

    // Send attestation to prover over the attestation socket
    // Protocol: 4-byte length prefix (big-endian) followed by bincode-encoded attestation
    let attestation_bytes = bincode::serialize(&attestation)?;
    info!("Sending attestation ({} bytes)", attestation_bytes.len());
    attestation_socket.write_u32(attestation_bytes.len() as u32).await?;
    attestation_socket.write_all(&attestation_bytes).await?;
    attestation_socket.flush().await?;

    info!("Attestation sent, waiting for presentation to sign");

    // Receive presentation from prover
    // Protocol: 4-byte length prefix (big-endian) followed by bincode-encoded presentation
    let presentation_len = attestation_socket.read_u32().await? as usize;
    info!("Receiving presentation ({} bytes)", presentation_len);
    let mut presentation_bytes = vec![0u8; presentation_len];
    attestation_socket.read_exact(&mut presentation_bytes).await?;

    let presentation: tlsn::attestation::presentation::Presentation = bincode::deserialize(&presentation_bytes)?;

    // Verify the presentation and extract revealed data
    let provider = CryptoProvider::default();
    let output = presentation.verify(&provider)?;

    // Extract the revealed response body from the transcript as clean JSON
    let data_to_sign = if let Some(transcript) = output.transcript {
        // Get the received bytes (response)
        let recv_bytes = transcript.received_unsafe();
        let recv_str = String::from_utf8_lossy(recv_bytes);

        // Find the body (after headers)
        if let Some(body_start) = recv_str.find("\r\n\r\n").map(|p| p + 4)
            .or_else(|| recv_str.find("\n\n").map(|p| p + 2))
        {
            let authed = transcript.received_authed();
            let body_bytes = &recv_bytes[body_start..];

            // Try to parse as JSON and extract only revealed key-value pairs
            if let Ok(full_json) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
                if let Some(obj) = full_json.as_object() {
                    // Build a new object with only the keys that have authenticated values
                    let mut revealed_obj = serde_json::Map::new();

                    for (key, value) in obj.iter() {
                        // Serialize the value to check if it's fully authenticated
                        let value_str = serde_json::to_string(value).unwrap_or_default();

                        // Find where this key-value appears in the body
                        let search_key = format!("\"{}\":", key);
                        if let Some(key_pos) = recv_str[body_start..].find(&search_key) {
                            let abs_key_pos = body_start + key_pos;
                            let value_start = abs_key_pos + search_key.len();

                            // Check if the value portion is authenticated
                            // We check if a significant portion of the value bytes are authenticated
                            let value_end = (value_start + value_str.len()).min(recv_bytes.len());
                            let mut authed_count = 0;
                            for i in value_start..value_end {
                                if authed.contains(&i) {
                                    authed_count += 1;
                                }
                            }

                            // If most of the value is authenticated, include it
                            if authed_count > 0 && authed_count >= (value_end - value_start) / 2 {
                                revealed_obj.insert(key.clone(), value.clone());
                            }
                        }
                    }

                    // Serialize the revealed object as canonical JSON
                    serde_json::to_vec(&serde_json::Value::Object(revealed_obj)).unwrap_or_default()
                } else {
                    // Not an object, just return the full body if authenticated
                    let mut authed_count = 0;
                    for i in body_start..recv_bytes.len() {
                        if authed.contains(&i) {
                            authed_count += 1;
                        }
                    }
                    if authed_count > 0 {
                        body_bytes.to_vec()
                    } else {
                        Vec::new()
                    }
                }
            } else {
                // Not JSON, extract raw authenticated bytes
                let mut body_vec = Vec::new();
                for i in body_start..recv_bytes.len() {
                    if authed.contains(&i) {
                        body_vec.push(recv_bytes[i]);
                    }
                }
                body_vec
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    info!("Extracted {} bytes of revealed data to sign", data_to_sign.len());

    // Pad data to 512 bytes for the contract's Bytes<512> type
    const PADDED_SIZE: usize = 512;
    let mut padded_data = vec![0u8; PADDED_SIZE];
    let data_len = data_to_sign.len().min(PADDED_SIZE);
    padded_data[..data_len].copy_from_slice(&data_to_sign[..data_len]);

    // Compute credential hash using Compact's persistentHash<Bytes<512>>
    let credential_hash = persistent_hash::persistent_hash_bytes(&padded_data, PADDED_SIZE);

    info!("Computed credential hash: {}", hex::encode(&credential_hash));

    // Create JubJub signature using persistentHash for both data and challenge
    let jubjub_signing_key = JubJubSigningKey::from_bytes(&config.signing_key);
    let signature = jubjub_signing_key.sign_with_persistent_hash(
        &credential_hash,
        |r_x, r_y, pk_x, pk_y, cred_hash| {
            persistent_hash::persistent_hash_challenge_input(r_x, r_y, pk_x, pk_y, cred_hash)
        },
    );

    let response = SignatureResponse {
        signature,
        data: data_to_sign, // Return original (unpadded) data
    };

    // Send JubJub signature to prover
    let sig_bytes = bincode::serialize(&response)?;
    info!("Sending JubJub signature ({} bytes)", sig_bytes.len());
    attestation_socket.write_u32(sig_bytes.len() as u32).await?;
    attestation_socket.write_all(&sig_bytes).await?;
    attestation_socket.flush().await?;

    info!("Attestation and JubJub signature sent successfully");
    Ok(())
}
