// Persistent hash computation compatible with Midnight's Compact runtime
//
// This module implements the persistentHash function in pure Rust, matching
// the serialization format used by Compact's onchain-runtime.
//
// Key insights from midnight-ledger:
// - persistentHash is SHA256 of binary-serialized data
// - Field values are serialized as 32-byte little-endian
// - Bytes<N> values are serialized as N bytes (data + zero padding)

use sha2::{Digest, Sha256};

/// Compute persistentHash for Bytes<N> type
///
/// Serialization format: The input bytes are written directly, followed by
/// zero-padding to reach the full length. This matches Compact's Bytes<N> type.
pub fn persistent_hash_bytes(data: &[u8], byte_length: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Write actual data
    let write_len = data.len().min(byte_length);
    hasher.update(&data[..write_len]);

    // Pad with zeros to reach full length
    let padding = byte_length.saturating_sub(data.len());
    if padding > 0 {
        hasher.update(&vec![0u8; padding]);
    }

    hasher.finalize().into()
}

/// Compute persistentHash for ChallengeInput struct
///
/// ChallengeInput layout in Compact:
/// ```compact
/// struct ChallengeInput {
///     r_x: Field;      // 32 bytes little-endian
///     r_y: Field;      // 32 bytes little-endian
///     pk_x: Field;     // 32 bytes little-endian
///     pk_y: Field;     // 32 bytes little-endian
///     credentialHash: Bytes<32>;  // 32 bytes
/// }
/// ```
///
/// The input coordinates should already be in little-endian format.
pub fn persistent_hash_challenge_input(
    r_x: &[u8; 32],
    r_y: &[u8; 32],
    pk_x: &[u8; 32],
    pk_y: &[u8; 32],
    credential_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Field elements are serialized as little-endian 32 bytes
    hasher.update(r_x);
    hasher.update(r_y);
    hasher.update(pk_x);
    hasher.update(pk_y);

    // Bytes<32> is just 32 bytes
    hasher.update(credential_hash);

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistent_hash_bytes_hello() {
        // Test data: "Hello" padded to 512 bytes
        let mut data = vec![0u8; 512];
        data[..5].copy_from_slice(b"Hello");

        let hash = persistent_hash_bytes(&data, 512);

        // Expected value from Node.js compact-runtime
        let expected = "999b4cf51bbf7f107cacd9843fa4d5a30914d686df4e7cc34f4d8b53cbff02d4";
        assert_eq!(hex::encode(hash), expected, "Bytes<512> 'Hello' hash mismatch");
    }

    #[test]
    fn test_persistent_hash_bytes_zeros() {
        // Test with all zeros
        let zeros = vec![0u8; 512];
        let hash = persistent_hash_bytes(&zeros, 512);

        // Expected value from Node.js compact-runtime (also SHA256 of 512 zeros)
        let expected = "076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560";
        assert_eq!(hex::encode(hash), expected, "Bytes<512> zeros hash mismatch");
    }

    #[test]
    fn test_persistent_hash_challenge_input_zeros() {
        // Test with all zeros
        let r_x = [0u8; 32];
        let r_y = [0u8; 32];
        let pk_x = [0u8; 32];
        let pk_y = [0u8; 32];
        let credential_hash = [0u8; 32];

        let hash = persistent_hash_challenge_input(&r_x, &r_y, &pk_x, &pk_y, &credential_hash);

        // Expected value from Node.js compact-runtime
        let expected = "b393978842a0fa3d3e1470196f098f473f9678e72463cb65ec4ab5581856c2e4";
        assert_eq!(hex::encode(hash), expected, "ChallengeInput zeros hash mismatch");
    }
}
