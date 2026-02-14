//! Post-quantum authenticated encryption for transaction messages and note data.
//!
//! Uses Kyber1024 KEM to establish a shared secret, then BLAKE3 in keyed mode
//! for authenticated encryption (encrypt-then-MAC).
//!
//! # Security rationale (H8)
//!
//! This module implements a custom AEAD construction because standard AEAD
//! ciphers (AES-GCM, ChaCha20-Poly1305) have classical key-recovery
//! complexity ≤128 bits. By using BLAKE3 (256-bit security margin) for both
//! the keystream and the MAC, this construction matches the post-quantum
//! security level of the KEM (Kyber1024, NIST Level 5).
//!
//! Message flow:
//! 1. Sender encapsulates against recipient's KEM public key -> (shared_secret, ciphertext)
//! 2. Derive encryption key and MAC key from shared_secret + nonce (domain-separated BLAKE3)
//! 3. XOR-encrypt the plaintext with a BLAKE3-derived keystream
//! 4. Compute MAC over (nonce || len(ciphertext) || ciphertext || len(kem_ct) || kem_ct)
//!
//! A random 24-byte nonce is included in every payload, ensuring that even if
//! the same shared secret is reused (via encrypt_with_shared_secret), the
//! keystream and MAC are unique.
//!
//! # Security analysis
//!
//! - **IND-CPA**: The keystream is derived via BLAKE3 in key-derivation mode
//!   with a fresh random 24-byte nonce per encryption. Each (key, nonce, counter)
//!   triple produces a unique keystream block. Nonce collision probability is
//!   ~2^{-96} per encryption under the same shared secret (birthday bound on
//!   192-bit nonces).
//!
//! - **INT-CTXT**: Encrypt-then-MAC with keyed BLAKE3. The MAC covers nonce,
//!   length-prefixed ciphertext, and length-prefixed KEM ciphertext. Length
//!   prefixing prevents boundary-ambiguity attacks.
//!
//! - **Key separation**: Encryption and MAC keys are derived from the shared
//!   secret using distinct BLAKE3 domain strings (`"umbra.encrypt.key"` and
//!   `"umbra.encrypt.mac"`), preventing related-key attacks.
//!
//! - **Why not standard AEAD**: AES-256-GCM and ChaCha20-Poly1305 provide at
//!   most 128-bit classical key-recovery security. BLAKE3 targets a 256-bit
//!   security margin, matching the post-quantum security level of Kyber1024
//!   (NIST Level 5). Using a standard AEAD would create a security level
//!   mismatch where the symmetric cipher is the weakest link.
//!
//! - **Limitations**: This construction has not undergone formal cryptographic
//!   analysis or third-party audit. The security argument relies on BLAKE3's
//!   PRF properties and the standard encrypt-then-MAC composition theorem.

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::keys::{KemCiphertext, KemKeypair, KemPublicKey, SharedSecret};
use crate::Hash;

/// Nonce size in bytes.
const NONCE_SIZE: usize = 24;

/// Padding bucket for encrypted payloads (bytes). Ciphertexts are padded to the
/// next multiple of this value to prevent message length from leaking information
/// about the plaintext structure.
const ENCRYPT_PADDING_BUCKET: usize = 64;

/// Pad plaintext with a 4-byte length prefix and random padding to the next
/// multiple of `ENCRYPT_PADDING_BUCKET`.
fn pad_plaintext(plaintext: &[u8]) -> Vec<u8> {
    // L5: Guard against silent truncation when casting length to u32.
    debug_assert!(
        plaintext.len() <= u32::MAX as usize,
        "plaintext length exceeds u32::MAX, length prefix would truncate"
    );
    let len = plaintext.len() as u32;
    let total = 4 + plaintext.len();
    let padded_len = total.div_ceil(ENCRYPT_PADDING_BUCKET) * ENCRYPT_PADDING_BUCKET;
    let mut buf = Vec::with_capacity(padded_len);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(plaintext);
    // Fill remaining with random bytes to prevent padding oracle attacks
    let pad_bytes = padded_len - total;
    if pad_bytes > 0 {
        let mut pad = vec![0u8; pad_bytes];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut pad);
        buf.extend_from_slice(&pad);
    }
    buf
}

/// Remove padding: read 4-byte length prefix, return that many bytes.
fn unpad_plaintext(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
    if 4 + len > data.len() {
        return None;
    }
    Some(data[4..4 + len].to_vec())
}

/// An encrypted message with its KEM ciphertext for the recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// KEM ciphertext — recipient decapsulates to get shared secret
    pub kem_ciphertext: KemCiphertext,
    /// Random nonce (unique per encryption, prevents keystream reuse)
    pub nonce: [u8; NONCE_SIZE],
    /// Encrypted data (XOR keystream cipher)
    pub ciphertext: Vec<u8>,
    /// Authentication tag (BLAKE3 keyed hash)
    pub mac: Hash,
}

impl EncryptedPayload {
    /// Encrypt a plaintext message to a recipient's KEM public key.
    ///
    /// Returns `None` if the KEM encapsulation fails or if the plaintext
    /// exceeds `MAX_ENCRYPT_PLAINTEXT`.
    pub fn encrypt(recipient: &KemPublicKey, plaintext: &[u8]) -> Option<Self> {
        if plaintext.len() > crate::constants::MAX_ENCRYPT_PLAINTEXT {
            return None;
        }
        let (shared_secret, kem_ct) = recipient.encapsulate()?;
        let nonce = random_nonce();
        let (enc_key, mac_key) = derive_keys(&shared_secret, &nonce);

        let padded = pad_plaintext(plaintext);
        let ciphertext = xor_keystream(&enc_key, &nonce, &padded);
        let mac = compute_mac(&mac_key, &nonce, &ciphertext, &kem_ct);

        Some(EncryptedPayload {
            kem_ciphertext: kem_ct,
            nonce,
            ciphertext,
            mac,
        })
    }

    /// Decrypt using the recipient's KEM keypair.
    pub fn decrypt(&self, recipient_kp: &KemKeypair) -> Option<Vec<u8>> {
        let shared_secret = recipient_kp.decapsulate(&self.kem_ciphertext)?;
        let (enc_key, mac_key) = derive_keys(&shared_secret, &self.nonce);

        // Verify MAC first (authenticate-then-decrypt) using constant-time comparison
        let expected_mac = compute_mac(
            &mac_key,
            &self.nonce,
            &self.ciphertext,
            &self.kem_ciphertext,
        );
        if !crate::constant_time_eq(&expected_mac, &self.mac) {
            return None;
        }

        let padded = xor_keystream(&enc_key, &self.nonce, &self.ciphertext);
        unpad_plaintext(&padded)
    }

    /// Encrypt with a pre-established shared secret (for stealth address outputs
    /// where the KEM exchange already happened). A fresh nonce ensures unique
    /// keystreams even when the shared secret is reused.
    ///
    /// Returns `None` if the plaintext exceeds `MAX_ENCRYPT_PLAINTEXT`.
    pub fn encrypt_with_shared_secret(
        shared_secret: &SharedSecret,
        kem_ciphertext: KemCiphertext,
        plaintext: &[u8],
    ) -> Option<Self> {
        if plaintext.len() > crate::constants::MAX_ENCRYPT_PLAINTEXT {
            return None;
        }
        let nonce = random_nonce();
        let (enc_key, mac_key) = derive_keys(shared_secret, &nonce);
        let padded = pad_plaintext(plaintext);
        let ciphertext = xor_keystream(&enc_key, &nonce, &padded);
        let mac = compute_mac(&mac_key, &nonce, &ciphertext, &kem_ciphertext);

        Some(EncryptedPayload {
            kem_ciphertext,
            nonce,
            ciphertext,
            mac,
        })
    }

    /// Decrypt with a pre-established shared secret.
    pub fn decrypt_with_shared_secret(&self, shared_secret: &SharedSecret) -> Option<Vec<u8>> {
        let (enc_key, mac_key) = derive_keys(shared_secret, &self.nonce);
        let expected_mac = compute_mac(
            &mac_key,
            &self.nonce,
            &self.ciphertext,
            &self.kem_ciphertext,
        );
        if !crate::constant_time_eq(&expected_mac, &self.mac) {
            return None;
        }
        let padded = xor_keystream(&enc_key, &self.nonce, &self.ciphertext);
        unpad_plaintext(&padded)
    }
}

/// Generate a cryptographically random nonce.
///
/// M12: Uses `rand::rng()` which is a CSPRNG (ChaCha20 seeded from OsRng).
/// This provides the same security guarantees as OsRng with better
/// performance for bulk operations.
fn random_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Derive encryption and MAC keys from a shared secret and nonce.
fn derive_keys(ss: &SharedSecret, nonce: &[u8; NONCE_SIZE]) -> ([u8; 32], [u8; 32]) {
    let mut enc_input = [0u8; 56]; // 32 + 24
    enc_input[..32].copy_from_slice(&ss.0);
    enc_input[32..].copy_from_slice(nonce);
    let enc_key = crate::hash_domain(b"umbra.encrypt.key", &enc_input);

    let mut mac_input = [0u8; 56];
    mac_input[..32].copy_from_slice(&ss.0);
    mac_input[32..].copy_from_slice(nonce);
    let mac_key = crate::hash_domain(b"umbra.encrypt.mac", &mac_input);

    (enc_key, mac_key)
}

/// XOR-based stream cipher using BLAKE3 as the keystream generator.
/// Keystream block i = H("umbra.keystream" || key || nonce || counter_i).
fn xor_keystream(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    let mut counter = 0u64;
    let mut pos = 0;

    while pos < data.len() {
        let mut block_input = Vec::with_capacity(32 + NONCE_SIZE + 8);
        block_input.extend_from_slice(key);
        block_input.extend_from_slice(nonce);
        block_input.extend_from_slice(&counter.to_le_bytes());
        let block = crate::hash_domain(b"umbra.keystream", &block_input);

        let remaining = data.len() - pos;
        let take = remaining.min(32);
        for i in 0..take {
            output.push(data[pos + i] ^ block[i]);
        }
        pos += take;
        counter += 1;
    }

    output
}

/// Compute MAC over (nonce || len(ciphertext) || ciphertext || len(kem_ct) || kem_ct)
/// using BLAKE3 keyed mode.
///
/// Each variable-length field is prefixed with its length as a little-endian u64,
/// preventing boundary-ambiguity attacks where an adversary shifts bytes between
/// the ciphertext and KEM ciphertext while preserving the same MAC input.
fn compute_mac(
    mac_key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    kem_ct: &KemCiphertext,
) -> Hash {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(nonce);
    hasher.update(&(ciphertext.len() as u64).to_le_bytes());
    hasher.update(ciphertext);
    hasher.update(&(kem_ct.0.len() as u64).to_le_bytes());
    hasher.update(&kem_ct.0);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KemKeypair;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let kp = KemKeypair::generate();
        let msg = b"hello umbra! this is an encrypted transaction message.";
        let encrypted = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let kp1 = KemKeypair::generate();
        let kp2 = KemKeypair::generate();
        let msg = b"secret message";
        let encrypted = EncryptedPayload::encrypt(&kp1.public, msg).unwrap();
        assert!(encrypted.decrypt(&kp2).is_none());
    }

    #[test]
    fn tampered_ciphertext_fails_mac() {
        let kp = KemKeypair::generate();
        let msg = b"integrity test";
        let mut encrypted = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xff;
        }
        assert!(encrypted.decrypt(&kp).is_none());
    }

    #[test]
    fn tampered_nonce_fails_mac() {
        let kp = KemKeypair::generate();
        let msg = b"nonce test";
        let mut encrypted = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        encrypted.nonce[0] ^= 0xff;
        assert!(encrypted.decrypt(&kp).is_none());
    }

    #[test]
    fn empty_message() {
        let kp = KemKeypair::generate();
        let encrypted = EncryptedPayload::encrypt(&kp.public, b"").unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn large_message() {
        let kp = KemKeypair::generate();
        let msg = vec![0xABu8; 10_000];
        let encrypted = EncryptedPayload::encrypt(&kp.public, &msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn shared_secret_reuse_produces_different_ciphertexts() {
        let kp = KemKeypair::generate();
        let (ss, ct) = kp.public.encapsulate().unwrap();
        let msg = b"same message";

        let e1 = EncryptedPayload::encrypt_with_shared_secret(&ss, ct.clone(), msg).unwrap();
        let e2 = EncryptedPayload::encrypt_with_shared_secret(&ss, ct, msg).unwrap();

        // Different nonces -> different ciphertexts (with overwhelming probability)
        assert_ne!(e1.nonce, e2.nonce);
        assert_ne!(e1.ciphertext, e2.ciphertext);

        // Both decrypt correctly
        assert_eq!(e1.decrypt_with_shared_secret(&ss).unwrap(), msg);
        assert_eq!(e2.decrypt_with_shared_secret(&ss).unwrap(), msg);
    }

    #[test]
    fn oversized_plaintext_rejected() {
        let kp = KemKeypair::generate();
        let huge = vec![0u8; crate::constants::MAX_ENCRYPT_PLAINTEXT + 1];
        assert!(EncryptedPayload::encrypt(&kp.public, &huge).is_none());
    }

    #[test]
    fn encrypt_exactly_32_bytes() {
        // Exactly one keystream block
        let kp = KemKeypair::generate();
        let msg = vec![0xABu8; 32];
        let encrypted = EncryptedPayload::encrypt(&kp.public, &msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_33_bytes_crosses_block_boundary() {
        // Crosses keystream block boundary (32 → 33 bytes)
        let kp = KemKeypair::generate();
        let msg = vec![0xCDu8; 33];
        let encrypted = EncryptedPayload::encrypt(&kp.public, &msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_with_shared_secret_oversized_rejected() {
        let kp = KemKeypair::generate();
        let (ss, ct) = kp.public.encapsulate().unwrap();
        let huge = vec![0u8; crate::constants::MAX_ENCRYPT_PLAINTEXT + 1];
        assert!(EncryptedPayload::encrypt_with_shared_secret(&ss, ct, &huge).is_none());
    }

    #[test]
    fn tampered_mac_directly_fails() {
        let kp = KemKeypair::generate();
        let msg = b"mac tamper test";
        let mut encrypted = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        encrypted.mac[0] ^= 0xff;
        assert!(encrypted.decrypt(&kp).is_none());
    }

    #[test]
    fn decrypt_with_shared_secret_roundtrip() {
        let kp = KemKeypair::generate();
        let (ss, ct) = kp.public.encapsulate().unwrap();
        let msg = b"shared secret roundtrip";
        let encrypted = EncryptedPayload::encrypt_with_shared_secret(&ss, ct, msg).unwrap();
        let decrypted = encrypted.decrypt_with_shared_secret(&ss).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn decrypt_with_wrong_shared_secret_fails() {
        let kp1 = KemKeypair::generate();
        let kp2 = KemKeypair::generate();
        let (ss1, ct1) = kp1.public.encapsulate().unwrap();
        let (ss2, _) = kp2.public.encapsulate().unwrap();

        let msg = b"wrong secret test";
        let encrypted = EncryptedPayload::encrypt_with_shared_secret(&ss1, ct1, msg).unwrap();
        assert!(encrypted.decrypt_with_shared_secret(&ss2).is_none());
    }

    #[test]
    fn encrypt_exactly_at_max_limit() {
        let kp = KemKeypair::generate();
        let msg = vec![0xFFu8; crate::constants::MAX_ENCRYPT_PLAINTEXT];
        let encrypted = EncryptedPayload::encrypt(&kp.public, &msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }
}
