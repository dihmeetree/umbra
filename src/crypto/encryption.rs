//! Post-quantum authenticated encryption for transaction messages and note data.
//!
//! Uses Kyber1024 KEM to establish a shared secret, then XChaCha20-Poly1305
//! (a standard AEAD) for authenticated encryption.
//!
//! Message flow:
//! 1. Sender encapsulates against recipient's KEM public key -> (shared_secret, ciphertext)
//! 2. Derive encryption key from shared_secret + nonce (domain-separated BLAKE3)
//! 3. Encrypt the padded plaintext with XChaCha20-Poly1305 (AAD = KEM ciphertext)
//!
//! A random 24-byte nonce is included in every payload, ensuring that even if
//! the same shared secret is reused (via encrypt_with_shared_secret), the
//! keystream is unique.
//!
//! The KEM ciphertext is bound via AEAD associated data (AAD), so any
//! modification of the KEM ciphertext is detected during decryption.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::keys::{KemCiphertext, KemKeypair, KemPublicKey, SharedSecret};

/// Nonce size in bytes (matches XChaCha20-Poly1305 nonce).
const NONCE_SIZE: usize = 24;

/// Padding bucket for encrypted payloads (bytes). Plaintexts are padded to the
/// next multiple of this value to prevent message length from leaking information
/// about the plaintext structure.
const ENCRYPT_PADDING_BUCKET: usize = 64;

/// Poly1305 authentication tag size (appended to ciphertext by AEAD).
#[cfg(test)]
const TAG_SIZE: usize = 16;

/// Pad plaintext with a 4-byte length prefix and random padding to the next
/// multiple of `ENCRYPT_PADDING_BUCKET`.
fn pad_plaintext(plaintext: &[u8]) -> Vec<u8> {
    // Guard against silent truncation when casting length to u32.
    assert!(
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
    /// KEM ciphertext -- recipient decapsulates to get shared secret
    pub kem_ciphertext: KemCiphertext,
    /// Random nonce (unique per encryption)
    pub nonce: [u8; NONCE_SIZE],
    /// Authenticated ciphertext (XChaCha20-Poly1305 output, includes 16-byte tag)
    pub ciphertext: Vec<u8>,
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
        let mut key = derive_key(&shared_secret, &nonce);

        let padded = pad_plaintext(plaintext);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let xnonce = XNonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(
                xnonce,
                Payload {
                    msg: &padded,
                    aad: &kem_ct.0,
                },
            )
            .ok()?;
        key.zeroize();

        Some(EncryptedPayload {
            kem_ciphertext: kem_ct,
            nonce,
            ciphertext,
        })
    }

    /// Decrypt using the recipient's KEM keypair.
    pub fn decrypt(&self, recipient_kp: &KemKeypair) -> Option<Vec<u8>> {
        let shared_secret = recipient_kp.decapsulate(&self.kem_ciphertext)?;
        let mut key = derive_key(&shared_secret, &self.nonce);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let xnonce = XNonce::from_slice(&self.nonce);
        let padded = cipher
            .decrypt(
                xnonce,
                Payload {
                    msg: &self.ciphertext,
                    aad: &self.kem_ciphertext.0,
                },
            )
            .ok()?;
        key.zeroize();
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
        let mut key = derive_key(shared_secret, &nonce);
        let padded = pad_plaintext(plaintext);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let xnonce = XNonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(
                xnonce,
                Payload {
                    msg: &padded,
                    aad: &kem_ciphertext.0,
                },
            )
            .ok()?;
        key.zeroize();

        Some(EncryptedPayload {
            kem_ciphertext,
            nonce,
            ciphertext,
        })
    }

    /// Decrypt with a pre-established shared secret.
    pub fn decrypt_with_shared_secret(&self, shared_secret: &SharedSecret) -> Option<Vec<u8>> {
        let mut key = derive_key(shared_secret, &self.nonce);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let xnonce = XNonce::from_slice(&self.nonce);
        let padded = cipher
            .decrypt(
                xnonce,
                Payload {
                    msg: &self.ciphertext,
                    aad: &self.kem_ciphertext.0,
                },
            )
            .ok()?;
        key.zeroize();
        unpad_plaintext(&padded)
    }
}

/// Generate a cryptographically random nonce.
fn random_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

/// Derive encryption key from a shared secret and nonce.
///
/// Intermediate buffers containing the shared secret are zeroized before return.
fn derive_key(ss: &SharedSecret, nonce: &[u8; NONCE_SIZE]) -> [u8; 32] {
    let mut input = [0u8; 56]; // 32 + 24
    input[..32].copy_from_slice(&ss.0);
    input[32..].copy_from_slice(nonce);
    let key = crate::hash_domain(b"umbra.encrypt.key", &input);
    input.zeroize();
    key
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
    fn tampered_ciphertext_fails() {
        let kp = KemKeypair::generate();
        let msg = b"integrity test";
        let mut encrypted = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xff;
        }
        assert!(encrypted.decrypt(&kp).is_none());
    }

    #[test]
    fn tampered_nonce_fails() {
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
        let kp = KemKeypair::generate();
        let msg = vec![0xABu8; 32];
        let encrypted = EncryptedPayload::encrypt(&kp.public, &msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_33_bytes_crosses_block_boundary() {
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
    fn tampered_tag_fails() {
        let kp = KemKeypair::generate();
        let msg = b"tag tamper test";
        let mut encrypted = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        // Tag is the last 16 bytes of ciphertext
        let len = encrypted.ciphertext.len();
        if len >= TAG_SIZE {
            encrypted.ciphertext[len - 1] ^= 0xff;
        }
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

    #[test]
    fn encrypt_empty_plaintext() {
        let kp = KemKeypair::generate();
        let encrypted = EncryptedPayload::encrypt(&kp.public, b"").unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_at_max_size_boundary() {
        let kp = KemKeypair::generate();
        let msg = vec![0xABu8; crate::constants::MAX_ENCRYPT_PLAINTEXT];
        let encrypted = EncryptedPayload::encrypt(&kp.public, &msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_over_max_size_returns_none() {
        let kp = KemKeypair::generate();
        let msg = vec![0u8; crate::constants::MAX_ENCRYPT_PLAINTEXT + 1];
        assert!(EncryptedPayload::encrypt(&kp.public, &msg).is_none());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let kp = KemKeypair::generate();
        let msg = b"tamper ciphertext test";
        let mut encrypted = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0x01;
        }
        assert!(encrypted.decrypt(&kp).is_none());
    }

    #[test]
    fn encrypt_various_padding_sizes() {
        let kp = KemKeypair::generate();
        for size in &[0, 1, 32, 60, 63, 64, 65, 128] {
            let msg = vec![0xABu8; *size];
            let encrypted = EncryptedPayload::encrypt(&kp.public, &msg).unwrap();
            let decrypted = encrypted.decrypt(&kp).unwrap();
            assert_eq!(decrypted, msg, "roundtrip failed for size {}", size);
        }
    }

    #[test]
    fn decrypt_tampered_nonce_fails() {
        let kp = KemKeypair::generate();
        let msg = b"tamper nonce test";
        let mut encrypted = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        encrypted.nonce[0] ^= 0x01;
        assert!(encrypted.decrypt(&kp).is_none());
    }

    #[test]
    fn encrypt_shared_secret_roundtrip() {
        let kp = KemKeypair::generate();
        let (ss, ct) = kp.public.encapsulate().unwrap();
        let msg = b"shared secret message";
        let encrypted = EncryptedPayload::encrypt_with_shared_secret(&ss, ct, msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_one_byte_message() {
        let kp = KemKeypair::generate();
        let msg = vec![0xAB];
        let encrypted = EncryptedPayload::encrypt(&kp.public, &msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_exactly_one_block() {
        let kp = KemKeypair::generate();
        let msg = vec![0xCD; 32];
        let encrypted = EncryptedPayload::encrypt(&kp.public, &msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_crosses_block_boundary() {
        let kp = KemKeypair::generate();
        let msg = vec![0xEF; 33];
        let encrypted = EncryptedPayload::encrypt(&kp.public, &msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_large_message() {
        let kp = KemKeypair::generate();
        let msg = vec![0x42; 10_000];
        let encrypted = EncryptedPayload::encrypt(&kp.public, &msg).unwrap();
        let decrypted = encrypted.decrypt(&kp).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn ciphertext_padded_to_bucket_boundary() {
        let kp = KemKeypair::generate();
        // 1 byte plaintext + 4 byte length prefix = 5 bytes, padded to 64, + 16 tag
        let encrypted = EncryptedPayload::encrypt(&kp.public, &[0x01]).unwrap();
        assert_eq!((encrypted.ciphertext.len() - TAG_SIZE) % 64, 0);

        // 60 byte plaintext + 4 = 64, already aligned, + 16 tag
        let encrypted = EncryptedPayload::encrypt(&kp.public, &[0x02; 60]).unwrap();
        assert_eq!((encrypted.ciphertext.len() - TAG_SIZE) % 64, 0);

        // 61 byte plaintext + 4 = 65, padded to 128, + 16 tag
        let encrypted = EncryptedPayload::encrypt(&kp.public, &[0x03; 61]).unwrap();
        assert_eq!((encrypted.ciphertext.len() - TAG_SIZE) % 64, 0);
    }

    #[test]
    fn different_encryptions_produce_different_ciphertexts() {
        let kp = KemKeypair::generate();
        let msg = b"same message";
        let e1 = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        let e2 = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        // Different nonces mean different ciphertexts
        assert_ne!(e1.nonce, e2.nonce);
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    #[test]
    fn decrypt_with_wrong_key_returns_none() {
        let kp1 = KemKeypair::generate();
        let kp2 = KemKeypair::generate();
        let msg = b"secret message";
        let encrypted = EncryptedPayload::encrypt(&kp1.public, msg).unwrap();
        assert!(encrypted.decrypt(&kp2).is_none());
    }

    #[test]
    fn tampered_kem_ciphertext_fails_decrypt() {
        let kp = KemKeypair::generate();
        let msg = b"test message for kem tamper";
        let mut encrypted = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        if !encrypted.kem_ciphertext.0.is_empty() {
            encrypted.kem_ciphertext.0[0] ^= 0xFF;
        }
        assert!(encrypted.decrypt(&kp).is_none());
    }

    #[test]
    fn nonce_uniqueness() {
        let kp = KemKeypair::generate();
        let msg = b"nonce test";
        let nonces: Vec<[u8; NONCE_SIZE]> = (0..10)
            .map(|_| EncryptedPayload::encrypt(&kp.public, msg).unwrap().nonce)
            .collect();
        // All nonces should be unique
        for i in 0..nonces.len() {
            for j in (i + 1)..nonces.len() {
                assert_ne!(nonces[i], nonces[j], "nonce collision at {} and {}", i, j);
            }
        }
    }

    #[test]
    fn decrypt_with_truncated_ciphertext_fails() {
        let kp = KemKeypair::generate();
        let msg = b"truncation test";
        let mut encrypted = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        // Truncate ciphertext to 1 byte (corrupt the auth tag)
        encrypted.ciphertext = vec![0u8];
        assert!(encrypted.decrypt(&kp).is_none());
    }

    #[test]
    fn decrypt_with_empty_ciphertext_fails() {
        let kp = KemKeypair::generate();
        let msg = b"empty ct test";
        let mut encrypted = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        encrypted.ciphertext = vec![];
        assert!(encrypted.decrypt(&kp).is_none());
    }

    #[test]
    fn shared_secret_decrypt_with_wrong_secret_fails() {
        let kp1 = KemKeypair::generate();
        let kp2 = KemKeypair::generate();
        let (ss1, ct1) = kp1.public.encapsulate().unwrap();
        let (ss2, _) = kp2.public.encapsulate().unwrap();
        let msg = b"cross-secret test";
        let encrypted = EncryptedPayload::encrypt_with_shared_secret(&ss1, ct1, msg).unwrap();
        // Decrypt with wrong shared secret
        assert!(encrypted.decrypt_with_shared_secret(&ss2).is_none());
    }

    #[test]
    fn repeated_encrypt_same_plaintext_different_output() {
        let kp = KemKeypair::generate();
        let msg = b"repeat test";
        let e1 = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        let e2 = EncryptedPayload::encrypt(&kp.public, msg).unwrap();
        // Different nonces and ciphertexts
        assert_ne!(e1.nonce, e2.nonce);
        assert_ne!(e1.ciphertext, e2.ciphertext);
        // Both should still decrypt correctly
        assert_eq!(e1.decrypt(&kp).unwrap(), msg);
        assert_eq!(e2.decrypt(&kp).unwrap(), msg);
    }
}
