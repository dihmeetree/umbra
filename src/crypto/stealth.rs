//! Stealth addresses for receiver privacy.
//!
//! When Alice sends to Bob, she doesn't send to Bob's public address directly.
//! Instead, she derives a unique one-time stealth address for each transaction
//! output. Only Bob can detect and spend outputs sent to him.
//!
//! Protocol (Kyber-based):
//! 1. Alice encapsulates against Bob's KEM public key → (shared_secret, ciphertext)
//! 2. Alice derives: one_time_key = H("stealth" || shared_secret || output_index)
//! 3. The output is "addressed" to this one_time_key
//! 4. Bob scans outputs by decapsulating the ciphertext and re-deriving the key
//! 5. Bob can spend using knowledge of shared_secret + his signing key

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::keys::{KemCiphertext, KemKeypair, KemPublicKey};
use crate::Hash;

/// A one-time stealth address attached to a transaction output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthAddress {
    /// The one-time public identifier for this output
    pub one_time_key: Hash,
    /// The KEM ciphertext needed for the recipient to derive the shared secret
    pub kem_ciphertext: KemCiphertext,
}

/// Data the recipient needs to spend an output sent to a stealth address.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StealthSpendInfo {
    /// The shared secret derived from KEM decapsulation
    pub shared_secret: [u8; 32],
    /// The derived one-time spending key
    pub one_time_key: Hash,
}

/// Result of stealth address generation, including the shared secret
/// so it can be reused for encrypting note data (avoiding a second KEM).
pub struct StealthGenResult {
    pub address: StealthAddress,
    pub shared_secret: super::keys::SharedSecret,
}

impl StealthAddress {
    /// Generate a stealth address for a recipient.
    ///
    /// Returns the address and the KEM shared secret, which callers should
    /// reuse for encrypting note data (via `encrypt_with_shared_secret`)
    /// instead of performing a second KEM encapsulation.
    ///
    /// `recipient_kem_pk`: the recipient's KEM public key
    /// `output_index`: the index of this output within the transaction
    pub fn generate(
        recipient_kem_pk: &KemPublicKey,
        output_index: u32,
    ) -> Option<StealthGenResult> {
        let (shared_secret, ciphertext) = recipient_kem_pk.encapsulate()?;
        let one_time_key = derive_one_time_key(&shared_secret.0, output_index);
        Some(StealthGenResult {
            address: StealthAddress {
                one_time_key,
                kem_ciphertext: ciphertext,
            },
            shared_secret,
        })
    }

    /// Try to detect if this stealth address belongs to us.
    /// Returns the spend info if it does.
    ///
    /// Always iterates all candidate indices to avoid leaking which index
    /// matched via timing side-channels.
    pub fn try_detect(&self, our_kem_kp: &KemKeypair) -> Option<StealthSpendInfo> {
        let shared_secret = match our_kem_kp.decapsulate(&self.kem_ciphertext) {
            Some(ss) => ss,
            None => {
                // Perform dummy iteration to equalize timing with the success
                // path (defense-in-depth against malformed ciphertexts that
                // bypass Kyber's implicit rejection).
                let dummy = [0u8; 32];
                for idx in 0..crate::constants::MAX_TX_IO as u32 {
                    let _ = derive_one_time_key(&dummy, idx);
                }
                return None;
            }
        };
        let mut result: Option<StealthSpendInfo> = None;
        // Try output indices 0..MAX_TX_IO; do NOT return early to prevent
        // timing leaks that reveal which output index matched.
        for idx in 0..crate::constants::MAX_TX_IO as u32 {
            let derived = derive_one_time_key(&shared_secret.0, idx);
            if crate::constant_time_eq(&derived, &self.one_time_key) {
                result = Some(StealthSpendInfo {
                    shared_secret: shared_secret.0,
                    one_time_key: derived,
                });
            }
        }
        result
    }

    /// Detect with a known output index (faster than scanning).
    pub fn try_detect_at_index(
        &self,
        our_kem_kp: &KemKeypair,
        output_index: u32,
    ) -> Option<StealthSpendInfo> {
        let shared_secret = match our_kem_kp.decapsulate(&self.kem_ciphertext) {
            Some(ss) => ss,
            None => {
                // Dummy derivation + comparison to equalize timing
                let dummy = [0u8; 32];
                let derived = derive_one_time_key(&dummy, output_index);
                let _ = crate::constant_time_eq(&derived, &self.one_time_key);
                return None;
            }
        };
        let derived = derive_one_time_key(&shared_secret.0, output_index);
        if crate::constant_time_eq(&derived, &self.one_time_key) {
            Some(StealthSpendInfo {
                shared_secret: shared_secret.0,
                one_time_key: derived,
            })
        } else {
            None
        }
    }
}

/// Derive the one-time key from a shared secret and output index.
///
/// Uses `hash_domain` (BLAKE3 `new_derive_key`) for proper domain separation.
/// Inputs are fixed-length (32 + 4 bytes), so concatenation is unambiguous.
fn derive_one_time_key(shared_secret: &[u8; 32], output_index: u32) -> Hash {
    let mut data = [0u8; 36];
    data[..32].copy_from_slice(shared_secret);
    data[32..].copy_from_slice(&output_index.to_le_bytes());
    crate::hash_domain(b"umbra.stealth.one_time_key", &data)
}

/// Derive the spending authorization key from shared secret + owner's signing key
/// fingerprint + output index.
///
/// The output_index ensures each output produces a unique spend_auth, preventing
/// linkability across outputs sent to the same recipient. Without this, an observer
/// who compromises one spend_auth could link all outputs sharing the same
/// (shared_secret, fingerprint) pair.
///
/// Uses `hash_domain` (BLAKE3 `new_derive_key`) for proper domain separation.
/// Inputs are fixed-length (32 + 32 + 4 bytes), so concatenation is unambiguous.
pub fn derive_spend_auth(
    shared_secret: &[u8; 32],
    signing_key_fingerprint: &Hash,
    output_index: u32,
) -> Hash {
    let mut data = [0u8; 68];
    data[..32].copy_from_slice(shared_secret);
    data[32..64].copy_from_slice(signing_key_fingerprint);
    data[64..68].copy_from_slice(&output_index.to_le_bytes());
    crate::hash_domain(b"umbra.stealth.spend_auth", &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KemKeypair;

    #[test]
    fn stealth_address_roundtrip() {
        let recipient = KemKeypair::generate();
        let result = StealthAddress::generate(&recipient.public, 0).unwrap();
        let info = result.address.try_detect_at_index(&recipient, 0).unwrap();
        assert_eq!(info.one_time_key, result.address.one_time_key);
    }

    #[test]
    fn stealth_address_wrong_recipient() {
        let recipient = KemKeypair::generate();
        let wrong = KemKeypair::generate();
        let result = StealthAddress::generate(&recipient.public, 0).unwrap();
        assert!(result.address.try_detect_at_index(&wrong, 0).is_none());
    }

    #[test]
    fn try_detect_scans_all_indices() {
        let recipient = KemKeypair::generate();
        // Generate at index 3
        let result = StealthAddress::generate(&recipient.public, 3).unwrap();
        // try_detect (no index hint) should still find it
        let info = result.address.try_detect(&recipient).unwrap();
        assert_eq!(info.one_time_key, result.address.one_time_key);
    }

    #[test]
    fn derive_spend_auth_deterministic() {
        let secret = [42u8; 32];
        let fingerprint = crate::hash_domain(b"test", b"fp");
        let a = derive_spend_auth(&secret, &fingerprint, 0);
        let b = derive_spend_auth(&secret, &fingerprint, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_spend_auth_differs_by_key() {
        let secret = [42u8; 32];
        let fp1 = crate::hash_domain(b"test", b"key1");
        let fp2 = crate::hash_domain(b"test", b"key2");
        assert_ne!(
            derive_spend_auth(&secret, &fp1, 0),
            derive_spend_auth(&secret, &fp2, 0)
        );
    }

    #[test]
    fn derive_spend_auth_differs_by_index() {
        let secret = [42u8; 32];
        let fp = crate::hash_domain(b"test", b"key");
        assert_ne!(
            derive_spend_auth(&secret, &fp, 0),
            derive_spend_auth(&secret, &fp, 1)
        );
    }

    #[test]
    fn stealth_different_indices_different_keys() {
        let recipient = KemKeypair::generate();
        let r0 = StealthAddress::generate(&recipient.public, 0).unwrap();
        let r1 = StealthAddress::generate(&recipient.public, 1).unwrap();
        // Different indices must produce different one_time_keys
        // (they also use different KEM encapsulations, so different ciphertexts)
        assert_ne!(r0.address.one_time_key, r1.address.one_time_key);
    }

    #[test]
    fn stealth_derive_spend_auth_different_indices() {
        let secret = [42u8; 32];
        let fingerprint = crate::hash_domain(b"test", b"fp");
        let auth0 = derive_spend_auth(&secret, &fingerprint, 0);
        let auth1 = derive_spend_auth(&secret, &fingerprint, 1);
        assert_ne!(auth0, auth1);
    }

    #[test]
    fn stealth_try_detect_wrong_key_constant_time() {
        let recipient_a = KemKeypair::generate();
        let recipient_b = KemKeypair::generate();
        let result = StealthAddress::generate(&recipient_a.public, 0).unwrap();
        // Detecting with the wrong key should return None
        assert!(result.address.try_detect(&recipient_b).is_none());
    }

    #[test]
    fn derive_spend_auth_differs_by_secret() {
        let fp = crate::hash_domain(b"test", b"fp");
        let auth1 = derive_spend_auth(&[1u8; 32], &fp, 0);
        let auth2 = derive_spend_auth(&[2u8; 32], &fp, 0);
        assert_ne!(auth1, auth2);
    }

    #[test]
    fn stealth_address_wrong_index_fails_detection() {
        let recipient = KemKeypair::generate();
        let result = StealthAddress::generate(&recipient.public, 0).unwrap();
        // Trying to detect at a different index should fail
        assert!(result.address.try_detect_at_index(&recipient, 1).is_none());
        assert!(result.address.try_detect_at_index(&recipient, 99).is_none());
    }

    #[test]
    fn stealth_address_shared_secret_consistent() {
        let recipient = KemKeypair::generate();
        let result = StealthAddress::generate(&recipient.public, 0).unwrap();
        let info = result.address.try_detect_at_index(&recipient, 0).unwrap();
        // shared_secret should be the same as the one used for generation
        assert_eq!(info.shared_secret, result.shared_secret.0);
    }

    #[test]
    fn stealth_address_multiple_outputs_same_recipient() {
        let recipient = KemKeypair::generate();
        // Generate multiple stealth addresses for the same recipient
        let r0 = StealthAddress::generate(&recipient.public, 0).unwrap();
        let r1 = StealthAddress::generate(&recipient.public, 1).unwrap();
        let r2 = StealthAddress::generate(&recipient.public, 2).unwrap();

        // All should be detectable
        assert!(r0.address.try_detect(&recipient).is_some());
        assert!(r1.address.try_detect(&recipient).is_some());
        assert!(r2.address.try_detect(&recipient).is_some());

        // All should have different one-time keys
        assert_ne!(r0.address.one_time_key, r1.address.one_time_key);
        assert_ne!(r1.address.one_time_key, r2.address.one_time_key);

        // All should have different KEM ciphertexts
        assert_ne!(r0.address.kem_ciphertext.0, r1.address.kem_ciphertext.0);
    }

    #[test]
    fn stealth_try_detect_at_max_tx_io_minus_one() {
        let recipient = KemKeypair::generate();
        let max_idx = crate::constants::MAX_TX_IO as u32 - 1;
        let result = StealthAddress::generate(&recipient.public, max_idx).unwrap();
        // try_detect scans 0..MAX_TX_IO so max_idx should be found
        let info = result.address.try_detect(&recipient).unwrap();
        assert_eq!(info.one_time_key, result.address.one_time_key);
    }

    #[test]
    fn stealth_try_detect_at_index_beyond_max_fails_scan() {
        let recipient = KemKeypair::generate();
        // Generate at index MAX_TX_IO (out of scan range 0..MAX_TX_IO)
        let out_of_range_idx = crate::constants::MAX_TX_IO as u32;
        let result = StealthAddress::generate(&recipient.public, out_of_range_idx).unwrap();
        // try_detect only scans 0..MAX_TX_IO, so it should NOT find index MAX_TX_IO
        assert!(result.address.try_detect(&recipient).is_none());
        // But try_detect_at_index with the exact index should work
        assert!(result
            .address
            .try_detect_at_index(&recipient, out_of_range_idx)
            .is_some());
    }

    #[test]
    fn derive_spend_auth_all_zero_inputs_nonzero() {
        let secret = [0u8; 32];
        let fp = [0u8; 32];
        let auth = derive_spend_auth(&secret, &fp, 0);
        assert_ne!(auth, [0u8; 32]);
    }

    #[test]
    fn stealth_generate_different_recipients_different_keys() {
        let r1 = KemKeypair::generate();
        let r2 = KemKeypair::generate();
        let s1 = StealthAddress::generate(&r1.public, 0).unwrap();
        let s2 = StealthAddress::generate(&r2.public, 0).unwrap();
        // Different recipients should produce different one-time keys
        assert_ne!(s1.address.one_time_key, s2.address.one_time_key);
    }
}
