//! Post-quantum key management using CRYSTALS-Dilithium (signatures)
//! and CRYSTALS-Kyber (key encapsulation).
//!
//! Dilithium5 provides NIST security level 5 (~256-bit classical, ~128-bit quantum).
//! Kyber1024 provides NIST security level 5 for key encapsulation.

use pqcrypto_dilithium::dilithium5;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertextTrait, PublicKey as KemPkTrait, SecretKey as KemSkTrait,
    SharedSecret as KemSsTrait,
};
use pqcrypto_traits::sign::{
    DetachedSignature as SigTrait, PublicKey as SignPkTrait, SecretKey as SignSkTrait,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Hash;

// Expected key sizes for validation
const DILITHIUM5_PK_BYTES: usize = 2592;
const _DILITHIUM5_SK_BYTES: usize = 4896;
const DILITHIUM5_SIG_BYTES: usize = 4595;
const KYBER1024_PK_BYTES: usize = 1568;
const _KYBER1024_SK_BYTES: usize = 3168;
const KYBER1024_CT_BYTES: usize = 1568;

// ── Signing (Dilithium5) ──

/// A CRYSTALS-Dilithium5 signing public key (2592 bytes).
#[derive(Clone, Debug)]
pub struct SigningPublicKey(pub Vec<u8>);

/// A CRYSTALS-Dilithium5 signing secret key.
///
/// The inner bytes are `pub(crate)` to prevent external crates from
/// reading or constructing secret keys directly. Use [`SigningKeypair::generate`]
/// or [`SigningKeypair::from_bytes`] instead.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningSecretKey(pub(crate) Vec<u8>);

/// A Dilithium5 detached signature (4595 bytes).
///
/// L6: Size is validated during deserialization to prevent oversized payloads.
#[derive(Clone, Debug)]
pub struct Signature(pub Vec<u8>);

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        // Allow empty signatures (genesis vertex) and valid Dilithium5 signatures.
        // Reject anything larger than expected to prevent memory exhaustion.
        if !bytes.is_empty() && bytes.len() != DILITHIUM5_SIG_BYTES {
            return Err(serde::de::Error::custom(format!(
                "invalid Dilithium5 signature: expected {} bytes, got {}",
                DILITHIUM5_SIG_BYTES,
                bytes.len()
            )));
        }
        Ok(Signature(bytes))
    }
}

/// A Dilithium5 signing keypair.
///
/// Implements [`Clone`] because keypairs need to be shared between the
/// node's proposal and voting subsystems. The secret key is zeroized on
/// drop via [`ZeroizeOnDrop`] on [`SigningSecretKey`].
#[derive(Clone)]
pub struct SigningKeypair {
    pub public: SigningPublicKey,
    pub secret: SigningSecretKey,
}

impl SigningKeypair {
    /// Generate a new random Dilithium5 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = dilithium5::keypair();
        SigningKeypair {
            public: SigningPublicKey(pk.as_bytes().to_vec()),
            secret: SigningSecretKey(sk.as_bytes().to_vec()),
        }
    }

    /// Sign a message, producing a detached signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        // Safety: secret key was validated at construction (generate or from_bytes)
        let sk = dilithium5::SecretKey::from_bytes(&self.secret.0)
            .expect("BUG: SigningKeypair holds invalid secret key");
        let sig = dilithium5::detached_sign(message, &sk);
        Signature(sig.as_bytes().to_vec())
    }

    /// Create a keypair from raw bytes, validating key sizes.
    pub fn from_bytes(public: Vec<u8>, secret: Vec<u8>) -> Option<Self> {
        dilithium5::PublicKey::from_bytes(&public).ok()?;
        dilithium5::SecretKey::from_bytes(&secret).ok()?;
        Some(SigningKeypair {
            public: SigningPublicKey(public),
            secret: SigningSecretKey(secret),
        })
    }
}

impl SigningPublicKey {
    /// Verify a detached signature against this public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let pk = match dilithium5::PublicKey::from_bytes(&self.0) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let sig = match dilithium5::DetachedSignature::from_bytes(&signature.0) {
            Ok(s) => s,
            Err(_) => return false,
        };
        dilithium5::verify_detached_signature(&sig, message, &pk).is_ok()
    }

    /// Derive a compact fingerprint (BLAKE3 hash of the public key).
    pub fn fingerprint(&self) -> Hash {
        crate::hash_domain(b"spectra.signing.fingerprint", &self.0)
    }

    /// Check if this public key has the correct size.
    pub fn is_valid_size(&self) -> bool {
        self.0.len() == DILITHIUM5_PK_BYTES
    }
}

impl Serialize for SigningPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for SigningPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        // Validate key size on deserialization to prevent malformed keys
        if bytes.len() != DILITHIUM5_PK_BYTES {
            return Err(serde::de::Error::custom(format!(
                "invalid Dilithium5 public key: expected {} bytes, got {}",
                DILITHIUM5_PK_BYTES,
                bytes.len()
            )));
        }
        Ok(SigningPublicKey(bytes))
    }
}

// ── Key Encapsulation (Kyber1024) ──

/// A CRYSTALS-Kyber1024 encapsulation public key (1568 bytes).
#[derive(Clone, Debug)]
pub struct KemPublicKey(pub Vec<u8>);

/// A CRYSTALS-Kyber1024 encapsulation secret key.
///
/// The inner bytes are `pub(crate)` to prevent external crates from
/// reading or constructing secret keys directly. Use [`KemKeypair::generate`]
/// or [`KemKeypair::from_bytes`] instead.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KemSecretKey(pub(crate) Vec<u8>);

/// A Kyber1024 ciphertext (encapsulated shared secret).
///
/// L5: Size is validated during deserialization to prevent oversized payloads.
#[derive(Clone, Debug)]
pub struct KemCiphertext(pub Vec<u8>);

impl Serialize for KemCiphertext {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for KemCiphertext {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        if bytes.len() != KYBER1024_CT_BYTES {
            return Err(serde::de::Error::custom(format!(
                "invalid Kyber1024 ciphertext: expected {} bytes, got {}",
                KYBER1024_CT_BYTES,
                bytes.len()
            )));
        }
        Ok(KemCiphertext(bytes))
    }
}

/// The shared secret produced by Kyber KEM (32 bytes).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(pub [u8; 32]);

/// A Kyber1024 KEM keypair.
///
/// Implements [`Clone`] for the same reasons as [`SigningKeypair`]; the
/// secret key is zeroized on drop.
#[derive(Clone)]
pub struct KemKeypair {
    pub public: KemPublicKey,
    pub secret: KemSecretKey,
}

impl KemKeypair {
    /// Generate a new random Kyber1024 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = kyber1024::keypair();
        KemKeypair {
            public: KemPublicKey(pk.as_bytes().to_vec()),
            secret: KemSecretKey(sk.as_bytes().to_vec()),
        }
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> Option<SharedSecret> {
        let sk = kyber1024::SecretKey::from_bytes(&self.secret.0).ok()?;
        let ct = kyber1024::Ciphertext::from_bytes(&ciphertext.0).ok()?;
        let ss = kyber1024::decapsulate(&ct, &sk);
        let bytes = ss.as_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Some(SharedSecret(arr))
    }

    /// Create a keypair from raw bytes, validating key sizes.
    pub fn from_bytes(public: Vec<u8>, secret: Vec<u8>) -> Option<Self> {
        kyber1024::PublicKey::from_bytes(&public).ok()?;
        kyber1024::SecretKey::from_bytes(&secret).ok()?;
        Some(KemKeypair {
            public: KemPublicKey(public),
            secret: KemSecretKey(secret),
        })
    }
}

impl KemPublicKey {
    /// Encapsulate: generate a shared secret and its ciphertext.
    /// Only the holder of the corresponding secret key can decapsulate.
    pub fn encapsulate(&self) -> Option<(SharedSecret, KemCiphertext)> {
        let pk = kyber1024::PublicKey::from_bytes(&self.0).ok()?;
        let (ss, ct) = kyber1024::encapsulate(&pk);
        let bytes = ss.as_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Some((SharedSecret(arr), KemCiphertext(ct.as_bytes().to_vec())))
    }

    /// Derive a compact fingerprint (BLAKE3 hash of the public key).
    pub fn fingerprint(&self) -> Hash {
        crate::hash_domain(b"spectra.kem.fingerprint", &self.0)
    }

    /// Check if this public key has the correct size.
    pub fn is_valid_size(&self) -> bool {
        self.0.len() == KYBER1024_PK_BYTES
    }
}

impl Serialize for KemPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for KemPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(d)?;
        // Validate key size on deserialization to prevent malformed keys
        if bytes.len() != KYBER1024_PK_BYTES {
            return Err(serde::de::Error::custom(format!(
                "invalid Kyber1024 public key: expected {} bytes, got {}",
                KYBER1024_PK_BYTES,
                bytes.len()
            )));
        }
        Ok(KemPublicKey(bytes))
    }
}

// ── Full Identity ──

/// A complete Spectra identity: signing key + KEM key.
/// The signing key authorizes spends; the KEM key receives encrypted data.
#[derive(Clone)]
pub struct FullKeypair {
    pub signing: SigningKeypair,
    pub kem: KemKeypair,
}

/// The public half of a Spectra identity, used as an address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicAddress {
    pub signing: SigningPublicKey,
    pub kem: KemPublicKey,
}

impl FullKeypair {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        FullKeypair {
            signing: SigningKeypair::generate(),
            kem: KemKeypair::generate(),
        }
    }

    /// Extract the public address.
    pub fn public_address(&self) -> PublicAddress {
        PublicAddress {
            signing: self.signing.public.clone(),
            kem: self.kem.public.clone(),
        }
    }
}

impl PublicAddress {
    /// A unique identifier for this address: H(signing_pk || kem_pk) with domain separation.
    pub fn address_id(&self) -> Hash {
        let mut combined = Vec::with_capacity(self.signing.0.len() + self.kem.0.len());
        combined.extend_from_slice(&self.signing.0);
        combined.extend_from_slice(&self.kem.0);
        crate::hash_domain(b"spectra.address_id", &combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let kp = SigningKeypair::generate();
        let msg = b"spectra test message";
        let sig = kp.sign(msg);
        assert!(kp.public.verify(msg, &sig));
        assert!(!kp.public.verify(b"wrong message", &sig));
    }

    #[test]
    fn kem_encapsulate_decapsulate() {
        let kp = KemKeypair::generate();
        let (ss1, ct) = kp.public.encapsulate().unwrap();
        let ss2 = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss1.0, ss2.0);
    }

    #[test]
    fn full_keypair_address() {
        let kp = FullKeypair::generate();
        let addr = kp.public_address();
        let id = addr.address_id();
        assert_ne!(id, [0u8; 32]);
    }

    #[test]
    fn signing_key_valid_size() {
        let kp = SigningKeypair::generate();
        assert!(kp.public.is_valid_size());
        assert_eq!(kp.public.0.len(), DILITHIUM5_PK_BYTES);
        assert_eq!(kp.secret.0.len(), _DILITHIUM5_SK_BYTES);
    }

    #[test]
    fn kem_key_valid_size() {
        let kp = KemKeypair::generate();
        assert!(kp.public.is_valid_size());
        assert_eq!(kp.public.0.len(), KYBER1024_PK_BYTES);
        assert_eq!(kp.secret.0.len(), _KYBER1024_SK_BYTES);
    }

    #[test]
    fn from_bytes_rejects_invalid() {
        assert!(SigningKeypair::from_bytes(vec![0; 10], vec![0; 10]).is_none());
        assert!(KemKeypair::from_bytes(vec![0; 10], vec![0; 10]).is_none());
    }
}
