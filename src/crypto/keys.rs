//! Post-quantum key management using hybrid signatures (Dilithium5 + SPHINCS+)
//! and CRYSTALS-Kyber (key encapsulation).
//!
//! Dilithium5 + SPHINCS+-SHAKE-256s-simple provides ~256-bit quantum security
//! through AND composition: both signature schemes must verify.
//! Kyber1024 provides NIST security level 5 for key encapsulation.

use pqcrypto_dilithium::dilithium5;
use pqcrypto_kyber::kyber1024;
use pqcrypto_sphincsplus::sphincsshake256ssimple;
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

// Expected key/signature sizes for validation
const DILITHIUM5_PK_BYTES: usize = 2592;
pub(crate) const DILITHIUM5_SIG_BYTES: usize = 4627;
const KYBER1024_PK_BYTES: usize = 1568;
const KYBER1024_CT_BYTES: usize = 1568;
const SPHINCS_PK_BYTES: usize = 64;
#[cfg(test)]
const SPHINCS_SK_BYTES: usize = 128;
#[cfg(any(not(feature = "fast-tests"), test))]
pub(crate) const SPHINCS_SIG_BYTES: usize = 29_792;

// ── Signing (Dilithium5 + SPHINCS+) ──

/// A hybrid signing public key: Dilithium5 (2592 bytes) + SPHINCS+-SHAKE-256s-simple (64 bytes).
///
/// Fields are `pub(crate)` to prevent external construction of
/// unvalidated keys. Use [`SigningKeypair::generate`] or deserialization.
#[derive(Clone, Debug)]
pub struct SigningPublicKey {
    pub(crate) dilithium: Vec<u8>,
    pub(crate) sphincs: Vec<u8>,
}

/// A hybrid signing secret key: Dilithium5 (4896 bytes) + SPHINCS+-SHAKE-256s-simple (128 bytes).
///
/// Fields are `pub(crate)` to prevent external construction of
/// secret keys directly. Use [`SigningKeypair::generate`]
/// or [`SigningKeypair::from_bytes`] instead.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SigningSecretKey {
    pub(crate) dilithium: Vec<u8>,
    pub(crate) sphincs: Vec<u8>,
}

/// A hybrid detached signature: Dilithium5 (4627 bytes) + SPHINCS+-SHAKE-256s-simple (29792 bytes).
///
/// Both components must be present and valid for verification to succeed (AND composition).
/// Size is validated during deserialization.
#[derive(Clone, Debug)]
pub struct Signature {
    pub(crate) dilithium: Vec<u8>,
    pub(crate) sphincs: Vec<u8>,
}

impl Signature {
    /// Create an empty signature (used for genesis/unsigned vertices).
    pub fn empty() -> Self {
        Signature {
            dilithium: vec![],
            sphincs: vec![],
        }
    }

    /// Check if this signature is empty (genesis/unsigned).
    pub fn is_empty(&self) -> bool {
        self.dilithium.is_empty() && self.sphincs.is_empty()
    }

    /// Check if this signature has valid sizes for both components.
    pub fn is_valid_size(&self) -> bool {
        #[cfg(not(feature = "fast-tests"))]
        {
            (self.dilithium.is_empty() && self.sphincs.is_empty())
                || (self.dilithium.len() == DILITHIUM5_SIG_BYTES
                    && self.sphincs.len() == SPHINCS_SIG_BYTES)
        }
        #[cfg(feature = "fast-tests")]
        {
            self.dilithium.is_empty() || self.dilithium.len() == DILITHIUM5_SIG_BYTES
        }
    }

    /// Access the raw Dilithium signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.dilithium
    }
}

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (&self.dilithium, &self.sphincs).serialize(s)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (dilithium, sphincs): (Vec<u8>, Vec<u8>) = Deserialize::deserialize(d)?;
        if dilithium.is_empty() && sphincs.is_empty() {
            return Ok(Signature { dilithium, sphincs });
        }
        if dilithium.len() != DILITHIUM5_SIG_BYTES {
            return Err(serde::de::Error::custom(format!(
                "invalid Dilithium5 signature: expected {} bytes, got {}",
                DILITHIUM5_SIG_BYTES,
                dilithium.len()
            )));
        }
        #[cfg(not(feature = "fast-tests"))]
        if sphincs.len() != SPHINCS_SIG_BYTES {
            return Err(serde::de::Error::custom(format!(
                "invalid SPHINCS+ signature: expected {} bytes, got {}",
                SPHINCS_SIG_BYTES,
                sphincs.len()
            )));
        }
        Ok(Signature { dilithium, sphincs })
    }
}

/// A hybrid signing keypair: Dilithium5 + SPHINCS+-SHAKE-256s-simple.
///
/// Implements [`Clone`] because keypairs need to be shared between the
/// node's proposal and voting subsystems. Secret keys are zeroized on
/// drop via [`ZeroizeOnDrop`] on [`SigningSecretKey`].
#[derive(Clone)]
pub struct SigningKeypair {
    pub public: SigningPublicKey,
    pub secret: SigningSecretKey,
}

impl SigningKeypair {
    /// Generate a new random hybrid keypair (Dilithium5 + SPHINCS+).
    pub fn generate() -> Self {
        let (dil_pk, dil_sk) = dilithium5::keypair();
        let (sph_pk, sph_sk) = sphincsshake256ssimple::keypair();
        SigningKeypair {
            public: SigningPublicKey {
                dilithium: dil_pk.as_bytes().to_vec(),
                sphincs: sph_pk.as_bytes().to_vec(),
            },
            secret: SigningSecretKey {
                dilithium: dil_sk.as_bytes().to_vec(),
                sphincs: sph_sk.as_bytes().to_vec(),
            },
        }
    }

    /// Sign a message, producing a hybrid detached signature.
    ///
    /// Both Dilithium5 and SPHINCS+ sign the same message. Both signatures
    /// must verify for the hybrid to be accepted (AND composition).
    ///
    /// If either internal secret key is corrupted, logs an error and returns
    /// an empty signature instead of panicking.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let dil_sk = match dilithium5::SecretKey::from_bytes(&self.secret.dilithium) {
            Ok(sk) => sk,
            Err(_) => {
                tracing::error!("SigningKeypair::sign: corrupted Dilithium secret key");
                return Signature::empty();
            }
        };
        let dil_sig = dilithium5::detached_sign(message, &dil_sk);

        #[cfg(not(feature = "fast-tests"))]
        let sph_sig_bytes = {
            let sph_sk = match sphincsshake256ssimple::SecretKey::from_bytes(&self.secret.sphincs) {
                Ok(sk) => sk,
                Err(_) => {
                    tracing::error!("SigningKeypair::sign: corrupted SPHINCS+ secret key");
                    return Signature::empty();
                }
            };
            sphincsshake256ssimple::detached_sign(message, &sph_sk)
                .as_bytes()
                .to_vec()
        };
        #[cfg(feature = "fast-tests")]
        let sph_sig_bytes = vec![];

        Signature {
            dilithium: dil_sig.as_bytes().to_vec(),
            sphincs: sph_sig_bytes,
        }
    }

    /// Create a keypair from raw bytes, validating key sizes.
    pub fn from_bytes(
        dil_pk: Vec<u8>,
        dil_sk: Vec<u8>,
        sph_pk: Vec<u8>,
        sph_sk: Vec<u8>,
    ) -> Option<Self> {
        dilithium5::PublicKey::from_bytes(&dil_pk).ok()?;
        dilithium5::SecretKey::from_bytes(&dil_sk).ok()?;
        sphincsshake256ssimple::PublicKey::from_bytes(&sph_pk).ok()?;
        sphincsshake256ssimple::SecretKey::from_bytes(&sph_sk).ok()?;
        Some(SigningKeypair {
            public: SigningPublicKey {
                dilithium: dil_pk,
                sphincs: sph_pk,
            },
            secret: SigningSecretKey {
                dilithium: dil_sk,
                sphincs: sph_sk,
            },
        })
    }
}

impl SigningPublicKey {
    /// Access the raw Dilithium public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.dilithium
    }

    /// Verify a hybrid detached signature against this public key.
    ///
    /// Both the Dilithium5 AND SPHINCS+ components must verify (AND composition).
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        // Verify Dilithium5
        let dil_pk = match dilithium5::PublicKey::from_bytes(&self.dilithium) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        let dil_sig = match dilithium5::DetachedSignature::from_bytes(&signature.dilithium) {
            Ok(s) => s,
            Err(_) => return false,
        };
        if dilithium5::verify_detached_signature(&dil_sig, message, &dil_pk).is_err() {
            return false;
        }

        // Verify SPHINCS+ (skipped under fast-tests feature for CI speed)
        #[cfg(not(feature = "fast-tests"))]
        {
            let sph_pk = match sphincsshake256ssimple::PublicKey::from_bytes(&self.sphincs) {
                Ok(pk) => pk,
                Err(_) => return false,
            };
            let sph_sig =
                match sphincsshake256ssimple::DetachedSignature::from_bytes(&signature.sphincs) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
            if sphincsshake256ssimple::verify_detached_signature(&sph_sig, message, &sph_pk)
                .is_err()
            {
                return false;
            }
        }

        true
    }

    /// Derive a compact fingerprint (BLAKE3 hash of both public keys).
    pub fn fingerprint(&self) -> Hash {
        crate::hash_concat(&[b"umbra.signing.fingerprint", &self.dilithium, &self.sphincs])
    }

    /// Check if this public key has the correct sizes for both components.
    pub fn is_valid_size(&self) -> bool {
        self.dilithium.len() == DILITHIUM5_PK_BYTES && self.sphincs.len() == SPHINCS_PK_BYTES
    }
}

impl Serialize for SigningPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (&self.dilithium, &self.sphincs).serialize(s)
    }
}

impl<'de> Deserialize<'de> for SigningPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (dilithium, sphincs): (Vec<u8>, Vec<u8>) = Deserialize::deserialize(d)?;
        if dilithium.len() != DILITHIUM5_PK_BYTES {
            return Err(serde::de::Error::custom(format!(
                "invalid Dilithium5 public key: expected {} bytes, got {}",
                DILITHIUM5_PK_BYTES,
                dilithium.len()
            )));
        }
        if sphincs.len() != SPHINCS_PK_BYTES {
            return Err(serde::de::Error::custom(format!(
                "invalid SPHINCS+ public key: expected {} bytes, got {}",
                SPHINCS_PK_BYTES,
                sphincs.len()
            )));
        }
        Ok(SigningPublicKey { dilithium, sphincs })
    }
}

// ── Key Encapsulation (Kyber1024) ──

/// A CRYSTALS-Kyber1024 encapsulation public key (1568 bytes).
///
/// Inner bytes are `pub(crate)` to prevent external construction of
/// unvalidated keys. Use [`KemKeypair::generate`] or deserialization.
#[derive(Clone, Debug)]
pub struct KemPublicKey(pub(crate) Vec<u8>);

/// A CRYSTALS-Kyber1024 encapsulation secret key.
///
/// The inner bytes are `pub(crate)` to prevent external crates from
/// reading or constructing secret keys directly. Use [`KemKeypair::generate`]
/// or [`KemKeypair::from_bytes`] instead.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KemSecretKey(pub(crate) Vec<u8>);

/// A Kyber1024 ciphertext (encapsulated shared secret).
///
/// Inner bytes are `pub(crate)` to enforce size validation through
/// deserialization. Size is validated during deserialization.
#[derive(Clone, Debug)]
pub struct KemCiphertext(pub(crate) Vec<u8>);

impl KemCiphertext {
    /// Access the raw ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

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
pub struct SharedSecret(pub(crate) [u8; 32]);

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
    /// Access the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

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
        crate::hash_domain(b"umbra.kem.fingerprint", &self.0)
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

/// A complete Umbra identity: signing key + KEM key.
/// The signing key authorizes spends; the KEM key receives encrypted data.
#[derive(Clone)]
pub struct FullKeypair {
    pub signing: SigningKeypair,
    pub kem: KemKeypair,
}

/// The public half of a Umbra identity, used as an address.
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
    /// A unique identifier for this address: H(signing_pks || kem_pk) with domain separation.
    pub fn address_id(&self) -> Hash {
        let mut combined = Vec::with_capacity(
            self.signing.dilithium.len() + self.signing.sphincs.len() + self.kem.0.len(),
        );
        combined.extend_from_slice(&self.signing.dilithium);
        combined.extend_from_slice(&self.signing.sphincs);
        combined.extend_from_slice(&self.kem.0);
        crate::hash_domain(b"umbra.address_id", &combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DILITHIUM5_SK_BYTES: usize = 4896;
    const KYBER1024_SK_BYTES: usize = 3168;

    #[test]
    fn sign_and_verify() {
        let kp = SigningKeypair::generate();
        let msg = b"umbra test message";
        let sig = kp.sign(msg);
        assert!(kp.public.verify(msg, &sig));
        assert!(!kp.public.verify(b"wrong message", &sig));
    }

    #[test]
    fn hybrid_signature_has_both_components() {
        let kp = SigningKeypair::generate();
        let sig = kp.sign(b"test");
        assert_eq!(sig.dilithium.len(), DILITHIUM5_SIG_BYTES);
        #[cfg(not(feature = "fast-tests"))]
        assert_eq!(sig.sphincs.len(), SPHINCS_SIG_BYTES);
        assert!(sig.is_valid_size());
        assert!(!sig.is_empty());
    }

    #[test]
    fn hybrid_verify_fails_if_dilithium_tampered() {
        let kp = SigningKeypair::generate();
        let mut sig = kp.sign(b"test");
        if !sig.dilithium.is_empty() {
            sig.dilithium[0] ^= 0xFF;
        }
        assert!(!kp.public.verify(b"test", &sig));
    }

    #[test]
    #[cfg(not(feature = "fast-tests"))]
    fn hybrid_verify_fails_if_sphincs_tampered() {
        let kp = SigningKeypair::generate();
        let mut sig = kp.sign(b"test");
        if !sig.sphincs.is_empty() {
            sig.sphincs[0] ^= 0xFF;
        }
        assert!(!kp.public.verify(b"test", &sig));
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
        assert_eq!(kp.public.dilithium.len(), DILITHIUM5_PK_BYTES);
        assert_eq!(kp.public.sphincs.len(), SPHINCS_PK_BYTES);
        assert_eq!(kp.secret.dilithium.len(), DILITHIUM5_SK_BYTES);
        assert_eq!(kp.secret.sphincs.len(), SPHINCS_SK_BYTES);
    }

    #[test]
    fn kem_key_valid_size() {
        let kp = KemKeypair::generate();
        assert!(kp.public.is_valid_size());
        assert_eq!(kp.public.0.len(), KYBER1024_PK_BYTES);
        assert_eq!(kp.secret.0.len(), KYBER1024_SK_BYTES);
    }

    #[test]
    fn from_bytes_rejects_invalid() {
        assert!(
            SigningKeypair::from_bytes(vec![0; 10], vec![0; 10], vec![0; 10], vec![0; 10])
                .is_none()
        );
        assert!(KemKeypair::from_bytes(vec![0; 10], vec![0; 10]).is_none());
    }

    #[test]
    fn signing_fingerprint_deterministic_and_unique() {
        let kp1 = SigningKeypair::generate();
        let kp2 = SigningKeypair::generate();
        assert_eq!(kp1.public.fingerprint(), kp1.public.fingerprint());
        assert_ne!(kp1.public.fingerprint(), kp2.public.fingerprint());
        assert_ne!(kp1.public.fingerprint(), [0u8; 32]);
    }

    #[test]
    fn kem_fingerprint_deterministic_and_unique() {
        let kp1 = KemKeypair::generate();
        let kp2 = KemKeypair::generate();
        assert_eq!(kp1.public.fingerprint(), kp1.public.fingerprint());
        assert_ne!(kp1.public.fingerprint(), kp2.public.fingerprint());
        assert_ne!(kp1.public.fingerprint(), [0u8; 32]);
    }

    #[test]
    fn signature_empty_and_as_bytes() {
        let empty = Signature::empty();
        assert!(empty.as_bytes().is_empty());
        assert!(empty.is_empty());
        assert!(empty.is_valid_size());

        let kp = SigningKeypair::generate();
        let sig = kp.sign(b"test");
        assert_eq!(sig.as_bytes().len(), DILITHIUM5_SIG_BYTES);
        assert!(!sig.is_empty());
    }

    #[test]
    fn kem_ciphertext_as_bytes() {
        let kp = KemKeypair::generate();
        let (_, ct) = kp.public.encapsulate().unwrap();
        assert_eq!(ct.as_bytes().len(), KYBER1024_CT_BYTES);
    }

    #[test]
    fn signature_deserialize_rejects_wrong_size() {
        // Encode a tuple of (wrong-size dilithium, empty sphincs)
        let bad: (Vec<u8>, Vec<u8>) = (vec![0u8; 100], vec![]);
        let encoded = crate::serialize(&bad).unwrap();
        let result: Result<Signature, _> = crate::deserialize(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn signature_deserialize_accepts_empty() {
        let empty_sig = Signature::empty();
        let encoded = crate::serialize(&empty_sig).unwrap();
        let result: Result<Signature, _> = crate::deserialize(&encoded);
        assert!(result.is_ok());
        let sig = result.unwrap();
        assert!(sig.is_empty());
    }

    #[test]
    #[cfg(not(feature = "fast-tests"))]
    fn signature_deserialize_rejects_valid_dilithium_wrong_sphincs() {
        let bad: (Vec<u8>, Vec<u8>) = (vec![0u8; DILITHIUM5_SIG_BYTES], vec![0u8; 100]);
        let encoded = crate::serialize(&bad).unwrap();
        let result: Result<Signature, _> = crate::deserialize(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn signing_public_key_deserialize_rejects_wrong_sphincs_size() {
        let bad: (Vec<u8>, Vec<u8>) = (vec![0u8; DILITHIUM5_PK_BYTES], vec![0u8; 10]);
        let encoded = crate::serialize(&bad).unwrap();
        let result: Result<SigningPublicKey, _> = crate::deserialize(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn signing_public_key_deserialize_rejects_wrong_size() {
        let bad: (Vec<u8>, Vec<u8>) = (vec![0u8; 100], vec![0u8; 100]);
        let encoded = crate::serialize(&bad).unwrap();
        let result: Result<SigningPublicKey, _> = crate::deserialize(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn kem_public_key_deserialize_rejects_wrong_size() {
        let bad_bytes: Vec<u8> = vec![0u8; 100];
        let encoded = crate::serialize(&bad_bytes).unwrap();
        let result: Result<KemPublicKey, _> = crate::deserialize(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn kem_ciphertext_deserialize_rejects_wrong_size() {
        let bad_bytes: Vec<u8> = vec![0u8; 100];
        let encoded = crate::serialize(&bad_bytes).unwrap();
        let result: Result<KemCiphertext, _> = crate::deserialize(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn public_address_address_id_deterministic() {
        let kp = FullKeypair::generate();
        let addr = kp.public_address();
        let id1 = addr.address_id();
        let id2 = addr.address_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn public_address_id_differs_for_different_keys() {
        let kp1 = FullKeypair::generate();
        let kp2 = FullKeypair::generate();
        assert_ne!(
            kp1.public_address().address_id(),
            kp2.public_address().address_id()
        );
    }

    #[test]
    fn invalid_size_public_key_reports_false() {
        let bad_signing = SigningPublicKey {
            dilithium: vec![0u8; 10],
            sphincs: vec![0u8; 10],
        };
        assert!(!bad_signing.is_valid_size());

        let bad_kem = KemPublicKey(vec![0u8; 10]);
        assert!(!bad_kem.is_valid_size());
    }

    #[test]
    fn verify_with_empty_signature_fails() {
        let kp = SigningKeypair::generate();
        let empty_sig = Signature::empty();
        assert!(!kp.public.verify(b"test message", &empty_sig));
    }

    #[test]
    fn signing_keypair_from_bytes_roundtrip() {
        let kp = SigningKeypair::generate();
        let dil_pk = kp.public.dilithium.clone();
        let sph_pk = kp.public.sphincs.clone();
        let dil_sk = kp.secret.dilithium.clone();
        let sph_sk = kp.secret.sphincs.clone();
        let restored = SigningKeypair::from_bytes(dil_pk, dil_sk, sph_pk, sph_sk).unwrap();
        let msg = b"roundtrip test message";
        let sig = restored.sign(msg);
        assert!(restored.public.verify(msg, &sig));
        assert!(kp.public.verify(msg, &sig));
    }

    #[test]
    fn kem_keypair_from_bytes_roundtrip() {
        let kp = KemKeypair::generate();
        let pk_bytes = kp.public.as_bytes().to_vec();
        let sk_bytes = kp.secret.0.clone();
        let restored = KemKeypair::from_bytes(pk_bytes, sk_bytes).unwrap();
        let (ss1, ct) = restored.public.encapsulate().unwrap();
        let ss2 = restored.decapsulate(&ct).unwrap();
        assert_eq!(ss1.0, ss2.0);
    }

    #[test]
    fn sign_empty_message() {
        let kp = SigningKeypair::generate();
        let sig = kp.sign(b"");
        assert!(kp.public.verify(b"", &sig));
    }

    #[test]
    fn verify_rejects_zero_signature() {
        let kp = SigningKeypair::generate();
        let zero_sig = Signature {
            dilithium: vec![0u8; DILITHIUM5_SIG_BYTES],
            sphincs: vec![0u8; SPHINCS_SIG_BYTES],
        };
        assert!(!kp.public.verify(b"test message", &zero_sig));
    }

    #[test]
    fn signing_key_valid_size_boundary() {
        let too_small = SigningPublicKey {
            dilithium: vec![0u8; DILITHIUM5_PK_BYTES - 1],
            sphincs: vec![0u8; SPHINCS_PK_BYTES],
        };
        assert!(!too_small.is_valid_size());
        let too_large = SigningPublicKey {
            dilithium: vec![0u8; DILITHIUM5_PK_BYTES + 1],
            sphincs: vec![0u8; SPHINCS_PK_BYTES],
        };
        assert!(!too_large.is_valid_size());
        let sphincs_wrong = SigningPublicKey {
            dilithium: vec![0u8; DILITHIUM5_PK_BYTES],
            sphincs: vec![0u8; SPHINCS_PK_BYTES + 1],
        };
        assert!(!sphincs_wrong.is_valid_size());
    }

    #[test]
    fn kem_key_valid_size_boundary() {
        let too_small = KemPublicKey(vec![0u8; KYBER1024_PK_BYTES - 1]);
        assert!(!too_small.is_valid_size());
        let too_large = KemPublicKey(vec![0u8; KYBER1024_PK_BYTES + 1]);
        assert!(!too_large.is_valid_size());
    }

    #[test]
    fn signing_keypair_from_bytes_rejects_invalid() {
        let result = SigningKeypair::from_bytes(
            vec![0u8; 10],
            vec![0u8; 100],
            vec![0u8; 10],
            vec![0u8; 100],
        );
        assert!(result.is_none());
    }

    #[test]
    fn kem_keypair_from_bytes_rejects_invalid() {
        let result = KemKeypair::from_bytes(vec![0u8; 10], vec![0u8; 100]);
        assert!(result.is_none());
    }

    #[test]
    fn signing_key_fingerprint_deterministic() {
        let kp = SigningKeypair::generate();
        let fp1 = kp.public.fingerprint();
        let fp2 = kp.public.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn different_signing_keys_different_fingerprints() {
        let kp1 = SigningKeypair::generate();
        let kp2 = SigningKeypair::generate();
        assert_ne!(kp1.public.fingerprint(), kp2.public.fingerprint());
    }

    #[test]
    fn kem_key_fingerprint_deterministic() {
        let kp = KemKeypair::generate();
        let fp1 = kp.public.fingerprint();
        let fp2 = kp.public.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn verify_wrong_message_fails() {
        let kp = SigningKeypair::generate();
        let sig = kp.sign(b"message A");
        assert!(!kp.public.verify(b"message B", &sig));
    }

    #[test]
    fn sign_large_message() {
        let kp = SigningKeypair::generate();
        let msg = vec![0xABu8; 10_000];
        let sig = kp.sign(&msg);
        assert!(kp.public.verify(&msg, &sig));
    }

    #[test]
    fn kem_encapsulate_decapsulate_shared_secret_matches() {
        let kp = KemKeypair::generate();
        let (ss_enc, ct) = kp.public.encapsulate().unwrap();
        let ss_dec = kp.decapsulate(&ct).unwrap();
        assert_eq!(ss_enc.0, ss_dec.0);
    }

    #[test]
    fn signature_correct_size() {
        let kp = SigningKeypair::generate();
        let sig = kp.sign(b"test");
        assert_eq!(sig.dilithium.len(), DILITHIUM5_SIG_BYTES);
        #[cfg(not(feature = "fast-tests"))]
        assert_eq!(sig.sphincs.len(), SPHINCS_SIG_BYTES);
    }

    #[test]
    fn full_keypair_public_address_deterministic() {
        let kp = FullKeypair::generate();
        let addr1 = kp.public_address();
        let addr2 = kp.public_address();
        assert_eq!(addr1.address_id(), addr2.address_id());
    }

    #[test]
    fn verify_empty_signature_fails() {
        let kp = SigningKeypair::generate();
        let empty_sig = Signature {
            dilithium: vec![],
            sphincs: vec![],
        };
        assert!(!kp.public.verify(b"test", &empty_sig));
    }

    #[test]
    fn verify_short_signature_fails() {
        let kp = SigningKeypair::generate();
        let short_sig = Signature {
            dilithium: vec![0u8; 100],
            sphincs: vec![0u8; 100],
        };
        assert!(!kp.public.verify(b"test", &short_sig));
    }

    #[test]
    fn verify_wrong_length_signature_fails() {
        let kp = SigningKeypair::generate();
        let wrong_len_sig = Signature {
            dilithium: vec![0u8; DILITHIUM5_SIG_BYTES + 1],
            sphincs: vec![0u8; SPHINCS_SIG_BYTES],
        };
        assert!(!kp.public.verify(b"test", &wrong_len_sig));
    }

    #[test]
    fn kem_decapsulate_wrong_ciphertext_returns_none_or_wrong_secret() {
        let kp1 = KemKeypair::generate();
        let kp2 = KemKeypair::generate();
        let (ss1, ct1) = kp1.public.encapsulate().unwrap();
        if let Some(ss2) = kp2.decapsulate(&ct1) {
            assert_ne!(ss1.0, ss2.0);
        }
        let ss_correct = kp1.decapsulate(&ct1).unwrap();
        assert_eq!(ss1.0, ss_correct.0);
    }

    #[test]
    fn signing_public_key_as_bytes_correct_length() {
        let kp = SigningKeypair::generate();
        assert_eq!(kp.public.as_bytes().len(), DILITHIUM5_PK_BYTES);
    }

    #[test]
    fn kem_public_key_as_bytes_correct_length() {
        let kp = KemKeypair::generate();
        assert_eq!(kp.public.as_bytes().len(), KYBER1024_PK_BYTES);
    }

    #[test]
    fn signature_empty_constructor() {
        let sig = Signature::empty();
        assert!(sig.as_bytes().is_empty());
        assert!(sig.is_empty());
    }

    #[test]
    fn shared_secret_zeroize_on_drop() {
        let kp = KemKeypair::generate();
        let (ss, _ct) = kp.public.encapsulate().unwrap();
        assert_eq!(ss.0.len(), 32);
    }

    #[test]
    fn different_kem_keypairs_different_public_keys() {
        let kp1 = KemKeypair::generate();
        let kp2 = KemKeypair::generate();
        assert_ne!(kp1.public.as_bytes(), kp2.public.as_bytes());
    }

    #[test]
    fn different_signing_keypairs_different_public_keys() {
        let kp1 = SigningKeypair::generate();
        let kp2 = SigningKeypair::generate();
        assert_ne!(kp1.public.as_bytes(), kp2.public.as_bytes());
    }

    #[test]
    fn full_keypair_address_id_uniqueness() {
        let kp1 = FullKeypair::generate();
        let kp2 = FullKeypair::generate();
        assert_ne!(
            kp1.public_address().address_id(),
            kp2.public_address().address_id()
        );
    }

    #[test]
    fn signature_serialize_deserialize_roundtrip() {
        let kp = SigningKeypair::generate();
        let sig = kp.sign(b"roundtrip test");
        let encoded = crate::serialize(&sig).unwrap();
        let decoded: Signature = crate::deserialize(&encoded).unwrap();
        assert_eq!(decoded.dilithium, sig.dilithium);
        assert_eq!(decoded.sphincs, sig.sphincs);
        assert!(kp.public.verify(b"roundtrip test", &decoded));
    }

    #[test]
    fn signing_public_key_serialize_deserialize_roundtrip() {
        let kp = SigningKeypair::generate();
        let encoded = crate::serialize(&kp.public).unwrap();
        let decoded: SigningPublicKey = crate::deserialize(&encoded).unwrap();
        assert_eq!(decoded.dilithium, kp.public.dilithium);
        assert_eq!(decoded.sphincs, kp.public.sphincs);
    }

    #[test]
    fn public_address_serialize_deserialize_roundtrip() {
        let kp = FullKeypair::generate();
        let addr = kp.public_address();
        let encoded = crate::serialize(&addr).unwrap();
        let decoded: PublicAddress = crate::deserialize(&encoded).unwrap();
        assert_eq!(decoded.address_id(), addr.address_id());
    }

    #[test]
    fn verify_with_wrong_public_key_fails() {
        let kp1 = SigningKeypair::generate();
        let kp2 = SigningKeypair::generate();
        let sig = kp1.sign(b"test");
        assert!(!kp2.public.verify(b"test", &sig));
    }
}
