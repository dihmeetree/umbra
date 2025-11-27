// JubJub curve signing for Midnight/Compact compatibility
//
// This module implements Schnorr signatures on the JubJub curve that are compatible
// with the Crypto.compact verification circuit.

use group::Group;
use jubjub::{AffinePoint, ExtendedPoint, Fr, SubgroupPoint};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

/// JubJub signature compatible with Compact's Crypto module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JubJubSignature {
    /// r point x-coordinate (32 bytes as hex)
    pub r_x: String,
    /// r point y-coordinate (32 bytes as hex)
    pub r_y: String,
    /// s scalar (32 bytes as hex)
    pub s: String,
    /// Public key x-coordinate (32 bytes as hex)
    pub pk_x: String,
    /// Public key y-coordinate (32 bytes as hex)
    pub pk_y: String,
}

/// JubJub signing key
pub struct JubJubSigningKey {
    sk: Fr,
    pk: SubgroupPoint,
}

impl JubJubSigningKey {
    /// Create a new signing key from 32 bytes
    /// The bytes are interpreted as a scalar mod r (JubJub scalar field order)
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        // Convert bytes to scalar - we hash to ensure it's in range
        let sk = bytes_to_scalar(bytes);
        let pk = SubgroupPoint::generator() * sk;
        Self { sk, pk }
    }

    /// Get the public key as (u, v) coordinates (JubJub uses u,v not x,y)
    pub fn public_key(&self) -> (jubjub::Fq, jubjub::Fq) {
        let extended: ExtendedPoint = self.pk.into();
        let affine: AffinePoint = extended.into();
        (affine.get_u(), affine.get_v())
    }

    /// Sign data using the Schnorr scheme compatible with Compact's Crypto module
    ///
    /// Note: This is a simplified version that uses raw SHA256 for hashing.
    /// For production use with Compact contracts, use `sign_with_persistent_hash` instead.
    ///
    /// The signing process:
    /// 1. credentialHash = SHA256(data)
    /// 2. k = SHA256(SHA256(sk) || credentialHash) as scalar
    /// 3. r = k * G
    /// 4. challengeInput = r.x || r.y || pk.x || pk.y || credentialHash
    /// 5. c = SHA256(challengeInput) as scalar
    /// 6. s = k + c * sk
    pub fn sign(&self, data: &[u8]) -> JubJubSignature {
        // Step 1: Hash the credential data (matches persistentHash<T>)
        let credential_hash = Sha256::digest(data);

        // Step 2: Compute deterministic k
        // k = SHA256(SHA256(sk) || credentialHash)
        let sk_hash = Sha256::digest(scalar_to_bytes_le(&self.sk));
        let mut k_input = Vec::new();
        k_input.extend_from_slice(&sk_hash);
        k_input.extend_from_slice(&credential_hash);
        let k_hash = Sha256::digest(&k_input);
        let k = bytes_to_scalar(k_hash.as_slice().try_into().unwrap());

        // Step 3: Compute r = k * G
        let r_point = SubgroupPoint::generator() * k;
        let r_extended: ExtendedPoint = r_point.into();
        let r_affine: AffinePoint = r_extended.into();
        let r_u = r_affine.get_u();
        let r_v = r_affine.get_v();

        // Step 4: Get public key coordinates
        let (pk_u, pk_v) = self.public_key();

        // Step 5: Compute challenge (using little-endian for internal consistency)
        // challengeInput = { r_u, r_v, pk_u, pk_v, credentialHash }
        // c = SHA256(challengeInput)
        let mut challenge_input = Vec::new();
        challenge_input.extend_from_slice(&fq_to_bytes_le(&r_u));
        challenge_input.extend_from_slice(&fq_to_bytes_le(&r_v));
        challenge_input.extend_from_slice(&fq_to_bytes_le(&pk_u));
        challenge_input.extend_from_slice(&fq_to_bytes_le(&pk_v));
        challenge_input.extend_from_slice(&credential_hash);

        let c_hash = Sha256::digest(&challenge_input);
        let c = bytes_to_scalar(c_hash.as_slice().try_into().unwrap());

        // Step 6: Compute s = k + c * sk
        let s = k + (c * self.sk);

        // Output as big-endian hex for JSON/JS BigInt parsing
        JubJubSignature {
            r_x: hex::encode(fq_to_bytes_be(&r_u)),
            r_y: hex::encode(fq_to_bytes_be(&r_v)),
            s: hex::encode(scalar_to_bytes_be(&s)),
            pk_x: hex::encode(fq_to_bytes_be(&pk_u)),
            pk_y: hex::encode(fq_to_bytes_be(&pk_v)),
        }
    }

    /// Sign using precomputed hashes from Compact's persistentHash
    ///
    /// This method is used when the credential hash and challenge hash are computed
    /// externally using the Midnight onchain-runtime's persistentHash function.
    ///
    /// Parameters:
    /// - credential_hash: persistentHash<Bytes<512>>(data) - 32 bytes
    /// - compute_challenge_hash: A closure that computes persistentHash<ChallengeInput>
    ///   given (r_x, r_y, pk_x, pk_y, credential_hash) - all in little-endian
    pub fn sign_with_persistent_hash<F>(
        &self,
        credential_hash: &[u8; 32],
        compute_challenge_hash: F,
    ) -> JubJubSignature
    where
        F: FnOnce(&[u8; 32], &[u8; 32], &[u8; 32], &[u8; 32], &[u8; 32]) -> [u8; 32],
    {
        // Step 2: Compute deterministic k
        // k = SHA256(SHA256(sk) || credentialHash)
        let sk_hash = Sha256::digest(scalar_to_bytes_le(&self.sk));
        let mut k_input = Vec::new();
        k_input.extend_from_slice(&sk_hash);
        k_input.extend_from_slice(credential_hash);
        let k_hash = Sha256::digest(&k_input);
        let k = bytes_to_scalar(k_hash.as_slice().try_into().unwrap());

        // Step 3: Compute r = k * G
        let r_point = SubgroupPoint::generator() * k;
        let r_extended: ExtendedPoint = r_point.into();
        let r_affine: AffinePoint = r_extended.into();
        let r_u = r_affine.get_u();
        let r_v = r_affine.get_v();

        // Step 4: Get public key coordinates
        let (pk_u, pk_v) = self.public_key();

        // Get coordinate bytes for challenge computation (little-endian for persistentHash)
        let r_x_bytes_le = fq_to_bytes_le(&r_u);
        let r_y_bytes_le = fq_to_bytes_le(&r_v);
        let pk_x_bytes_le = fq_to_bytes_le(&pk_u);
        let pk_y_bytes_le = fq_to_bytes_le(&pk_v);

        // Step 5: Compute challenge using persistentHash<ChallengeInput>
        let c_hash = compute_challenge_hash(
            &r_x_bytes_le,
            &r_y_bytes_le,
            &pk_x_bytes_le,
            &pk_y_bytes_le,
            credential_hash,
        );

        // Convert challenge hash to scalar using degradeToTransient logic
        // In Compact: degradeToTransient converts Bytes<32> to Field
        let c = bytes_to_scalar(&c_hash);

        // Step 6: Compute s = k + c * sk
        let s = k + (c * self.sk);

        // Output as big-endian hex for JSON/JS BigInt parsing
        JubJubSignature {
            r_x: hex::encode(fq_to_bytes_be(&r_u)),
            r_y: hex::encode(fq_to_bytes_be(&r_v)),
            s: hex::encode(scalar_to_bytes_be(&s)),
            pk_x: hex::encode(fq_to_bytes_be(&pk_u)),
            pk_y: hex::encode(fq_to_bytes_be(&pk_v)),
        }
    }
}

/// Convert bytes (little-endian) to JubJub scalar
///
/// IMPORTANT: This matches Compact's `degradeToTransient` behavior which only uses
/// the first 31 bytes of a 32-byte hash. The JubJub scalar field is ~252 bits,
/// so 31 bytes (248 bits) always fits without rejection or reduction.
///
/// Compact's field_repr for [u8; 32] splits into two field elements:
/// - field_vec[0] = byte 31 (last byte)
/// - field_vec[1] = bytes 0-30 (first 31 bytes)
/// Then degradeToTransient returns field_vec[1], effectively discarding byte 31.
fn bytes_to_scalar(bytes: &[u8; 32]) -> Fr {
    // Match Compact's degradeToTransient: only use first 31 bytes
    // This ensures the notary's challenge computation matches the contract's
    let mut truncated = [0u8; 32];
    truncated[..31].copy_from_slice(&bytes[..31]);
    // 31 bytes (248 bits) always fits in the ~252-bit JubJub scalar field
    Fr::from_bytes(&truncated).expect("31 bytes always fits in JubJub Fr")
}

/// Convert JubJub scalar (Fr) to bytes for persistentHash (little-endian)
fn scalar_to_bytes_le(scalar: &Fr) -> [u8; 32] {
    scalar.to_bytes() // JubJub Fr::to_bytes() returns little-endian
}

/// Convert JubJub scalar (Fr) to bytes for hex output (big-endian)
/// The hex representation is used in JSON and needs to be big-endian for JS BigInt parsing
fn scalar_to_bytes_be(scalar: &Fr) -> [u8; 32] {
    let mut bytes = scalar.to_bytes();
    bytes.reverse(); // Convert little-endian to big-endian
    bytes
}

/// Convert JubJub base field element (Fq) to bytes for persistentHash (little-endian)
fn fq_to_bytes_le(fq: &jubjub::Fq) -> [u8; 32] {
    fq.to_bytes() // JubJub Fq::to_bytes() returns little-endian
}

/// Convert JubJub base field element (Fq) to bytes for hex output (big-endian)
/// The hex representation is used in JSON and needs to be big-endian for JS BigInt parsing
fn fq_to_bytes_be(fq: &jubjub::Fq) -> [u8; 32] {
    let mut bytes = fq.to_bytes();
    bytes.reverse(); // Convert little-endian to big-endian
    bytes
}

/// Convert bytes (big-endian from hex decode) to JubJub base field element (Fq)
#[cfg(test)]
fn bytes_be_to_fq(bytes: &[u8; 32]) -> jubjub::Fq {
    // Fq::from_bytes expects little-endian, so reverse big-endian input
    let mut le_bytes = *bytes;
    le_bytes.reverse();
    jubjub::Fq::from_bytes(&le_bytes).unwrap_or(jubjub::Fq::zero())
}

/// Convert bytes (big-endian from hex decode) to JubJub scalar (Fr)
#[cfg(test)]
fn bytes_be_to_scalar(bytes: &[u8; 32]) -> Fr {
    // Fr::from_bytes expects little-endian, so reverse big-endian input
    let mut le_bytes = *bytes;
    le_bytes.reverse();
    Fr::from_bytes(&le_bytes).unwrap_or(Fr::zero())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        // Create a signing key
        let key_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = JubJubSigningKey::from_bytes(&key_bytes);

        // Sign some data
        let data = b"Test data for signing";
        let signature = signing_key.sign(data);

        // Print signature for inspection
        println!("Signature: {:?}", signature);

        // Verify the signature manually
        // s * G == r + c * pk
        // Note: signature hex values are big-endian, so use bytes_be_to_* functions
        let s = bytes_be_to_scalar(&hex::decode(&signature.s).unwrap().try_into().unwrap());
        let r_u = bytes_be_to_fq(&hex::decode(&signature.r_x).unwrap().try_into().unwrap());
        let r_v = bytes_be_to_fq(&hex::decode(&signature.r_y).unwrap().try_into().unwrap());
        let pk_u = bytes_be_to_fq(&hex::decode(&signature.pk_x).unwrap().try_into().unwrap());
        let pk_v = bytes_be_to_fq(&hex::decode(&signature.pk_y).unwrap().try_into().unwrap());

        // Reconstruct r point from affine coordinates
        let r_affine = AffinePoint::from_raw_unchecked(r_u, r_v);
        let r_point: ExtendedPoint = r_affine.into();

        // Reconstruct pk point from affine coordinates
        let pk_affine = AffinePoint::from_raw_unchecked(pk_u, pk_v);
        let pk_point: ExtendedPoint = pk_affine.into();

        // Compute challenge using little-endian bytes (matching the sign() function)
        let credential_hash = Sha256::digest(data);
        let mut challenge_input = Vec::new();
        // For challenge, we need to use the little-endian representation
        // that the sign() function uses internally
        challenge_input.extend_from_slice(&fq_to_bytes_le(&r_u));
        challenge_input.extend_from_slice(&fq_to_bytes_le(&r_v));
        challenge_input.extend_from_slice(&fq_to_bytes_le(&pk_u));
        challenge_input.extend_from_slice(&fq_to_bytes_le(&pk_v));
        challenge_input.extend_from_slice(&credential_hash);
        let c_hash = Sha256::digest(&challenge_input);
        let c = bytes_to_scalar(c_hash.as_slice().try_into().unwrap());

        // lhs = s * G (using SubgroupPoint generator, then convert to ExtendedPoint)
        let lhs: ExtendedPoint = (SubgroupPoint::generator() * s).into();

        // rhs = r + c * pk
        let c_pk = pk_point * c;
        let rhs = r_point + c_pk;

        // Verify lhs == rhs
        assert_eq!(lhs, rhs, "Signature verification failed");
    }
}
