//! Conversion utilities between Spectra's `Hash` type and Goldilocks field elements.

use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

use crate::Hash;

/// A Goldilocks field element (p = 2^64 - 2^32 + 1).
pub type Felt = BaseElement;

/// Number of field elements in a Rescue Prime digest.
pub const DIGEST_SIZE: usize = 4;

/// Convert a Rescue Prime digest (4 field elements) to a 32-byte hash.
///
/// Each field element is serialized as 8 bytes little-endian.
pub fn felts_to_hash(elements: &[Felt; DIGEST_SIZE]) -> Hash {
    let mut out = [0u8; 32];
    for i in 0..DIGEST_SIZE {
        out[i * 8..(i + 1) * 8].copy_from_slice(&elements[i].as_int().to_le_bytes());
    }
    out
}

/// Convert a 32-byte hash to 4 Goldilocks field elements.
///
/// Each 8-byte chunk is interpreted as a little-endian u64 and reduced mod p
/// (where p = 2^64 - 2^32 + 1, the Goldilocks prime).
///
/// **Important:** This conversion is lossy for non-field-native values. A u64 value
/// in `[p, 2^64)` will be reduced mod p, so `felts_to_hash(hash_to_felts(h))` may
/// differ from `h` when `h` originates from BLAKE3 or another source of uniformly
/// random bytes. The probability of reduction per element is ~2^(-32), giving a
/// negligible full-digest collision probability of ~2^(-128).
///
/// For field-native digests (e.g., Rescue Prime outputs where all elements are
/// already in `[0, p)`), the round-trip is lossless.
pub fn hash_to_felts(bytes: &Hash) -> [Felt; DIGEST_SIZE] {
    let mut result = [Felt::ZERO; DIGEST_SIZE];
    for i in 0..DIGEST_SIZE {
        let val = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        result[i] = Felt::new(val);
    }
    result
}

/// Convert a u64 value to a field element.
pub fn u64_to_felt(v: u64) -> Felt {
    Felt::new(v)
}

/// Extract the digest portion (elements 4..8) from a Rescue state as a Hash.
pub fn state_digest_to_hash(state: &[Felt; 12]) -> Hash {
    let digest = [state[4], state[5], state[6], state[7]];
    felts_to_hash(&digest)
}

/// Compute x^7 for a field element (the Rescue Prime S-box).
#[inline]
pub fn exp7<E: FieldElement>(x: E) -> E {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x2 * x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_felts_roundtrip() {
        let original: Hash = [
            1, 0, 0, 0, 0, 0, 0, 0, // 1
            2, 0, 0, 0, 0, 0, 0, 0, // 2
            3, 0, 0, 0, 0, 0, 0, 0, // 3
            4, 0, 0, 0, 0, 0, 0, 0, // 4
        ];
        let felts = hash_to_felts(&original);
        assert_eq!(felts[0].as_int(), 1);
        assert_eq!(felts[1].as_int(), 2);
        assert_eq!(felts[2].as_int(), 3);
        assert_eq!(felts[3].as_int(), 4);

        let back = felts_to_hash(&felts);
        assert_eq!(original, back);
    }

    #[test]
    fn exp7_correct() {
        let x = Felt::new(5);
        let result = exp7(x);
        assert_eq!(result.as_int(), 78125); // 5^7
    }

    #[test]
    fn u64_to_felt_correct() {
        let f = u64_to_felt(1_000_000);
        assert_eq!(f.as_int(), 1_000_000);
    }
}
