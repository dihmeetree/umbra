//! STARK proof types and error definitions.

use serde::{Deserialize, Serialize};
use winterfell::math::ToElements;

use super::convert::Felt;

/// Error type for STARK proof operations.
#[derive(Clone, Debug, thiserror::Error)]
pub enum StarkError {
    #[error("proof generation failed: {0}")]
    ProvingFailed(String),
    #[error("proof verification failed: {0}")]
    VerificationFailed(String),
    #[error("proof deserialization failed: {0}")]
    DeserializationFailed(String),
    #[error("invalid witness: {0}")]
    InvalidWitness(String),
}

// ── Balance Proof ──

/// Public inputs for the balance STARK proof.
///
/// These are known to both prover and verifier.
#[derive(Clone, Debug)]
pub struct BalancePublicInputs {
    /// Proof links for inputs (each is 4 field elements).
    /// These replace input commitments — the actual commitment is hidden
    /// inside the proof and never revealed publicly.
    pub input_proof_links: Vec<[Felt; 4]>,
    /// Output commitment digests (outputs are newly created, no linkability issue)
    pub output_commitments: Vec<[Felt; 4]>,
    /// Transaction fee (public)
    pub fee: Felt,
    /// Hash binding the proof to a specific transaction
    pub tx_content_hash: [Felt; 4],
}

impl BalancePublicInputs {
    /// Total number of hash blocks.
    ///
    /// Each input requires 2 blocks (commitment + proof_link), each output 1 block.
    pub fn total_blocks(&self) -> usize {
        self.input_proof_links.len() * 2 + self.output_commitments.len()
    }

    /// Number of inputs.
    pub fn num_inputs(&self) -> usize {
        self.input_proof_links.len()
    }
}

/// Witness data for the balance proof (known only to prover).
///
/// Debug is intentionally not derived to prevent accidental logging of secret values.
/// Zeroize ensures witness data is cleared from memory when dropped.
#[derive(Clone)]
pub struct BalanceWitness {
    /// Input amounts
    pub input_values: Vec<u64>,
    /// Input blinding factors (each 4 field elements = 32 bytes)
    pub input_blindings: Vec<[Felt; 4]>,
    /// Input link nonces for proof_link computation
    pub input_link_nonces: Vec<[Felt; 4]>,
    /// Output amounts
    pub output_values: Vec<u64>,
    /// Output blinding factors
    pub output_blindings: Vec<[Felt; 4]>,
}

/// A serialized STARK proof for balance verification.
///
/// Proves (in zero knowledge):
/// - Each commitment opens correctly to its value and blinding
/// - sum(input_values) == sum(output_values) + fee
/// - All values are in [0, 2^64)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceStarkProof {
    /// The serialized winterfell proof bytes
    pub proof_bytes: Vec<u8>,
    /// Serialized public inputs (commitments, fee, tx_content_hash)
    pub public_inputs_bytes: Vec<u8>,
}

// ── Spend Proof ──

/// Public inputs for the spend STARK proof.
#[derive(Clone, Debug)]
pub struct SpendPublicInputs {
    /// Merkle root of the commitment tree
    pub merkle_root: [Felt; 4],
    /// The nullifier being revealed
    pub nullifier: [Felt; 4],
    /// Proof link binding this spend proof to a balance proof.
    /// Computed as Rescue(commitment, link_nonce) — the actual commitment
    /// is a private witness inside the proof.
    pub proof_link: [Felt; 4],
}

/// Witness data for the spend proof (known only to prover).
///
/// Debug is intentionally not derived to prevent accidental logging of secret values.
/// Zeroize ensures witness data is cleared from memory when dropped.
#[derive(Clone)]
pub struct SpendWitness {
    /// The spend authorization key (secret)
    pub spend_auth: [Felt; 4],
    /// The commitment being spent (leaf in Merkle tree, private)
    pub commitment: [Felt; 4],
    /// Link nonce for proof_link computation (random per input)
    pub link_nonce: [Felt; 4],
    /// Merkle authentication path: (sibling_digest, is_current_right_child)
    pub merkle_path: Vec<([Felt; 4], bool)>,
}

/// A serialized STARK proof for spend verification.
///
/// Proves (in zero knowledge):
/// - Nullifier is correctly derived from (spend_auth, commitment)
/// - The commitment exists in the Merkle tree with the given root
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendStarkProof {
    /// The serialized winterfell proof bytes
    pub proof_bytes: Vec<u8>,
    /// Serialized public inputs (merkle_root, nullifier)
    pub public_inputs_bytes: Vec<u8>,
}

// ── ToElements impls (required by winterfell Air trait) ──

impl ToElements<Felt> for BalancePublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut elems = Vec::new();
        for pl in &self.input_proof_links {
            elems.extend_from_slice(pl);
        }
        for c in &self.output_commitments {
            elems.extend_from_slice(c);
        }
        elems.push(self.fee);
        elems.extend_from_slice(&self.tx_content_hash);
        elems
    }
}

impl ToElements<Felt> for SpendPublicInputs {
    fn to_elements(&self) -> Vec<Felt> {
        let mut elems = Vec::new();
        elems.extend_from_slice(&self.merkle_root);
        elems.extend_from_slice(&self.nullifier);
        elems.extend_from_slice(&self.proof_link);
        elems
    }
}

// ── Serialization helpers for public inputs ──

impl BalancePublicInputs {
    /// Serialize to bytes for embedding in proof.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Input proof_link count
        buf.extend_from_slice(&(self.input_proof_links.len() as u32).to_le_bytes());
        for pl in &self.input_proof_links {
            for e in pl {
                buf.extend_from_slice(&e.as_int().to_le_bytes());
            }
        }
        // Output count
        buf.extend_from_slice(&(self.output_commitments.len() as u32).to_le_bytes());
        for c in &self.output_commitments {
            for e in c {
                buf.extend_from_slice(&e.as_int().to_le_bytes());
            }
        }
        // Fee
        buf.extend_from_slice(&self.fee.as_int().to_le_bytes());
        // tx_content_hash
        for e in &self.tx_content_hash {
            buf.extend_from_slice(&e.as_int().to_le_bytes());
        }
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut pos = 0;

        let read_u32 = |data: &[u8], pos: &mut usize| -> Option<u32> {
            if *pos + 4 > data.len() {
                return None;
            }
            let val = u32::from_le_bytes(data[*pos..*pos + 4].try_into().ok()?);
            *pos += 4;
            Some(val)
        };
        let read_felt = |data: &[u8], pos: &mut usize| -> Option<Felt> {
            if *pos + 8 > data.len() {
                return None;
            }
            let val = u64::from_le_bytes(data[*pos..*pos + 8].try_into().ok()?);
            *pos += 8;
            Some(Felt::new(val))
        };
        let read_digest = |data: &[u8], pos: &mut usize| -> Option<[Felt; 4]> {
            Some([
                read_felt(data, pos)?,
                read_felt(data, pos)?,
                read_felt(data, pos)?,
                read_felt(data, pos)?,
            ])
        };

        let n_in = read_u32(data, &mut pos)? as usize;
        // Reject counts exceeding the protocol limit to prevent allocation DoS.
        if n_in > crate::constants::MAX_TX_IO {
            return None;
        }
        let mut input_proof_links = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            input_proof_links.push(read_digest(data, &mut pos)?);
        }

        let n_out = read_u32(data, &mut pos)? as usize;
        if n_out > crate::constants::MAX_TX_IO {
            return None;
        }
        let mut output_commitments = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            output_commitments.push(read_digest(data, &mut pos)?);
        }

        let fee = read_felt(data, &mut pos)?;
        let tx_content_hash = read_digest(data, &mut pos)?;

        // Reject trailing data to prevent ambiguous deserialization
        if pos != data.len() {
            return None;
        }

        Some(BalancePublicInputs {
            input_proof_links,
            output_commitments,
            fee,
            tx_content_hash,
        })
    }
}

impl SpendPublicInputs {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(96);
        for e in &self.merkle_root {
            buf.extend_from_slice(&e.as_int().to_le_bytes());
        }
        for e in &self.nullifier {
            buf.extend_from_slice(&e.as_int().to_le_bytes());
        }
        for e in &self.proof_link {
            buf.extend_from_slice(&e.as_int().to_le_bytes());
        }
        buf
    }

    /// Deserialize from bytes. Rejects trailing data.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != 96 {
            return None;
        }
        let mut pos = 0;
        let read_felt = |pos: &mut usize| -> Felt {
            // Safety: length pre-checked >= 96 bytes, we read exactly 12 × 8 = 96
            let bytes: [u8; 8] = data[*pos..*pos + 8]
                .try_into()
                .expect("pre-checked 96-byte minimum");
            *pos += 8;
            Felt::new(u64::from_le_bytes(bytes))
        };
        let merkle_root = [
            read_felt(&mut pos),
            read_felt(&mut pos),
            read_felt(&mut pos),
            read_felt(&mut pos),
        ];
        let nullifier = [
            read_felt(&mut pos),
            read_felt(&mut pos),
            read_felt(&mut pos),
            read_felt(&mut pos),
        ];
        let proof_link = [
            read_felt(&mut pos),
            read_felt(&mut pos),
            read_felt(&mut pos),
            read_felt(&mut pos),
        ];
        Some(SpendPublicInputs {
            merkle_root,
            nullifier,
            proof_link,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::FieldElement;

    #[test]
    fn balance_public_inputs_roundtrip() {
        let pub_inputs = BalancePublicInputs {
            input_proof_links: vec![[Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]],
            output_commitments: vec![[Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]],
            fee: Felt::new(100),
            tx_content_hash: [Felt::new(9), Felt::new(10), Felt::new(11), Felt::new(12)],
        };
        let bytes = pub_inputs.to_bytes();
        let decoded = BalancePublicInputs::from_bytes(&bytes).expect("roundtrip should succeed");
        assert_eq!(decoded.input_proof_links.len(), 1);
        assert_eq!(decoded.output_commitments.len(), 1);
        assert_eq!(decoded.fee.as_int(), 100);
    }

    #[test]
    fn balance_from_bytes_rejects_oversized_input_count() {
        // Craft bytes with n_in = MAX_TX_IO + 1 (exceeds limit)
        let too_many = (crate::constants::MAX_TX_IO + 1) as u32;
        let mut data = Vec::new();
        data.extend_from_slice(&too_many.to_le_bytes());
        // Pad with enough zeros for one digest (won't matter, should reject early)
        data.extend_from_slice(&[0u8; 1024]);
        assert!(
            BalancePublicInputs::from_bytes(&data).is_none(),
            "should reject n_in > MAX_TX_IO"
        );
    }

    #[test]
    fn balance_from_bytes_rejects_oversized_output_count() {
        // Craft bytes with n_in = 0, n_out = MAX_TX_IO + 1
        let too_many = (crate::constants::MAX_TX_IO + 1) as u32;
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // n_in = 0
        data.extend_from_slice(&too_many.to_le_bytes()); // n_out > MAX_TX_IO
        data.extend_from_slice(&[0u8; 1024]);
        assert!(
            BalancePublicInputs::from_bytes(&data).is_none(),
            "should reject n_out > MAX_TX_IO"
        );
    }

    #[test]
    fn balance_from_bytes_accepts_max_count() {
        // n_in = MAX_TX_IO should be accepted (if enough data provided)
        let max_io = crate::constants::MAX_TX_IO;
        let pub_inputs = BalancePublicInputs {
            input_proof_links: vec![
                [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
                max_io
            ],
            output_commitments: vec![],
            fee: Felt::new(0),
            tx_content_hash: [Felt::ZERO; 4],
        };
        let bytes = pub_inputs.to_bytes();
        let decoded =
            BalancePublicInputs::from_bytes(&bytes).expect("MAX_TX_IO inputs should be accepted");
        assert_eq!(decoded.input_proof_links.len(), max_io);
    }

    #[test]
    fn balance_from_bytes_rejects_truncated_data() {
        // Just 4 bytes (n_in header) with no actual commitment data
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // claims 1 input
                                                     // No commitment data follows
        assert!(
            BalancePublicInputs::from_bytes(&data).is_none(),
            "should reject truncated data"
        );
    }

    #[test]
    fn balance_from_bytes_rejects_trailing_data() {
        let pub_inputs = BalancePublicInputs {
            input_proof_links: vec![[Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]],
            output_commitments: vec![[Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)]],
            fee: Felt::new(100),
            tx_content_hash: [Felt::new(9), Felt::new(10), Felt::new(11), Felt::new(12)],
        };
        let mut bytes = pub_inputs.to_bytes();
        bytes.push(0xFF); // trailing byte
        assert!(
            BalancePublicInputs::from_bytes(&bytes).is_none(),
            "should reject trailing data"
        );
    }

    #[test]
    fn spend_public_inputs_roundtrip() {
        let pub_inputs = SpendPublicInputs {
            merkle_root: [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)],
            nullifier: [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)],
            proof_link: [Felt::new(9), Felt::new(10), Felt::new(11), Felt::new(12)],
        };
        let bytes = pub_inputs.to_bytes();
        assert_eq!(bytes.len(), 96);
        let decoded = SpendPublicInputs::from_bytes(&bytes).expect("roundtrip should succeed");
        assert_eq!(decoded.merkle_root[0].as_int(), 1);
        assert_eq!(decoded.nullifier[0].as_int(), 5);
        assert_eq!(decoded.proof_link[0].as_int(), 9);
    }

    #[test]
    fn spend_from_bytes_rejects_trailing_data() {
        let pub_inputs = SpendPublicInputs {
            merkle_root: [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)],
            nullifier: [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)],
            proof_link: [Felt::new(9), Felt::new(10), Felt::new(11), Felt::new(12)],
        };
        let mut bytes = pub_inputs.to_bytes();
        bytes.push(0xFF); // trailing byte → 97 bytes
        assert!(
            SpendPublicInputs::from_bytes(&bytes).is_none(),
            "should reject trailing data (97 bytes != 96)"
        );
    }

    #[test]
    fn spend_from_bytes_rejects_truncated_data() {
        assert!(
            SpendPublicInputs::from_bytes(&[0u8; 95]).is_none(),
            "should reject truncated data (95 bytes < 96)"
        );
        assert!(
            SpendPublicInputs::from_bytes(&[]).is_none(),
            "should reject empty data"
        );
    }
}
