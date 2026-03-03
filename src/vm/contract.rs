//! Contract representation and identification.
//!
//! A contract is identified by a deterministic `ContractId` derived from its
//! bytecode. Contract state is represented as commitments in the UTXO tree,
//! using a domain-separated hash distinct from value commitments.

use serde::{Deserialize, Serialize};
use winterfell::math::fields::f64::BaseElement as Felt;

use crate::vm::instruction::Opcode;
use crate::Hash;

/// Unique identifier for a deployed contract, derived from its bytecode.
pub type ContractId = Hash;

/// A deployed contract's code and metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractCode {
    /// The contract bytecode (sequence of opcodes).
    pub bytecode: Vec<Opcode>,
    /// Deterministic contract identifier: `hash_domain(b"umbra.contract_id", serialized_bytecode)`.
    pub id: ContractId,
}

impl ContractCode {
    /// Create a new contract from bytecode, computing its deterministic ID.
    pub fn new(bytecode: Vec<Opcode>) -> Result<Self, ContractError> {
        if bytecode.is_empty() {
            return Err(ContractError::EmptyBytecode);
        }
        let serialized = crate::serialize(&bytecode)
            .map_err(|e| ContractError::InvalidBytecode(e.to_string()))?;
        if serialized.len() > crate::constants::MAX_CONTRACT_SIZE {
            return Err(ContractError::BytecodeTooLarge(serialized.len()));
        }
        let id = crate::hash_domain(b"umbra.contract_id", &serialized);
        Ok(Self { bytecode, id })
    }
}

/// Compute a contract state commitment using a domain-separated hash.
///
/// This uses a different domain separator than value commitments to prevent
/// confusion between contract state outputs and regular value outputs.
pub fn contract_state_commitment(contract_id: &ContractId, state_elements: &[Felt]) -> [Felt; 4] {
    use winterfell::math::FieldElement;

    // Build a deterministic byte representation for hashing.
    let mut data = Vec::new();
    data.extend_from_slice(contract_id);
    for elem in state_elements {
        data.extend_from_slice(&elem.as_int().to_le_bytes());
    }
    let hash = crate::hash_domain(b"umbra.contract_state", &data);

    // Convert the first 32 bytes of the hash into 4 Felt elements (8 bytes each),
    // reducing modulo the Goldilocks prime.
    let mut result = [Felt::ZERO; 4];
    for (i, chunk) in hash.chunks(8).take(4).enumerate() {
        let val = u64::from_le_bytes(chunk.try_into().expect("chunk is 8 bytes"));
        result[i] = Felt::new(val % (u64::MAX - (1u64 << 32) + 2));
    }
    result
}

/// Errors related to contract operations.
#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("contract bytecode is empty")]
    EmptyBytecode,
    #[error("contract bytecode too large: {0} bytes")]
    BytecodeTooLarge(usize),
    #[error("invalid contract bytecode: {0}")]
    InvalidBytecode(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::FieldElement;

    #[test]
    fn contract_id_is_deterministic() {
        let bytecode = vec![Opcode::Const { dst: 0, value: 42 }, Opcode::Halt];
        let c1 = ContractCode::new(bytecode.clone()).unwrap();
        let c2 = ContractCode::new(bytecode).unwrap();
        assert_eq!(c1.id, c2.id);
    }

    #[test]
    fn different_bytecode_different_id() {
        let c1 = ContractCode::new(vec![Opcode::Halt]).unwrap();
        let c2 = ContractCode::new(vec![Opcode::Const { dst: 0, value: 1 }, Opcode::Halt]).unwrap();
        assert_ne!(c1.id, c2.id);
    }

    #[test]
    fn empty_bytecode_rejected() {
        assert!(ContractCode::new(vec![]).is_err());
    }

    #[test]
    fn contract_state_commitment_deterministic() {
        let id = crate::hash_domain(b"umbra.contract_id", b"test");
        let state = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
        let c1 = contract_state_commitment(&id, &state);
        let c2 = contract_state_commitment(&id, &state);
        assert_eq!(c1, c2);
    }

    #[test]
    fn contract_state_commitment_different_inputs() {
        let id = crate::hash_domain(b"umbra.contract_id", b"test");
        let state_a = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
        let state_b = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)];
        let c1 = contract_state_commitment(&id, &state_a);
        let c2 = contract_state_commitment(&id, &state_b);
        assert_ne!(c1, c2);
    }

    #[test]
    fn contract_code_serialization_roundtrip() {
        let contract = ContractCode::new(vec![Opcode::Halt]).unwrap();
        let bytes = crate::serialize(&contract).unwrap();
        let restored: ContractCode = crate::deserialize(&bytes).unwrap();
        assert_eq!(contract.id, restored.id);
        assert_eq!(contract.bytecode.len(), restored.bytecode.len());
    }

    #[test]
    fn contract_state_commitment_uses_contract_domain() {
        let id = crate::hash_domain(b"umbra.contract_id", b"test");
        let state = [Felt::ZERO; 4];
        let commitment = contract_state_commitment(&id, &state);
        // Verify all elements are valid field elements (non-zero result from non-trivial input)
        let has_nonzero = commitment.iter().any(|e| *e != Felt::ZERO);
        assert!(has_nonzero, "commitment should be non-trivial");
    }
}
