//! High-level helper for building contract call transactions.
//!
//! Combines VM execution, STARK proving, and transaction building into a
//! single function call.

use crate::crypto::stark::convert::hash_to_felts;
use crate::crypto::stark::execution_prover::prove_execution;
use crate::crypto::stark::types::{ExecutionPublicInputs, ExecutionWitness, StarkError};
use crate::vm::{execute, ContractCode, VmInput};
use winterfell::math::FieldElement;

/// Build a contract call transaction from raw inputs.
///
/// 1. Executes the contract VM
/// 2. Produces a STARK execution proof
/// 3. Returns the execution proof, contract_id, and function_hash ready
///    for use with `TransactionBuilder::call_contract()`
pub fn build_contract_call(
    contract: &ContractCode,
    function_hash: crate::Hash,
    input_commitments: Vec<[winterfell::math::fields::f64::BaseElement; 4]>,
    initial_memory: Vec<winterfell::math::fields::f64::BaseElement>,
    proof_options: winterfell::ProofOptions,
) -> Result<ContractCallResult, ContractCallError> {
    type Felt = winterfell::math::fields::f64::BaseElement;

    let vm_input = VmInput {
        program: contract.bytecode.clone(),
        input_commitments: input_commitments.clone(),
        initial_memory: initial_memory.clone(),
    };

    // Execute the VM
    let vm_output = execute(&vm_input).map_err(ContractCallError::VmExecution)?;

    if !vm_output.success {
        return Err(ContractCallError::VmExecution(
            crate::vm::VmError::ExecutionFailed(vm_output.steps_used),
        ));
    }

    // Compute memory hashes for public inputs
    let initial_state_hash = memory_hash(&initial_memory);
    let final_state_hash = memory_hash(vm_output.final_state.memory.data());

    let pub_inputs = ExecutionPublicInputs {
        contract_id: hash_to_felts(&contract.id),
        function_hash: hash_to_felts(&function_hash),
        input_commitments,
        output_commitments: vm_output.output_commitments.clone(),
        emitted_nullifiers: vm_output.emitted_nullifiers.clone(),
        initial_state_hash,
        final_state_hash,
        steps_used: Felt::new(vm_output.steps_used as u64),
    };

    let trace_width = vm_output.trace.width();
    let witness = ExecutionWitness {
        trace_rows: vm_output.trace.rows,
        trace_width,
    };

    let execution_proof =
        prove_execution(&witness, &pub_inputs, proof_options).map_err(ContractCallError::Proof)?;

    Ok(ContractCallResult {
        contract_id: contract.id,
        function_hash,
        execution_proof,
        output_commitments: vm_output.output_commitments,
        emitted_nullifiers: vm_output.emitted_nullifiers,
        steps_used: vm_output.steps_used,
        initial_state_hash,
        final_state_hash,
    })
}

/// Compute a hash of memory contents for use as public input.
fn memory_hash(
    memory: &[winterfell::math::fields::f64::BaseElement],
) -> [winterfell::math::fields::f64::BaseElement; 4] {
    use winterfell::math::fields::f64::BaseElement as Felt;

    if memory.is_empty() {
        return [Felt::ZERO; 4];
    }

    // Hash memory as bytes via BLAKE3 and convert to felts
    let mut bytes = Vec::with_capacity(memory.len() * 8);
    for &felt in memory {
        bytes.extend_from_slice(&felt.as_int().to_le_bytes());
    }
    let hash = crate::hash_domain(b"umbra.vm.memory_hash", &bytes);
    hash_to_felts(&hash)
}

/// Result of building a contract call.
pub struct ContractCallResult {
    /// Contract ID.
    pub contract_id: crate::Hash,
    /// Function hash.
    pub function_hash: crate::Hash,
    /// STARK execution proof.
    pub execution_proof: crate::crypto::stark::types::ExecutionStarkProof,
    /// Output commitments produced by the contract.
    pub output_commitments: Vec<[winterfell::math::fields::f64::BaseElement; 4]>,
    /// Nullifiers emitted by the contract.
    pub emitted_nullifiers: Vec<[winterfell::math::fields::f64::BaseElement; 4]>,
    /// Number of execution steps used.
    pub steps_used: usize,
    /// Hash of the initial memory state (4 field elements).
    pub initial_state_hash: [winterfell::math::fields::f64::BaseElement; 4],
    /// Hash of the final memory state (4 field elements).
    pub final_state_hash: [winterfell::math::fields::f64::BaseElement; 4],
}

/// Errors that can occur when building a contract call.
#[derive(Debug, thiserror::Error)]
pub enum ContractCallError {
    #[error("VM execution failed: {0}")]
    VmExecution(#[from] crate::vm::VmError),
    #[error("STARK proof generation failed: {0}")]
    Proof(StarkError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::Opcode;

    fn test_proof_options() -> winterfell::ProofOptions {
        winterfell::ProofOptions::new(
            42,
            8,
            10,
            winterfell::FieldExtension::Cubic,
            8,
            255,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        )
    }

    #[test]
    fn build_contract_call_halt_only() {
        let contract = ContractCode::new(vec![Opcode::Halt]).unwrap();
        let function_hash = crate::hash_domain(b"test.fn", b"main");
        let result = build_contract_call(
            &contract,
            function_hash,
            vec![],
            vec![],
            test_proof_options(),
        );
        assert!(
            result.is_ok(),
            "build_contract_call failed: {:?}",
            result.err()
        );
        let call = result.unwrap();
        assert_eq!(call.contract_id, contract.id);
        assert_eq!(call.function_hash, function_hash);
        assert!(call.output_commitments.is_empty());
        assert!(call.emitted_nullifiers.is_empty());
    }

    #[test]
    fn build_contract_call_with_computation() {
        let contract = ContractCode::new(vec![
            Opcode::Const { dst: 0, value: 10 },
            Opcode::Const { dst: 1, value: 20 },
            Opcode::Add {
                dst: 2,
                lhs: 0,
                rhs: 1,
            },
            Opcode::Halt,
        ])
        .unwrap();
        let function_hash = crate::hash_domain(b"test.fn", b"add");
        let result = build_contract_call(
            &contract,
            function_hash,
            vec![],
            vec![],
            test_proof_options(),
        );
        assert!(
            result.is_ok(),
            "build_contract_call failed: {:?}",
            result.err()
        );
        let call = result.unwrap();
        assert_eq!(call.steps_used, 4);
    }

    #[test]
    fn build_contract_call_empty_program_fails() {
        let contract = ContractCode::new(vec![Opcode::Halt]).unwrap();
        // Manually create with empty bytecode (bypassing ContractCode::new validation)
        let mut empty_contract = contract;
        empty_contract.bytecode = vec![];
        let function_hash = crate::hash_domain(b"test.fn", b"main");
        let result = build_contract_call(
            &empty_contract,
            function_hash,
            vec![],
            vec![],
            test_proof_options(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_contract_call_result_has_correct_proof() {
        let contract = ContractCode::new(vec![Opcode::Halt]).unwrap();
        let function_hash = crate::hash_domain(b"test.fn", b"verify");
        let call = build_contract_call(
            &contract,
            function_hash,
            vec![],
            vec![],
            test_proof_options(),
        )
        .unwrap();
        // Proof bytes should be non-empty
        assert!(!call.execution_proof.proof_bytes.is_empty());
        assert!(!call.execution_proof.public_inputs_bytes.is_empty());
    }

    #[test]
    fn build_contract_call_exposes_state_hashes() {
        use winterfell::math::FieldElement;
        let contract = ContractCode::new(vec![Opcode::Halt]).unwrap();
        let function_hash = crate::hash_domain(b"test.fn", b"state");
        let call = build_contract_call(
            &contract,
            function_hash,
            vec![],
            vec![],
            test_proof_options(),
        )
        .unwrap();
        // With empty initial memory, initial_state_hash should be all zeros
        // (memory_hash returns ZERO for empty slice)
        for &felt in &call.initial_state_hash {
            assert_eq!(felt, winterfell::math::fields::f64::BaseElement::ZERO);
        }
        // final_state_hash is populated (VM memory is non-empty after execution
        // because the VM allocates a fixed-size memory array)
        // Just verify the fields are accessible and deterministic
        let call2 = build_contract_call(
            &contract,
            function_hash,
            vec![],
            vec![],
            test_proof_options(),
        )
        .unwrap();
        assert_eq!(call.final_state_hash, call2.final_state_hash);
    }

    #[test]
    fn initial_state_hash_matches_empty_memory() {
        use winterfell::math::fields::f64::BaseElement as Felt;
        use winterfell::math::FieldElement;

        // Verify memory_hash of empty slice returns zeros
        let hash = super::memory_hash(&[]);
        assert_eq!(hash, [Felt::ZERO; 4]);

        // Verify memory_hash of non-empty slice returns non-zeros
        let hash2 = super::memory_hash(&[Felt::new(42)]);
        assert_ne!(hash2, [Felt::ZERO; 4]);
    }
}
