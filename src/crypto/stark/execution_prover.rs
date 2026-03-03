//! Prover for the contract execution STARK proof.
//!
//! Builds the execution trace from VM output and generates a winterfell
//! STARK proof that the execution was structurally valid.

use winterfell::crypto::hashers::Rp64_256;
use winterfell::crypto::{DefaultRandomCoin, MerkleTree};
use winterfell::math::FieldElement;
use winterfell::matrix::ColMatrix;
use winterfell::{
    AuxRandElements, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions, Proof, ProofOptions,
    ProverError, StarkDomain, TraceInfo, TraceTable,
};

use super::convert::Felt;
use super::execution_air::{ExecutionAir, EXECUTION_TRACE_WIDTH};
use super::types::{ExecutionPublicInputs, ExecutionStarkProof, ExecutionWitness, StarkError};

/// Build a `TraceTable` from the VM execution witness.
pub fn build_execution_trace(witness: &ExecutionWitness) -> Result<TraceTable<Felt>, StarkError> {
    if witness.trace_rows.is_empty() {
        return Err(StarkError::InvalidWitness("empty trace".into()));
    }
    if witness.trace_width != EXECUTION_TRACE_WIDTH {
        return Err(StarkError::InvalidWitness(format!(
            "trace width mismatch: expected {}, got {}",
            EXECUTION_TRACE_WIDTH, witness.trace_width
        )));
    }

    let num_rows = witness.trace_rows.len();
    if !num_rows.is_power_of_two() {
        return Err(StarkError::InvalidWitness(format!(
            "trace length {} is not a power of two",
            num_rows
        )));
    }

    // Build column-major trace table (Winterfell expects column-major).
    let mut columns = vec![vec![Felt::ZERO; num_rows]; EXECUTION_TRACE_WIDTH];
    for (row_idx, row) in witness.trace_rows.iter().enumerate() {
        if row.len() != EXECUTION_TRACE_WIDTH {
            return Err(StarkError::InvalidWitness(format!(
                "row {} has width {}, expected {}",
                row_idx,
                row.len(),
                EXECUTION_TRACE_WIDTH
            )));
        }
        for (col_idx, &val) in row.iter().enumerate() {
            columns[col_idx][row_idx] = val;
        }
    }

    Ok(TraceTable::init(columns))
}

/// The execution prover (implements winterfell's `Prover` trait).
struct ExecutionProver {
    options: ProofOptions,
    pub_inputs: ExecutionPublicInputs,
}

impl winterfell::Prover for ExecutionProver {
    type BaseField = Felt;
    type Air = ExecutionAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Rp64_256;
    type VC = MerkleTree<Rp64_256>;
    type RandomCoin = DefaultRandomCoin<Rp64_256>;
    type TraceLde<E: FieldElement<BaseField = Felt>> =
        DefaultTraceLde<E, Rp64_256, MerkleTree<Rp64_256>>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, Rp64_256, MerkleTree<Rp64_256>>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, ExecutionAir, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> ExecutionPublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Felt>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Felt>,
        domain: &StarkDomain<Felt>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, winterfell::TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Felt>>(
        &self,
        composition_poly_trace: winterfell::CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Felt>,
        partition_options: PartitionOptions,
    ) -> (
        Self::ConstraintCommitment<E>,
        winterfell::CompositionPoly<E>,
    ) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

/// Generate an execution STARK proof from a witness and public inputs.
pub fn prove_execution(
    witness: &ExecutionWitness,
    pub_inputs: &ExecutionPublicInputs,
    options: ProofOptions,
) -> Result<ExecutionStarkProof, StarkError> {
    let trace = build_execution_trace(witness)?;

    let prover = ExecutionProver {
        options,
        pub_inputs: pub_inputs.clone(),
    };

    let proof: Proof = winterfell::Prover::prove(&prover, trace)
        .map_err(|e: ProverError| StarkError::ProvingFailed(e.to_string()))?;

    let proof_bytes = proof.to_bytes();
    let public_inputs_bytes = pub_inputs.to_bytes();

    Ok(ExecutionStarkProof {
        proof_bytes,
        public_inputs_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{execute, Opcode, VmInput};
    use winterfell::Trace;

    fn test_proof_options() -> ProofOptions {
        ProofOptions::new(
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

    fn make_witness_and_pub_inputs(
        program: Vec<Opcode>,
    ) -> (ExecutionWitness, ExecutionPublicInputs) {
        let vm_output = execute(&VmInput {
            program,
            input_commitments: vec![],
            initial_memory: vec![],
        })
        .unwrap();

        let witness = ExecutionWitness {
            trace_rows: vm_output.trace.rows,
            trace_width: EXECUTION_TRACE_WIDTH,
        };

        let pub_inputs = ExecutionPublicInputs {
            contract_id: [Felt::ZERO; 4],
            function_hash: [Felt::ZERO; 4],
            input_commitments: vec![],
            output_commitments: vm_output.output_commitments.to_vec(),
            emitted_nullifiers: vm_output.emitted_nullifiers.to_vec(),
            initial_state_hash: [Felt::ZERO; 4],
            final_state_hash: [Felt::ZERO; 4],
            steps_used: Felt::new(vm_output.steps_used as u64),
        };

        (witness, pub_inputs)
    }

    #[test]
    fn build_trace_from_vm_output() {
        let (witness, _) = make_witness_and_pub_inputs(vec![Opcode::Halt]);
        let trace = build_execution_trace(&witness).unwrap();
        assert_eq!(trace.width(), EXECUTION_TRACE_WIDTH);
        assert!(trace.length().is_power_of_two());
    }

    #[test]
    fn build_trace_rejects_empty() {
        let witness = ExecutionWitness {
            trace_rows: vec![],
            trace_width: EXECUTION_TRACE_WIDTH,
        };
        assert!(build_execution_trace(&witness).is_err());
    }

    #[test]
    fn build_trace_rejects_wrong_width() {
        let witness = ExecutionWitness {
            trace_rows: vec![vec![Felt::ZERO; 10]; 8],
            trace_width: 10,
        };
        assert!(build_execution_trace(&witness).is_err());
    }

    #[test]
    fn prove_verify_halt_only() {
        let (witness, pub_inputs) = make_witness_and_pub_inputs(vec![Opcode::Halt]);
        let proof = prove_execution(&witness, &pub_inputs, test_proof_options()).unwrap();
        let verified = crate::crypto::stark::verify::verify_execution_proof(&proof).unwrap();
        assert_eq!(verified.steps_used, pub_inputs.steps_used);
    }

    #[test]
    fn prove_verify_simple_add() {
        let (witness, pub_inputs) = make_witness_and_pub_inputs(vec![
            Opcode::Const { dst: 0, value: 10 },
            Opcode::Const { dst: 1, value: 20 },
            Opcode::Add {
                dst: 2,
                lhs: 0,
                rhs: 1,
            },
            Opcode::Halt,
        ]);
        let proof = prove_execution(&witness, &pub_inputs, test_proof_options()).unwrap();
        crate::crypto::stark::verify::verify_execution_proof(&proof).unwrap();
    }

    #[test]
    fn prove_verify_with_emit_output() {
        let (witness, pub_inputs) = make_witness_and_pub_inputs(vec![
            Opcode::Const { dst: 0, value: 1 },
            Opcode::Const { dst: 1, value: 2 },
            Opcode::Const { dst: 2, value: 3 },
            Opcode::Const { dst: 3, value: 4 },
            Opcode::EmitOutput { src: 0 },
            Opcode::Halt,
        ]);
        assert_eq!(pub_inputs.output_commitments.len(), 1);
        let proof = prove_execution(&witness, &pub_inputs, test_proof_options()).unwrap();
        let verified = crate::crypto::stark::verify::verify_execution_proof(&proof).unwrap();
        assert_eq!(verified.output_commitments.len(), 1);
    }

    #[test]
    fn prove_verify_conditional_branch() {
        let (witness, pub_inputs) = make_witness_and_pub_inputs(vec![
            Opcode::Const { dst: 0, value: 1 },
            Opcode::CJump { cond: 0, target: 3 },
            Opcode::Const { dst: 1, value: 99 },
            Opcode::Halt,
        ]);
        let proof = prove_execution(&witness, &pub_inputs, test_proof_options()).unwrap();
        crate::crypto::stark::verify::verify_execution_proof(&proof).unwrap();
    }

    #[test]
    fn prove_verify_memory_ops() {
        let (witness, pub_inputs) = make_witness_and_pub_inputs(vec![
            Opcode::Const { dst: 0, value: 5 },
            Opcode::Const { dst: 1, value: 42 },
            Opcode::Store { src: 1, addr: 0 },
            Opcode::Load { dst: 2, addr: 0 },
            Opcode::Halt,
        ]);
        let proof = prove_execution(&witness, &pub_inputs, test_proof_options()).unwrap();
        crate::crypto::stark::verify::verify_execution_proof(&proof).unwrap();
    }

    #[test]
    fn execution_proof_roundtrip_serialization() {
        let (witness, pub_inputs) = make_witness_and_pub_inputs(vec![Opcode::Halt]);
        let proof = prove_execution(&witness, &pub_inputs, test_proof_options()).unwrap();
        let bytes = crate::serialize(&proof).unwrap();
        let restored: ExecutionStarkProof = crate::deserialize(&bytes).unwrap();
        assert_eq!(proof.proof_bytes, restored.proof_bytes);
        assert_eq!(proof.public_inputs_bytes, restored.public_inputs_bytes);
    }
}
