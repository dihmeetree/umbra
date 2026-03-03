//! AIR for the contract execution STARK proof.
//!
//! Proves that a VM execution trace is structurally valid:
//! 1. Execution starts from a clean state (registers zeroed, pc=0)
//! 2. Execution terminates in a halted state
//! 3. The halted flag is boolean (0 or 1)
//! 4. The halted flag transitions monotonically (0 -> 1, never 1 -> 0)
//!
//! Trace layout (EXECUTION_TRACE_WIDTH = 25 columns):
//!
//! Columns 0-15:  Registers r0..r15
//! Column  16:    Program counter
//! Column  17:    Opcode selector
//! Columns 18-20: Operands (a, b, c)
//! Column  21:    Memory address
//! Column  22:    Memory value
//! Column  23:    Hash active flag
//! Column  24:    Halted flag

use winterfell::math::FieldElement;
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use super::convert::Felt;
use super::types::ExecutionPublicInputs;

/// Trace width for the execution AIR.
pub const EXECUTION_TRACE_WIDTH: usize = 25;

/// Number of register columns.
const NUM_REGISTERS: usize = 16;

// Column indices (matching executor.rs layout).
const COL_PC: usize = 16;
const COL_HALTED: usize = 24;

/// The Execution AIR definition.
pub struct ExecutionAir {
    context: AirContext<Felt>,
    // Will be used for public-input boundary assertions as constraints are expanded.
    _pub_inputs: ExecutionPublicInputs,
}

impl Air for ExecutionAir {
    type BaseField = Felt;
    type PublicInputs = ExecutionPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Transition constraints (2 total, each degree 2):
        //
        // 0: Halted flag is boolean:
        //    halted * (halted - 1) = 0
        //
        // 1: Halted monotonicity (once halted, stays halted):
        //    halted_current * (1 - halted_next) = 0
        //
        // Per-column halt-freezing constraints are omitted for now because
        // Winterfell requires each constraint polynomial to have the declared
        // degree. Columns that are all-zero (unused registers, etc.) would
        // produce degree-0 constraint polynomials, causing a degree mismatch.
        // Per-column freezing will be added alongside opcode-level constraints
        // that guarantee non-trivial column usage.

        let num_constraints = 2;
        let degrees = vec![TransitionConstraintDegree::new(2); num_constraints];

        // Boundary assertions: 16 registers=0 + pc=0 + halted=0 at first row,
        // halted=1 at last row = 19 total.
        let num_assertions = NUM_REGISTERS + 3;
        let context = AirContext::new(trace_info, degrees, num_assertions, options);

        Self {
            context,
            _pub_inputs: pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Felt> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        let halted = current[COL_HALTED];

        // Constraint 0: Halted flag is boolean.
        // halted * (halted - 1) = 0
        result[0] = halted * (halted - E::ONE);

        // Constraint 1: Halted monotonicity (once halted, stays halted).
        // halted_current * (1 - halted_next) = 0
        result[1] = halted * (E::ONE - next[COL_HALTED]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let mut assertions = Vec::new();
        let trace_len = self.trace_length();

        // First row: all registers are zero.
        for i in 0..NUM_REGISTERS {
            assertions.push(Assertion::single(i, 0, Felt::ZERO));
        }
        // First row: pc = 0.
        assertions.push(Assertion::single(COL_PC, 0, Felt::ZERO));
        // First row: not halted.
        assertions.push(Assertion::single(COL_HALTED, 0, Felt::ZERO));

        // Last row: halted.
        assertions.push(Assertion::single(COL_HALTED, trace_len - 1, Felt::ONE));

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        // No periodic columns needed for the current constraint set.
        vec![]
    }
}
