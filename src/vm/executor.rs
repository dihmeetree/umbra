//! VM execution engine with trace recording for STARK proving.

use winterfell::math::FieldElement;

use crate::crypto::stark::convert::Felt;
use crate::crypto::stark::rescue;

use super::instruction::Opcode;
use super::memory::{Memory, MAX_MEMORY};

/// Maximum number of execution steps (bounds trace size).
pub const MAX_STEPS: usize = 1 << 16; // 65536

/// Number of general-purpose registers.
pub const NUM_REGISTERS: usize = 16;

/// Trace layout:
///   columns 0..15:  registers r0..r15
///   column  16:     program counter
///   column  17:     opcode selector
///   column  18..20: operands (a, b, c)
///   column  21:     memory address
///   column  22:     memory value
///   column  23:     flag 0 (hash_active)
///   column  24:     flag 1 (halted)
pub const TRACE_WIDTH: usize = 25;

// Column indices.
const COL_PC: usize = 16;
const COL_OPCODE: usize = 17;
const COL_OP_A: usize = 18;
const COL_OP_B: usize = 19;
const COL_OP_C: usize = 20;
const COL_MEM_ADDR: usize = 21;
const COL_MEM_VAL: usize = 22;
const COL_HASH_ACTIVE: usize = 23;
const COL_HALTED: usize = 24;

/// Opcode selector values (used in trace for constraint dispatch).
mod selector {
    pub const ADD: u64 = 1;
    pub const SUB: u64 = 2;
    pub const MUL: u64 = 3;
    pub const DIV: u64 = 4;
    pub const CONST: u64 = 5;
    pub const EQ: u64 = 6;
    pub const CJUMP: u64 = 7;
    pub const JUMP: u64 = 8;
    pub const LOAD: u64 = 9;
    pub const STORE: u64 = 10;
    pub const HASH: u64 = 11;
    pub const LOAD_INPUT: u64 = 12;
    pub const EMIT_OUTPUT: u64 = 13;
    pub const EMIT_NULLIFIER: u64 = 14;
    pub const HALT: u64 = 15;
    pub const FAIL: u64 = 16;
    pub const PADDING: u64 = 0;
}

/// VM execution state.
#[derive(Clone, Debug)]
pub struct VmState {
    pub registers: [Felt; NUM_REGISTERS],
    pub pc: usize,
    pub memory: Memory,
    pub halted: bool,
    pub failed: bool,
    pub step: usize,
}

/// Input to the VM execution.
pub struct VmInput {
    pub program: Vec<Opcode>,
    pub input_commitments: Vec<[Felt; 4]>,
    pub initial_memory: Vec<Felt>,
}

/// Output of VM execution.
pub struct VmOutput {
    pub output_commitments: Vec<[Felt; 4]>,
    pub emitted_nullifiers: Vec<[Felt; 4]>,
    pub trace: VmTrace,
    pub final_state: VmState,
    pub success: bool,
    pub steps_used: usize,
}

/// Execution trace suitable for STARK proving.
///
/// Each row has `TRACE_WIDTH` columns. The number of rows is padded
/// to the next power of two (Winterfell requirement).
pub struct VmTrace {
    pub rows: Vec<Vec<Felt>>,
}

impl VmTrace {
    /// Number of rows in the trace (always a power of two after padding).
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the trace is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Trace width (number of columns).
    pub fn width(&self) -> usize {
        TRACE_WIDTH
    }
}

/// VM execution errors.
#[derive(Debug, thiserror::Error)]
pub enum VmError {
    #[error("max steps exceeded ({MAX_STEPS})")]
    MaxStepsExceeded,
    #[error("division by zero at step {0}")]
    DivisionByZero(usize),
    #[error("memory address out of bounds: {0}")]
    MemoryOutOfBounds(u64),
    #[error("register index out of bounds: {0}")]
    RegisterOutOfBounds(u8),
    #[error("input index out of bounds: {0}")]
    InputOutOfBounds(u8),
    #[error("jump target out of bounds: {0}")]
    JumpOutOfBounds(u32),
    #[error("execution failed (Fail opcode at step {0})")]
    ExecutionFailed(usize),
    #[error("initial memory too large: {0} > {MAX_MEMORY}")]
    InitialMemoryTooLarge(usize),
    #[error("empty program")]
    EmptyProgram,
}

/// Execute a program and return the output with execution trace.
pub fn execute(input: &VmInput) -> Result<VmOutput, VmError> {
    if input.program.is_empty() {
        return Err(VmError::EmptyProgram);
    }

    let memory = Memory::with_initial(&input.initial_memory)
        .ok_or(VmError::InitialMemoryTooLarge(input.initial_memory.len()))?;

    let mut state = VmState {
        registers: [Felt::ZERO; NUM_REGISTERS],
        pc: 0,
        memory,
        halted: false,
        failed: false,
        step: 0,
    };

    let mut trace_rows: Vec<Vec<Felt>> = Vec::new();
    let mut output_commitments: Vec<[Felt; 4]> = Vec::new();
    let mut emitted_nullifiers: Vec<[Felt; 4]> = Vec::new();

    // Record pre-execution initial row (all zeros, halted=0) so the AIR
    // boundary assertion `halted=0 at row 0` is satisfied.
    trace_rows.push(build_trace_row(&state, selector::PADDING));

    while !state.halted && !state.failed {
        if state.step >= MAX_STEPS {
            return Err(VmError::MaxStepsExceeded);
        }
        if state.pc >= input.program.len() {
            return Err(VmError::JumpOutOfBounds(state.pc as u32));
        }

        let opcode = input.program[state.pc];

        if !opcode.validate_registers(NUM_REGISTERS) {
            // Find the first out-of-bounds register
            return Err(VmError::RegisterOutOfBounds(find_oob_register(
                &opcode,
                NUM_REGISTERS,
            )));
        }

        execute_opcode(
            &mut state,
            &opcode,
            &input.input_commitments,
            &mut trace_rows,
            &mut output_commitments,
            &mut emitted_nullifiers,
        )?;

        state.step += 1;
    }

    let steps_used = state.step;
    let success = state.halted && !state.failed;

    // Pad trace to next power of two
    pad_trace(&mut trace_rows);

    Ok(VmOutput {
        output_commitments,
        emitted_nullifiers,
        trace: VmTrace { rows: trace_rows },
        final_state: state,
        success,
        steps_used,
    })
}

/// Execute a single opcode, recording trace rows.
fn execute_opcode(
    state: &mut VmState,
    opcode: &Opcode,
    inputs: &[[Felt; 4]],
    trace: &mut Vec<Vec<Felt>>,
    outputs: &mut Vec<[Felt; 4]>,
    nullifiers: &mut Vec<[Felt; 4]>,
) -> Result<(), VmError> {
    match *opcode {
        Opcode::Add { dst, lhs, rhs } => {
            let result = state.registers[lhs as usize] + state.registers[rhs as usize];
            let mut row = build_trace_row(state, selector::ADD);
            row[COL_OP_A] = Felt::new(dst as u64);
            row[COL_OP_B] = Felt::new(lhs as u64);
            row[COL_OP_C] = Felt::new(rhs as u64);
            trace.push(row);
            state.registers[dst as usize] = result;
            state.pc += 1;
        }
        Opcode::Sub { dst, lhs, rhs } => {
            let result = state.registers[lhs as usize] - state.registers[rhs as usize];
            let mut row = build_trace_row(state, selector::SUB);
            row[COL_OP_A] = Felt::new(dst as u64);
            row[COL_OP_B] = Felt::new(lhs as u64);
            row[COL_OP_C] = Felt::new(rhs as u64);
            trace.push(row);
            state.registers[dst as usize] = result;
            state.pc += 1;
        }
        Opcode::Mul { dst, lhs, rhs } => {
            let result = state.registers[lhs as usize] * state.registers[rhs as usize];
            let mut row = build_trace_row(state, selector::MUL);
            row[COL_OP_A] = Felt::new(dst as u64);
            row[COL_OP_B] = Felt::new(lhs as u64);
            row[COL_OP_C] = Felt::new(rhs as u64);
            trace.push(row);
            state.registers[dst as usize] = result;
            state.pc += 1;
        }
        Opcode::Div { dst, lhs, rhs } => {
            let divisor = state.registers[rhs as usize];
            if divisor == Felt::ZERO {
                return Err(VmError::DivisionByZero(state.step));
            }
            let result = state.registers[lhs as usize] / divisor;
            let mut row = build_trace_row(state, selector::DIV);
            row[COL_OP_A] = Felt::new(dst as u64);
            row[COL_OP_B] = Felt::new(lhs as u64);
            row[COL_OP_C] = Felt::new(rhs as u64);
            trace.push(row);
            state.registers[dst as usize] = result;
            state.pc += 1;
        }
        Opcode::Const { dst, value } => {
            let mut row = build_trace_row(state, selector::CONST);
            row[COL_OP_A] = Felt::new(dst as u64);
            row[COL_OP_B] = Felt::new(value);
            trace.push(row);
            state.registers[dst as usize] = Felt::new(value);
            state.pc += 1;
        }
        Opcode::Eq { dst, lhs, rhs } => {
            let result = if state.registers[lhs as usize] == state.registers[rhs as usize] {
                Felt::ONE
            } else {
                Felt::ZERO
            };
            let mut row = build_trace_row(state, selector::EQ);
            row[COL_OP_A] = Felt::new(dst as u64);
            row[COL_OP_B] = Felt::new(lhs as u64);
            row[COL_OP_C] = Felt::new(rhs as u64);
            trace.push(row);
            state.registers[dst as usize] = result;
            state.pc += 1;
        }
        Opcode::CJump { cond, target } => {
            let mut row = build_trace_row(state, selector::CJUMP);
            row[COL_OP_A] = Felt::new(cond as u64);
            row[COL_OP_B] = Felt::new(target as u64);
            trace.push(row);
            if state.registers[cond as usize] != Felt::ZERO {
                if target as usize >= input_len_placeholder(state) {
                    // Target validation happens at jump time -- we just set pc.
                    // The main loop will catch out-of-bounds pc.
                }
                state.pc = target as usize;
            } else {
                state.pc += 1;
            }
        }
        Opcode::Jump { target } => {
            let mut row = build_trace_row(state, selector::JUMP);
            row[COL_OP_A] = Felt::new(target as u64);
            trace.push(row);
            state.pc = target as usize;
        }
        Opcode::Load { dst, addr } => {
            let address = state.registers[addr as usize].as_int();
            let value = state
                .memory
                .load(address)
                .map_err(|_| VmError::MemoryOutOfBounds(address))?;
            let mut row = build_trace_row(state, selector::LOAD);
            row[COL_OP_A] = Felt::new(dst as u64);
            row[COL_OP_B] = Felt::new(addr as u64);
            row[COL_MEM_ADDR] = Felt::new(address);
            row[COL_MEM_VAL] = value;
            trace.push(row);
            state.registers[dst as usize] = value;
            state.pc += 1;
        }
        Opcode::Store { src, addr } => {
            let address = state.registers[addr as usize].as_int();
            let value = state.registers[src as usize];
            state
                .memory
                .store(address, value)
                .map_err(|_| VmError::MemoryOutOfBounds(address))?;
            let mut row = build_trace_row(state, selector::STORE);
            row[COL_OP_A] = Felt::new(src as u64);
            row[COL_OP_B] = Felt::new(addr as u64);
            row[COL_MEM_ADDR] = Felt::new(address);
            row[COL_MEM_VAL] = value;
            trace.push(row);
            state.pc += 1;
        }
        Opcode::Hash { dst, src_start } => {
            // Build Rescue Prime initial state from register values.
            // Capacity (state[0..4]) is zeroed; rate (state[4..12]) is loaded
            // from r[src_start..src_start+8].
            let mut rescue_state = [Felt::ZERO; rescue::STATE_WIDTH];
            for i in 0..8 {
                rescue_state[4 + i] = state.registers[src_start as usize + i];
            }

            // Record 8 trace rows: row 0 = initial state, rows 1..7 = after each round.
            // Row 0 (initial state)
            let mut row = build_trace_row(state, selector::HASH);
            row[COL_OP_A] = Felt::new(dst as u64);
            row[COL_OP_B] = Felt::new(src_start as u64);
            row[COL_HASH_ACTIVE] = Felt::ONE;
            trace.push(row);

            // Rows 1..7 (after each Rescue round)
            for round in 0..rescue::NUM_ROUNDS {
                rescue::apply_round(&mut rescue_state, round);
                let mut round_row = build_trace_row(state, selector::HASH);
                round_row[COL_HASH_ACTIVE] = Felt::ONE;
                // Store Rescue state in the first 12 register columns for AIR access
                round_row[..rescue::STATE_WIDTH].copy_from_slice(&rescue_state);
                trace.push(round_row);
            }

            // Write digest (elements 4..8) to r[dst..dst+4]
            for i in 0..4 {
                state.registers[dst as usize + i] = rescue_state[4 + i];
            }
            state.pc += 1;
        }
        Opcode::LoadInput { dst, index } => {
            if index as usize >= inputs.len() {
                return Err(VmError::InputOutOfBounds(index));
            }
            let commitment = inputs[index as usize];
            let mut row = build_trace_row(state, selector::LOAD_INPUT);
            row[COL_OP_A] = Felt::new(dst as u64);
            row[COL_OP_B] = Felt::new(index as u64);
            trace.push(row);
            state.registers[dst as usize..dst as usize + 4].copy_from_slice(&commitment);
            state.pc += 1;
        }
        Opcode::EmitOutput { src } => {
            let commitment = [
                state.registers[src as usize],
                state.registers[src as usize + 1],
                state.registers[src as usize + 2],
                state.registers[src as usize + 3],
            ];
            let mut row = build_trace_row(state, selector::EMIT_OUTPUT);
            row[COL_OP_A] = Felt::new(src as u64);
            trace.push(row);
            outputs.push(commitment);
            state.pc += 1;
        }
        Opcode::EmitNullifier { src } => {
            let nullifier = [
                state.registers[src as usize],
                state.registers[src as usize + 1],
                state.registers[src as usize + 2],
                state.registers[src as usize + 3],
            ];
            let mut row = build_trace_row(state, selector::EMIT_NULLIFIER);
            row[COL_OP_A] = Felt::new(src as u64);
            trace.push(row);
            nullifiers.push(nullifier);
            state.pc += 1;
        }
        Opcode::Halt => {
            let mut row = build_trace_row(state, selector::HALT);
            row[COL_HALTED] = Felt::ONE;
            trace.push(row);
            state.halted = true;
        }
        Opcode::Fail => {
            let row = build_trace_row(state, selector::FAIL);
            trace.push(row);
            state.failed = true;
            return Err(VmError::ExecutionFailed(state.step));
        }
    }
    Ok(())
}

/// Build a trace row snapshot from current VM state.
fn build_trace_row(state: &VmState, opcode_sel: u64) -> Vec<Felt> {
    let mut row = vec![Felt::ZERO; TRACE_WIDTH];
    row[..NUM_REGISTERS].copy_from_slice(&state.registers);
    row[COL_PC] = Felt::new(state.pc as u64);
    row[COL_OPCODE] = Felt::new(opcode_sel);
    if state.halted {
        row[COL_HALTED] = Felt::ONE;
    }
    row
}

/// Pad trace rows to the next power of two by cloning the last row.
///
/// Cloning ensures all columns are identical in padding rows, which is
/// required by the AIR halt-freezing constraints (once halted, every
/// column must remain unchanged).
fn pad_trace(rows: &mut Vec<Vec<Felt>>) {
    let min_rows = 8; // Minimum for Winterfell (must be >= 8)
    let target = rows.len().max(min_rows).next_power_of_two();
    let last_row = rows
        .last()
        .expect("trace must have at least one row")
        .clone();
    while rows.len() < target {
        rows.push(last_row.clone());
    }
}

/// Find the first out-of-bounds register in an opcode (for error reporting).
fn find_oob_register(opcode: &Opcode, num_regs: usize) -> u8 {
    match *opcode {
        Opcode::Add { dst, lhs, rhs }
        | Opcode::Sub { dst, lhs, rhs }
        | Opcode::Mul { dst, lhs, rhs }
        | Opcode::Div { dst, lhs, rhs }
        | Opcode::Eq { dst, lhs, rhs } => {
            if dst as usize >= num_regs {
                dst
            } else if lhs as usize >= num_regs {
                lhs
            } else {
                rhs
            }
        }
        Opcode::Const { dst, .. } => dst,
        Opcode::CJump { cond, .. } => cond,
        Opcode::Load { dst, addr } | Opcode::Store { src: dst, addr } => {
            if dst as usize >= num_regs {
                dst
            } else {
                addr
            }
        }
        Opcode::Hash { dst, src_start } => {
            if dst as usize + 3 >= num_regs {
                dst
            } else {
                src_start
            }
        }
        Opcode::LoadInput { dst, .. } => dst,
        Opcode::EmitOutput { src } | Opcode::EmitNullifier { src } => src,
        _ => 0,
    }
}

/// Placeholder: the program length is not stored in VmState, so the main
/// loop's bounds check handles jump targets. This function exists only to
/// make the CJump branch's intent clear.
fn input_len_placeholder(_state: &VmState) -> usize {
    usize::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(program: Vec<Opcode>) -> Result<VmOutput, VmError> {
        execute(&VmInput {
            program,
            input_commitments: vec![],
            initial_memory: vec![],
        })
    }

    #[test]
    fn vm_add_sub_mul_div() {
        let output = run(vec![
            Opcode::Const { dst: 0, value: 10 },
            Opcode::Const { dst: 1, value: 3 },
            Opcode::Add {
                dst: 2,
                lhs: 0,
                rhs: 1,
            },
            Opcode::Sub {
                dst: 3,
                lhs: 0,
                rhs: 1,
            },
            Opcode::Mul {
                dst: 4,
                lhs: 0,
                rhs: 1,
            },
            Opcode::Div {
                dst: 5,
                lhs: 0,
                rhs: 1,
            },
            Opcode::Halt,
        ])
        .unwrap();

        assert!(output.success);
        assert_eq!(output.final_state.registers[2], Felt::new(13)); // 10+3
        assert_eq!(output.final_state.registers[3], Felt::new(7)); // 10-3
        assert_eq!(output.final_state.registers[4], Felt::new(30)); // 10*3
                                                                    // 10/3 in the field: 10 * 3^(-1) mod p
        let expected_div = Felt::new(10) / Felt::new(3);
        assert_eq!(output.final_state.registers[5], expected_div);
    }

    #[test]
    fn vm_const_and_eq() {
        let output = run(vec![
            Opcode::Const { dst: 0, value: 42 },
            Opcode::Const { dst: 1, value: 42 },
            Opcode::Const { dst: 2, value: 99 },
            Opcode::Eq {
                dst: 3,
                lhs: 0,
                rhs: 1,
            },
            Opcode::Eq {
                dst: 4,
                lhs: 0,
                rhs: 2,
            },
            Opcode::Halt,
        ])
        .unwrap();

        assert!(output.success);
        assert_eq!(output.final_state.registers[3], Felt::ONE); // 42 == 42
        assert_eq!(output.final_state.registers[4], Felt::ZERO); // 42 != 99
    }

    #[test]
    fn vm_conditional_jump() {
        // If r0 != 0, jump to instruction 3 (skip the Const that sets r1=99)
        let output = run(vec![
            Opcode::Const { dst: 0, value: 1 },   // r0 = 1
            Opcode::CJump { cond: 0, target: 3 }, // jump to 3
            Opcode::Const { dst: 1, value: 99 },  // skipped
            Opcode::Const { dst: 1, value: 42 },  // r1 = 42
            Opcode::Halt,
        ])
        .unwrap();

        assert!(output.success);
        assert_eq!(output.final_state.registers[1], Felt::new(42));
    }

    #[test]
    fn vm_conditional_jump_not_taken() {
        let output = run(vec![
            Opcode::Const { dst: 0, value: 0 },   // r0 = 0
            Opcode::CJump { cond: 0, target: 3 }, // not taken
            Opcode::Const { dst: 1, value: 99 },  // executed
            Opcode::Halt,
        ])
        .unwrap();

        assert!(output.success);
        assert_eq!(output.final_state.registers[1], Felt::new(99));
    }

    #[test]
    fn vm_load_store_memory() {
        let output = run(vec![
            Opcode::Const { dst: 0, value: 100 }, // addr = 100
            Opcode::Const { dst: 1, value: 42 },  // value = 42
            Opcode::Store { src: 1, addr: 0 },    // mem[100] = 42
            Opcode::Load { dst: 2, addr: 0 },     // r2 = mem[100]
            Opcode::Halt,
        ])
        .unwrap();

        assert!(output.success);
        assert_eq!(output.final_state.registers[2], Felt::new(42));
    }

    #[test]
    fn vm_hash_matches_rescue() {
        // Load 8 values into registers 4..12, hash them, check against direct Rescue.
        let mut program = Vec::new();
        for i in 0..8 {
            program.push(Opcode::Const {
                dst: (4 + i) as u8,
                value: (i + 1) as u64,
            });
        }
        program.push(Opcode::Hash {
            dst: 0,
            src_start: 4,
        });
        program.push(Opcode::Halt);

        let output = run(program).unwrap();
        assert!(output.success);

        // Compute expected Rescue hash directly.
        let mut rescue_state = [Felt::ZERO; rescue::STATE_WIDTH];
        for i in 0..8 {
            rescue_state[4 + i] = Felt::new((i + 1) as u64);
        }
        rescue::apply_permutation(&mut rescue_state);

        for i in 0..4 {
            assert_eq!(
                output.final_state.registers[i],
                rescue_state[4 + i],
                "hash digest element {i} mismatch"
            );
        }
    }

    #[test]
    fn vm_halt_produces_trace() {
        let output = run(vec![Opcode::Halt]).unwrap();
        assert!(output.success);
        assert_eq!(output.steps_used, 1);
        // Trace must be padded to power of 2, minimum 8
        assert!(output.trace.len().is_power_of_two());
        assert!(output.trace.len() >= 8);
        assert_eq!(output.trace.width(), TRACE_WIDTH);
    }

    #[test]
    fn vm_max_steps_exceeded() {
        // Infinite loop: Jump to self
        let result = execute(&VmInput {
            program: vec![Opcode::Jump { target: 0 }],
            input_commitments: vec![],
            initial_memory: vec![],
        });
        assert!(matches!(result, Err(VmError::MaxStepsExceeded)));
    }

    #[test]
    fn vm_emit_output_commitment() {
        let output = run(vec![
            Opcode::Const { dst: 0, value: 10 },
            Opcode::Const { dst: 1, value: 20 },
            Opcode::Const { dst: 2, value: 30 },
            Opcode::Const { dst: 3, value: 40 },
            Opcode::EmitOutput { src: 0 },
            Opcode::Halt,
        ])
        .unwrap();

        assert!(output.success);
        assert_eq!(output.output_commitments.len(), 1);
        assert_eq!(
            output.output_commitments[0],
            [Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]
        );
    }

    #[test]
    fn vm_emit_nullifier() {
        let output = run(vec![
            Opcode::Const { dst: 0, value: 1 },
            Opcode::Const { dst: 1, value: 2 },
            Opcode::Const { dst: 2, value: 3 },
            Opcode::Const { dst: 3, value: 4 },
            Opcode::EmitNullifier { src: 0 },
            Opcode::Halt,
        ])
        .unwrap();

        assert!(output.success);
        assert_eq!(output.emitted_nullifiers.len(), 1);
        assert_eq!(
            output.emitted_nullifiers[0],
            [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]
        );
    }

    #[test]
    fn vm_div_by_zero_fails() {
        let result = run(vec![
            Opcode::Const { dst: 0, value: 10 },
            Opcode::Div {
                dst: 1,
                lhs: 0,
                rhs: 2,
            }, // r2 is 0
            Opcode::Halt,
        ]);
        assert!(matches!(result, Err(VmError::DivisionByZero(1))));
    }

    #[test]
    fn vm_load_input() {
        let commitment = [
            Felt::new(100),
            Felt::new(200),
            Felt::new(300),
            Felt::new(400),
        ];
        let output = execute(&VmInput {
            program: vec![Opcode::LoadInput { dst: 0, index: 0 }, Opcode::Halt],
            input_commitments: vec![commitment],
            initial_memory: vec![],
        })
        .unwrap();

        assert!(output.success);
        assert_eq!(output.final_state.registers[..4], commitment);
    }

    #[test]
    fn vm_load_input_out_of_range_fails() {
        let result = execute(&VmInput {
            program: vec![Opcode::LoadInput { dst: 0, index: 5 }, Opcode::Halt],
            input_commitments: vec![], // no inputs
            initial_memory: vec![],
        });
        assert!(matches!(result, Err(VmError::InputOutOfBounds(5))));
    }

    #[test]
    fn vm_memory_bounds_check() {
        let result = run(vec![
            Opcode::Const {
                dst: 0,
                value: MAX_MEMORY as u64,
            },
            Opcode::Load { dst: 1, addr: 0 },
            Opcode::Halt,
        ]);
        assert!(matches!(result, Err(VmError::MemoryOutOfBounds(_))));
    }

    #[test]
    fn vm_trace_length_is_power_of_two() {
        // Various program lengths should all produce power-of-two traces.
        for len in [1, 2, 3, 5, 7, 15, 16, 17] {
            let mut program = Vec::new();
            for i in 0..len {
                program.push(Opcode::Const {
                    dst: 0,
                    value: i as u64,
                });
            }
            program.push(Opcode::Halt);
            let output = run(program).unwrap();
            assert!(
                output.trace.len().is_power_of_two(),
                "trace len {} is not power of 2 for program len {}",
                output.trace.len(),
                len
            );
        }
    }

    #[test]
    fn vm_program_with_initial_memory() {
        let output = execute(&VmInput {
            program: vec![
                Opcode::Const { dst: 0, value: 0 }, // addr = 0
                Opcode::Load { dst: 1, addr: 0 },   // r1 = mem[0] = 42
                Opcode::Const { dst: 0, value: 1 }, // addr = 1
                Opcode::Load { dst: 2, addr: 0 },   // r2 = mem[1] = 99
                Opcode::Halt,
            ],
            input_commitments: vec![],
            initial_memory: vec![Felt::new(42), Felt::new(99)],
        })
        .unwrap();

        assert!(output.success);
        assert_eq!(output.final_state.registers[1], Felt::new(42));
        assert_eq!(output.final_state.registers[2], Felt::new(99));
    }

    #[test]
    fn vm_empty_program_fails() {
        let result = run(vec![]);
        assert!(matches!(result, Err(VmError::EmptyProgram)));
    }

    #[test]
    fn vm_fail_opcode() {
        let result = run(vec![Opcode::Fail]);
        assert!(matches!(result, Err(VmError::ExecutionFailed(0))));
    }

    #[test]
    fn vm_unconditional_jump() {
        let output = run(vec![
            Opcode::Jump { target: 2 },          // jump over next
            Opcode::Const { dst: 0, value: 99 }, // skipped
            Opcode::Const { dst: 0, value: 42 }, // r0 = 42
            Opcode::Halt,
        ])
        .unwrap();

        assert!(output.success);
        assert_eq!(output.final_state.registers[0], Felt::new(42));
    }
}
