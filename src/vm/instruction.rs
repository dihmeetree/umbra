//! Opcode definitions for the Umbra contract VM.
//!
//! All operations are over the Goldilocks field (p = 2^64 - 2^32 + 1).
//! Each instruction maps to a fixed number of execution trace rows,
//! making STARK constraint generation straightforward:
//!
//! - Arithmetic/memory/control: 1 trace row each
//! - Hash: 8 trace rows (one Rescue Prime permutation cycle)

use serde::{Deserialize, Serialize};

/// Opcode for the Umbra contract VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Opcode {
    // -- Arithmetic (1 trace row each) --
    /// r[dst] = r[lhs] + r[rhs] mod p
    Add { dst: u8, lhs: u8, rhs: u8 },
    /// r[dst] = r[lhs] - r[rhs] mod p
    Sub { dst: u8, lhs: u8, rhs: u8 },
    /// r[dst] = r[lhs] * r[rhs] mod p
    Mul { dst: u8, lhs: u8, rhs: u8 },
    /// r[dst] = r[lhs] * r[rhs]^{-1} mod p (fails if rhs == 0)
    Div { dst: u8, lhs: u8, rhs: u8 },
    /// r[dst] = value (as Felt)
    Const { dst: u8, value: u64 },

    // -- Comparison (1 trace row) --
    /// r[dst] = 1 if r[lhs] == r[rhs], else 0
    Eq { dst: u8, lhs: u8, rhs: u8 },

    // -- Control flow (1 trace row each) --
    /// If r[cond] != 0, set pc = target
    CJump { cond: u8, target: u32 },
    /// Unconditional jump: set pc = target
    Jump { target: u32 },

    // -- Memory (1 trace row each) --
    /// r[dst] = memory[r[addr]]
    Load { dst: u8, addr: u8 },
    /// memory[r[addr]] = r[src]
    Store { src: u8, addr: u8 },

    // -- Hashing (8 trace rows: one Rescue Prime permutation cycle) --
    /// Hash 8 rate elements from r[src_start..src_start+8], writing
    /// the 4-element digest to r[dst..dst+4].
    ///
    /// Uses the same Rescue Prime permutation as the existing STARK proofs.
    Hash { dst: u8, src_start: u8 },

    // -- Contract I/O --
    /// Load 4 felts of input commitment[index] into r[dst..dst+4].
    LoadInput { dst: u8, index: u8 },
    /// Emit r[src..src+4] as an output commitment (4 felts).
    EmitOutput { src: u8 },
    /// Emit r[src..src+4] as a nullifier (4 felts).
    EmitNullifier { src: u8 },

    // -- Termination --
    /// Stop execution successfully.
    Halt,
    /// Stop execution with failure (assertion failed).
    Fail,
}

impl Opcode {
    /// Number of trace rows this opcode consumes.
    pub fn trace_rows(&self) -> usize {
        match self {
            Opcode::Hash { .. } => 8,
            _ => 1,
        }
    }

    /// Validate register indices are within bounds (0..NUM_REGISTERS).
    pub fn validate_registers(&self, num_registers: usize) -> bool {
        let check = |r: u8| (r as usize) < num_registers;
        let check4 = |r: u8| (r as usize + 3) < num_registers;
        let check8 = |r: u8| (r as usize + 7) < num_registers;

        match *self {
            Opcode::Add { dst, lhs, rhs }
            | Opcode::Sub { dst, lhs, rhs }
            | Opcode::Mul { dst, lhs, rhs }
            | Opcode::Div { dst, lhs, rhs }
            | Opcode::Eq { dst, lhs, rhs } => check(dst) && check(lhs) && check(rhs),
            Opcode::Const { dst, .. } => check(dst),
            Opcode::CJump { cond, .. } => check(cond),
            Opcode::Jump { .. } | Opcode::Halt | Opcode::Fail => true,
            Opcode::Load { dst, addr } | Opcode::Store { src: dst, addr } => {
                check(dst) && check(addr)
            }
            Opcode::Hash { dst, src_start } => check4(dst) && check8(src_start),
            Opcode::LoadInput { dst, .. } => check4(dst),
            Opcode::EmitOutput { src } | Opcode::EmitNullifier { src } => check4(src),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_trace_rows() {
        assert_eq!(
            Opcode::Add {
                dst: 0,
                lhs: 1,
                rhs: 2
            }
            .trace_rows(),
            1
        );
        assert_eq!(
            Opcode::Hash {
                dst: 0,
                src_start: 4
            }
            .trace_rows(),
            8
        );
        assert_eq!(Opcode::Halt.trace_rows(), 1);
    }

    #[test]
    fn opcode_validate_registers_valid() {
        assert!(Opcode::Add {
            dst: 0,
            lhs: 1,
            rhs: 15
        }
        .validate_registers(16));
        assert!(Opcode::Hash {
            dst: 0,
            src_start: 8
        }
        .validate_registers(16));
        assert!(Opcode::LoadInput { dst: 12, index: 0 }.validate_registers(16));
    }

    #[test]
    fn opcode_validate_registers_invalid() {
        assert!(!Opcode::Add {
            dst: 16,
            lhs: 0,
            rhs: 0
        }
        .validate_registers(16));
        assert!(!Opcode::Hash {
            dst: 0,
            src_start: 9
        }
        .validate_registers(16));
        assert!(!Opcode::LoadInput { dst: 13, index: 0 }.validate_registers(16));
    }

    #[test]
    fn opcode_roundtrip_serialization() {
        let opcodes = vec![
            Opcode::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Opcode::Const { dst: 3, value: 42 },
            Opcode::Hash {
                dst: 0,
                src_start: 4,
            },
            Opcode::CJump {
                cond: 0,
                target: 10,
            },
            Opcode::Halt,
        ];
        let bytes = crate::serialize(&opcodes).unwrap();
        let restored: Vec<Opcode> = crate::deserialize(&bytes).unwrap();
        assert_eq!(opcodes, restored);
    }
}
