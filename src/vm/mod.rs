//! Contract virtual machine for STARK-provable smart contract execution.
//!
//! The VM is a register-based machine operating over the Goldilocks field
//! (p = 2^64 - 2^32 + 1), the same field used by Umbra's existing STARK
//! proof system. It produces execution traces suitable for proving in
//! Winterfell AIR constraints.
//!
//! # Architecture
//!
//! - 16 general-purpose registers (r0..r15), each holding a `Felt`
//! - Fixed-size memory (up to `MAX_MEMORY` field elements)
//! - Bounded execution (up to `MAX_STEPS` steps)
//! - Trace recording for STARK proving

pub mod builder;
pub mod contract;
pub mod executor;
pub mod instruction;
pub mod memory;

pub use builder::{build_contract_call, ContractCallError, ContractCallResult};
pub use contract::{contract_state_commitment, ContractCode, ContractError, ContractId};
pub use executor::{execute, VmError, VmInput, VmOutput, VmState, VmTrace};
pub use instruction::Opcode;
pub use memory::Memory;
