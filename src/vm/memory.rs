//! Fixed-size, bounds-checked memory for the contract VM.

use crate::crypto::stark::convert::Felt;
use winterfell::math::FieldElement;

/// Maximum memory size in field elements.
pub const MAX_MEMORY: usize = 1 << 14; // 16384 slots

/// Fixed-size memory backed by a `Vec<Felt>`.
///
/// All addresses are checked against `MAX_MEMORY`. Out-of-range accesses
/// return an error rather than panicking, so the VM can surface them
/// as structured `VmError`s.
#[derive(Clone, Debug)]
pub struct Memory {
    data: Vec<Felt>,
}

impl Memory {
    /// Create a new zeroed memory region.
    pub fn new() -> Self {
        Self {
            data: vec![Felt::ZERO; MAX_MEMORY],
        }
    }

    /// Create memory pre-populated with initial data.
    ///
    /// `initial` is loaded starting at address 0. Remaining slots are zero.
    /// Returns `None` if `initial` exceeds `MAX_MEMORY`.
    pub fn with_initial(initial: &[Felt]) -> Option<Self> {
        if initial.len() > MAX_MEMORY {
            return None;
        }
        let mut data = vec![Felt::ZERO; MAX_MEMORY];
        data[..initial.len()].copy_from_slice(initial);
        Some(Self { data })
    }

    /// Read a field element from the given address.
    pub fn load(&self, addr: u64) -> Result<Felt, MemoryError> {
        let idx = addr as usize;
        if idx >= MAX_MEMORY {
            return Err(MemoryError::OutOfBounds(addr));
        }
        Ok(self.data[idx])
    }

    /// Write a field element to the given address.
    pub fn store(&mut self, addr: u64, value: Felt) -> Result<(), MemoryError> {
        let idx = addr as usize;
        if idx >= MAX_MEMORY {
            return Err(MemoryError::OutOfBounds(addr));
        }
        self.data[idx] = value;
        Ok(())
    }

    /// Return a reference to the underlying data.
    pub fn data(&self) -> &[Felt] {
        &self.data
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory access errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MemoryError {
    #[error("memory address out of bounds: {0}")]
    OutOfBounds(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_new_is_zeroed() {
        let mem = Memory::new();
        assert_eq!(mem.load(0).unwrap(), Felt::ZERO);
        assert_eq!(mem.load(MAX_MEMORY as u64 - 1).unwrap(), Felt::ZERO);
    }

    #[test]
    fn memory_store_load_roundtrip() {
        let mut mem = Memory::new();
        let val = Felt::new(42);
        mem.store(100, val).unwrap();
        assert_eq!(mem.load(100).unwrap(), val);
    }

    #[test]
    fn memory_out_of_bounds() {
        let mem = Memory::new();
        assert!(mem.load(MAX_MEMORY as u64).is_err());
        assert!(mem.load(u64::MAX).is_err());
    }

    #[test]
    fn memory_with_initial() {
        let initial = vec![Felt::new(1), Felt::new(2), Felt::new(3)];
        let mem = Memory::with_initial(&initial).unwrap();
        assert_eq!(mem.load(0).unwrap(), Felt::new(1));
        assert_eq!(mem.load(1).unwrap(), Felt::new(2));
        assert_eq!(mem.load(2).unwrap(), Felt::new(3));
        assert_eq!(mem.load(3).unwrap(), Felt::ZERO);
    }

    #[test]
    fn memory_with_initial_oversized_rejected() {
        let oversized = vec![Felt::ZERO; MAX_MEMORY + 1];
        assert!(Memory::with_initial(&oversized).is_none());
    }
}
