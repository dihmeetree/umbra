//! High-level contract builder DSL that compiles to VM opcodes.
//!
//! Provides a Solidity-like API for writing contracts without manually
//! constructing opcodes, managing registers, or patching jump targets.
//!
//! # Example
//!
//! ```ignore
//! let contract = ContractBuilder::new()
//!     .state("counter", StateType::U64)
//!     .function("increment", |f| {
//!         let count = f.load("counter");
//!         let new_count = f.add(count, f.lit(1));
//!         f.store("counter", new_count);
//!     })
//!     .build();
//! ```

use crate::vm::{ContractCode, Opcode};

// ── Public Types ────────────────────────────────────────────────────────

/// Type of a state variable at the contract's top-level memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateType {
    /// Single field element (1 felt).
    U64,
    /// Boolean flag (1 felt: 0 or 1).
    Bool,
    /// 4-felt identity (e.g., a public key digest).
    Identity,
}

impl StateType {
    fn size(self) -> u64 {
        match self {
            StateType::U64 | StateType::Bool => 1,
            StateType::Identity => 4,
        }
    }
}

/// Type of a field within a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    /// Single field element (1 felt).
    U64,
    /// Boolean flag (1 felt: 0 or 1).
    Bool,
    /// 4-felt identity.
    Identity,
}

impl FieldType {
    fn size(self) -> u64 {
        match self {
            FieldType::U64 | FieldType::Bool => 1,
            FieldType::Identity => 4,
        }
    }

    fn is_identity(self) -> bool {
        matches!(self, FieldType::Identity)
    }
}

/// Handle to a value produced by a FunctionBuilder operation.
///
/// Lightweight and Copy — just an index into the compiler's value table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Var(u16);

/// Handle to a record's computed base address in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordRef(u16);

// ── Internal Types ──────────────────────────────────────────────────────

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct StateDef {
    name: String,
    addr: u64,
    stype: StateType,
}

#[derive(Clone, Debug)]
struct RecordFieldDef {
    name: String,
    offset: u64,
    ftype: FieldType,
}

#[derive(Clone, Debug)]
struct RecordDef {
    name: String,
    fields: Vec<RecordFieldDef>,
    size: u64,
}

#[derive(Clone, Debug)]
struct ArrayDef {
    name: String,
    record_name: String,
    base_addr: u64,
    record_size: u64,
    #[allow(dead_code)]
    max_count: u64,
}

/// Tracks whether a Var is scalar (1 felt) or identity (4 felts).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VarKind {
    Scalar,
    Identity,
}

/// A high-level operation recorded by FunctionBuilder.
#[derive(Clone, Debug)]
enum Op {
    /// Load caller identity from input_commitments[1].
    LoadCaller(Var),
    /// Load scalar param from input_commitments[2][index].
    LoadParam(Var, u8),
    /// Load state variable from memory.
    LoadState(Var, String),
    /// Store value to state variable.
    StoreState(String, Var),
    /// Compute record base address: base_addr + index * record_size.
    IndexRecord(RecordRef, String, Var),
    /// Read a field from a record.
    GetField(Var, RecordRef, String),
    /// Write a value to a record field.
    SetField(RecordRef, String, Var),
    /// Write a constant to a record field.
    SetFieldConst(RecordRef, String, u64),
    /// Load a constant.
    Lit(Var, u64),
    /// dst = lhs + rhs
    Add(Var, Var, Var),
    /// dst = lhs - rhs
    Sub(Var, Var, Var),
    /// dst = lhs * rhs
    Mul(Var, Var, Var),
    /// Assert two values are equal (identity-aware). Fail if not.
    RequireEq(Var, Var),
    /// Emit output commitment.
    Emit(Var),
    /// Emit nullifier.
    Nullify(Var),
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct FunctionDef {
    name: String,
    ops: Vec<Op>,
    var_kinds: Vec<VarKind>,
}

// ── ContractBuilder ─────────────────────────────────────────────────────

/// High-level contract builder. Define state, records, arrays, and functions,
/// then call `.build()` to compile to VM opcodes.
#[derive(Default)]
pub struct ContractBuilder {
    states: Vec<StateDef>,
    records: Vec<RecordDef>,
    arrays: Vec<ArrayDef>,
    functions: Vec<FunctionDef>,
    next_state_addr: u64,
}

impl ContractBuilder {
    pub fn new() -> Self {
        Self {
            states: Vec::new(),
            records: Vec::new(),
            arrays: Vec::new(),
            functions: Vec::new(),
            next_state_addr: 0,
        }
    }

    /// Declare a top-level state variable. Variables are laid out sequentially
    /// starting at memory address 0.
    pub fn state(mut self, name: &str, stype: StateType) -> Self {
        let addr = self.next_state_addr;
        self.next_state_addr += stype.size();
        self.states.push(StateDef {
            name: name.to_string(),
            addr,
            stype,
        });
        self
    }

    /// Declare a record type with named fields.
    pub fn record(mut self, name: &str, fields: &[(&str, FieldType)]) -> Self {
        let mut offset = 0u64;
        let mut field_defs = Vec::new();
        for &(fname, ftype) in fields {
            field_defs.push(RecordFieldDef {
                name: fname.to_string(),
                offset,
                ftype,
            });
            offset += ftype.size();
        }
        self.records.push(RecordDef {
            name: name.to_string(),
            fields: field_defs,
            size: offset,
        });
        self
    }

    /// Declare an array of records. The array starts after the state header,
    /// padded to align with the record size.
    pub fn array(mut self, name: &str, record_type: &str, max_count: u64) -> Self {
        let rec = self
            .records
            .iter()
            .find(|r| r.name == record_type)
            .unwrap_or_else(|| panic!("unknown record type: {record_type}"));
        let record_size = rec.size;

        // Align array start to record_size boundary after state header.
        let header_end = self.next_state_addr;
        let base_addr = if header_end.is_multiple_of(record_size) {
            header_end
        } else {
            header_end + (record_size - header_end % record_size)
        };

        self.arrays.push(ArrayDef {
            name: name.to_string(),
            record_name: record_type.to_string(),
            base_addr,
            record_size,
            max_count,
        });
        self
    }

    /// Define a contract function. The closure receives a `FunctionBuilder`
    /// for declaring the function body using high-level operations.
    pub fn function<F>(mut self, name: &str, body: F) -> Self
    where
        F: FnOnce(&mut FunctionBuilder),
    {
        let mut fb = FunctionBuilder {
            ops: Vec::new(),
            var_kinds: Vec::new(),
        };
        body(&mut fb);
        self.functions.push(FunctionDef {
            name: name.to_string(),
            ops: fb.ops,
            var_kinds: fb.var_kinds,
        });
        self
    }

    /// Compile all declarations and functions into VM bytecode.
    pub fn build(self) -> ContractCode {
        compile(self)
    }
}

// ── FunctionBuilder ─────────────────────────────────────────────────────

/// Builder for a single contract function's body.
///
/// All methods return `Var` or `RecordRef` handles that represent values
/// without exposing registers or memory addresses.
pub struct FunctionBuilder {
    ops: Vec<Op>,
    var_kinds: Vec<VarKind>,
}

impl FunctionBuilder {
    fn new_var(&mut self, kind: VarKind) -> Var {
        let id = self.var_kinds.len() as u16;
        self.var_kinds.push(kind);
        id.into()
    }

    /// The caller's identity (4 felts from input_commitments[1]).
    pub fn caller(&mut self) -> Var {
        let v = self.new_var(VarKind::Identity);
        self.ops.push(Op::LoadCaller(v));
        v
    }

    /// A scalar parameter from input_commitments[2][index].
    pub fn param(&mut self, index: u8) -> Var {
        let v = self.new_var(VarKind::Scalar);
        self.ops.push(Op::LoadParam(v, index));
        v
    }

    /// Load a state variable from memory.
    pub fn load(&mut self, name: &str) -> Var {
        let v = self.new_var(VarKind::Scalar);
        self.ops.push(Op::LoadState(v, name.to_string()));
        v
    }

    /// Store a value to a state variable.
    pub fn store(&mut self, name: &str, value: Var) {
        self.ops.push(Op::StoreState(name.to_string(), value));
    }

    /// Get a handle to a record in an array by index.
    pub fn index(&mut self, array_name: &str, idx: Var) -> RecordRef {
        let id = self.var_kinds.len() as u16;
        // RecordRef is backed by a Var slot holding the base address.
        self.var_kinds.push(VarKind::Scalar);
        let rr = RecordRef(id);
        self.ops
            .push(Op::IndexRecord(rr, array_name.to_string(), idx));
        rr
    }

    /// Read a field from a record.
    pub fn get(&mut self, rec: &RecordRef, field_name: &str) -> Var {
        // We need to figure out the field type to determine VarKind.
        // This is deferred to compilation, but we mark it as Scalar for now
        // and the compiler will fix identity fields.
        let v = self.new_var(VarKind::Scalar); // placeholder
        self.ops.push(Op::GetField(v, *rec, field_name.to_string()));
        v
    }

    /// Write a value to a record field.
    pub fn set(&mut self, rec: &RecordRef, field_name: &str, value: Var) {
        self.ops
            .push(Op::SetField(*rec, field_name.to_string(), value));
    }

    /// Write a constant to a record field.
    pub fn set_const(&mut self, rec: &RecordRef, field_name: &str, value: u64) {
        self.ops
            .push(Op::SetFieldConst(*rec, field_name.to_string(), value));
    }

    /// A constant literal value.
    pub fn lit(&mut self, value: u64) -> Var {
        let v = self.new_var(VarKind::Scalar);
        self.ops.push(Op::Lit(v, value));
        v
    }

    /// Addition: dst = a + b.
    pub fn add(&mut self, a: Var, b: Var) -> Var {
        let v = self.new_var(VarKind::Scalar);
        self.ops.push(Op::Add(v, a, b));
        v
    }

    /// Subtraction: dst = a - b.
    pub fn sub(&mut self, a: Var, b: Var) -> Var {
        let v = self.new_var(VarKind::Scalar);
        self.ops.push(Op::Sub(v, a, b));
        v
    }

    /// Multiplication: dst = a * b.
    pub fn mul(&mut self, a: Var, b: Var) -> Var {
        let v = self.new_var(VarKind::Scalar);
        self.ops.push(Op::Mul(v, a, b));
        v
    }

    /// Assert two values are equal. If they differ, the contract fails.
    /// For identity values (4 felts), automatically compares all 4 elements.
    pub fn require_eq(&mut self, a: Var, b: Var) {
        self.ops.push(Op::RequireEq(a, b));
    }

    /// Emit an output commitment. For identity values, emits 4 felts.
    pub fn emit(&mut self, v: Var) {
        self.ops.push(Op::Emit(v));
    }

    /// Emit a nullifier. For identity values, emits 4 felts.
    pub fn nullify(&mut self, v: Var) {
        self.ops.push(Op::Nullify(v));
    }
}

impl From<u16> for Var {
    fn from(id: u16) -> Self {
        Var(id)
    }
}

// ── Compiler ────────────────────────────────────────────────────────────

/// Internal compilation context.
struct CompileCtx<'a> {
    states: &'a [StateDef],
    records: &'a [RecordDef],
    arrays: &'a [ArrayDef],
    /// Maps RecordRef id -> array name (filled during compilation).
    record_ref_arrays: Vec<(u16, String)>,
}

impl<'a> CompileCtx<'a> {
    fn new(builder: &'a ContractBuilder) -> Self {
        Self {
            states: &builder.states,
            records: &builder.records,
            arrays: &builder.arrays,
            record_ref_arrays: Vec::new(),
        }
    }

    fn find_state(&self, name: &str) -> &StateDef {
        self.states
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("unknown state variable: {name}"))
    }

    fn find_array(&self, name: &str) -> &ArrayDef {
        self.arrays
            .iter()
            .find(|a| a.name == name)
            .unwrap_or_else(|| panic!("unknown array: {name}"))
    }

    fn find_record(&self, name: &str) -> &RecordDef {
        self.records
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("unknown record: {name}"))
    }

    fn find_field(&self, record_name: &str, field_name: &str) -> (u64, FieldType) {
        let rec = self.find_record(record_name);
        let field = rec
            .fields
            .iter()
            .find(|f| f.name == field_name)
            .unwrap_or_else(|| panic!("unknown field: {record_name}.{field_name}"));
        (field.offset, field.ftype)
    }

    fn array_for_record_ref(&self, rr: RecordRef) -> &str {
        self.record_ref_arrays
            .iter()
            .find(|(id, _)| *id == rr.0)
            .map(|(_, name)| name.as_str())
            .unwrap_or_else(|| panic!("unknown RecordRef"))
    }

    /// Generate the dispatch section: load inputs, compare selector, jump to functions.
    fn build_dispatch(&self, num_functions: usize) -> Vec<Opcode> {
        use Opcode::*;
        let mut code = vec![
            LoadInput { dst: 0, index: 0 }, // r0-r3 = selector
            LoadInput { dst: 4, index: 1 }, // r4-r7 = caller identity
            LoadInput { dst: 8, index: 2 }, // r8-r11 = parameters
        ];

        // For each function, add: Const selector, Eq, CJump
        for i in 0..num_functions {
            let selector = (i + 1) as u64;
            code.push(Const {
                dst: 14,
                value: selector,
            });
            code.push(Eq {
                dst: 13,
                lhs: 0,
                rhs: 14,
            });
            code.push(CJump {
                cond: 13,
                target: 0, // patched later
            });
        }

        code.push(Fail); // unknown selector
        code
    }

    /// Compile a single function to opcodes.
    fn compile_function(&mut self, func: &FunctionDef) -> Vec<Opcode> {
        let mut code = Vec::new();
        let mut alloc = RegAlloc::new();

        // Caller identity is pre-loaded in r4-r7 by dispatch.
        // Params are pre-loaded in r8-r11 by dispatch.

        // Track which Var kinds are identity (may be updated by GetField).
        let mut var_kinds = func.var_kinds.clone();

        // First pass: resolve RecordRef -> array name mappings and fix VarKinds for GetField.
        self.record_ref_arrays.clear();
        for op in &func.ops {
            if let Op::IndexRecord(rr, array_name, _) = op {
                self.record_ref_arrays.push((rr.0, array_name.clone()));
            }
        }
        // Fix GetField VarKinds.
        for op in &func.ops {
            if let Op::GetField(var, rr, field_name) = op {
                let array_name = self.array_for_record_ref(*rr).to_string();
                let arr = self.find_array(&array_name);
                let (_, ftype) = self.find_field(&arr.record_name, field_name);
                if ftype.is_identity() {
                    var_kinds[var.0 as usize] = VarKind::Identity;
                }
            }
        }

        for op in &func.ops {
            match op {
                Op::LoadCaller(var) => {
                    // Caller is already in r4-r7 from dispatch LoadInput.
                    alloc.assign_identity(*var, 4);
                }
                Op::LoadParam(var, index) => {
                    // Params are in r8-r11 from dispatch LoadInput.
                    alloc.assign(*var, 8 + *index);
                }
                Op::LoadState(var, name) => {
                    let state = self.find_state(name);
                    let reg = alloc.alloc_scalar();
                    alloc.assign(*var, reg);
                    // Const addr -> r14, Load dst <- mem[r14]
                    code.push(Opcode::Const {
                        dst: 14,
                        value: state.addr,
                    });
                    code.push(Opcode::Load { dst: reg, addr: 14 });
                }
                Op::StoreState(name, val) => {
                    let state = self.find_state(name);
                    let val_reg = alloc.get(*val);
                    code.push(Opcode::Const {
                        dst: 14,
                        value: state.addr,
                    });
                    code.push(Opcode::Store {
                        src: val_reg,
                        addr: 14,
                    });
                }
                Op::IndexRecord(rr, array_name, idx) => {
                    let arr = self.find_array(array_name);
                    let idx_reg = alloc.get(*idx);
                    let base_reg = alloc.alloc_scalar();
                    alloc.assign_rr(*rr, base_reg);

                    // base = base_addr + idx * record_size
                    code.push(Opcode::Const {
                        dst: 14,
                        value: arr.record_size,
                    });
                    code.push(Opcode::Mul {
                        dst: 13,
                        lhs: idx_reg,
                        rhs: 14,
                    });
                    code.push(Opcode::Const {
                        dst: 14,
                        value: arr.base_addr,
                    });
                    code.push(Opcode::Add {
                        dst: base_reg,
                        lhs: 14,
                        rhs: 13,
                    });
                }
                Op::GetField(var, rr, field_name) => {
                    let array_name = self.array_for_record_ref(*rr).to_string();
                    let arr = self.find_array(&array_name);
                    let (offset, ftype) = self.find_field(&arr.record_name, field_name);
                    let base_reg = alloc.get_rr(*rr);

                    if ftype.is_identity() {
                        // Load 4 felts into consecutive registers.
                        let dst_start = alloc.alloc_identity();
                        alloc.assign_identity(*var, dst_start);
                        for i in 0..4u64 {
                            code.push(Opcode::Const {
                                dst: 15,
                                value: offset + i,
                            });
                            code.push(Opcode::Add {
                                dst: 15,
                                lhs: base_reg,
                                rhs: 15,
                            });
                            code.push(Opcode::Load {
                                dst: dst_start + i as u8,
                                addr: 15,
                            });
                        }
                    } else {
                        let dst = alloc.alloc_scalar();
                        alloc.assign(*var, dst);
                        if offset == 0 {
                            code.push(Opcode::Load {
                                dst,
                                addr: base_reg,
                            });
                        } else {
                            code.push(Opcode::Const {
                                dst: 15,
                                value: offset,
                            });
                            code.push(Opcode::Add {
                                dst: 15,
                                lhs: base_reg,
                                rhs: 15,
                            });
                            code.push(Opcode::Load { dst, addr: 15 });
                        }
                    }
                }
                Op::SetField(rr, field_name, val) => {
                    let array_name = self.array_for_record_ref(*rr).to_string();
                    let arr = self.find_array(&array_name);
                    let (offset, ftype) = self.find_field(&arr.record_name, field_name);
                    let base_reg = alloc.get_rr(*rr);
                    let val_reg = alloc.get(*val);

                    if ftype.is_identity() {
                        // Store 4 felts from consecutive registers.
                        for i in 0..4u64 {
                            code.push(Opcode::Const {
                                dst: 15,
                                value: offset + i,
                            });
                            code.push(Opcode::Add {
                                dst: 15,
                                lhs: base_reg,
                                rhs: 15,
                            });
                            code.push(Opcode::Store {
                                src: val_reg + i as u8,
                                addr: 15,
                            });
                        }
                    } else if offset == 0 {
                        code.push(Opcode::Store {
                            src: val_reg,
                            addr: base_reg,
                        });
                    } else {
                        code.push(Opcode::Const {
                            dst: 15,
                            value: offset,
                        });
                        code.push(Opcode::Add {
                            dst: 15,
                            lhs: base_reg,
                            rhs: 15,
                        });
                        code.push(Opcode::Store {
                            src: val_reg,
                            addr: 15,
                        });
                    }
                }
                Op::SetFieldConst(rr, field_name, value) => {
                    let array_name = self.array_for_record_ref(*rr).to_string();
                    let arr = self.find_array(&array_name);
                    let (offset, _) = self.find_field(&arr.record_name, field_name);
                    let base_reg = alloc.get_rr(*rr);

                    code.push(Opcode::Const {
                        dst: 15,
                        value: offset,
                    });
                    code.push(Opcode::Add {
                        dst: 15,
                        lhs: base_reg,
                        rhs: 15,
                    });
                    code.push(Opcode::Const {
                        dst: 14,
                        value: *value,
                    });
                    code.push(Opcode::Store { src: 14, addr: 15 });
                }
                Op::Lit(var, value) => {
                    let reg = alloc.alloc_scalar();
                    alloc.assign(*var, reg);
                    code.push(Opcode::Const {
                        dst: reg,
                        value: *value,
                    });
                }
                Op::Add(dst, a, b) => {
                    let a_reg = alloc.get(*a);
                    let b_reg = alloc.get(*b);
                    let dst_reg = alloc.alloc_scalar();
                    alloc.assign(*dst, dst_reg);
                    code.push(Opcode::Add {
                        dst: dst_reg,
                        lhs: a_reg,
                        rhs: b_reg,
                    });
                }
                Op::Sub(dst, a, b) => {
                    let a_reg = alloc.get(*a);
                    let b_reg = alloc.get(*b);
                    let dst_reg = alloc.alloc_scalar();
                    alloc.assign(*dst, dst_reg);
                    code.push(Opcode::Sub {
                        dst: dst_reg,
                        lhs: a_reg,
                        rhs: b_reg,
                    });
                }
                Op::Mul(dst, a, b) => {
                    let a_reg = alloc.get(*a);
                    let b_reg = alloc.get(*b);
                    let dst_reg = alloc.alloc_scalar();
                    alloc.assign(*dst, dst_reg);
                    code.push(Opcode::Mul {
                        dst: dst_reg,
                        lhs: a_reg,
                        rhs: b_reg,
                    });
                }
                Op::RequireEq(a, b) => {
                    let a_kind = var_kinds[a.0 as usize];
                    let b_kind = var_kinds[b.0 as usize];
                    let a_reg = alloc.get(*a);
                    let b_reg = alloc.get(*b);

                    if a_kind == VarKind::Identity || b_kind == VarKind::Identity {
                        // 4-felt comparison with AND via Mul.
                        // Eq r13, a+0, b+0
                        // Eq r15, a+1, b+1
                        // Mul r13, r13, r15
                        // Eq r15, a+2, b+2
                        // Mul r13, r13, r15
                        // Eq r15, a+3, b+3
                        // Mul r13, r13, r15
                        // CJump r13, skip
                        // Fail
                        code.push(Opcode::Eq {
                            dst: 13,
                            lhs: a_reg,
                            rhs: b_reg,
                        });
                        code.push(Opcode::Eq {
                            dst: 15,
                            lhs: a_reg + 1,
                            rhs: b_reg + 1,
                        });
                        code.push(Opcode::Mul {
                            dst: 13,
                            lhs: 13,
                            rhs: 15,
                        });
                        code.push(Opcode::Eq {
                            dst: 15,
                            lhs: a_reg + 2,
                            rhs: b_reg + 2,
                        });
                        code.push(Opcode::Mul {
                            dst: 13,
                            lhs: 13,
                            rhs: 15,
                        });
                        code.push(Opcode::Eq {
                            dst: 15,
                            lhs: a_reg + 3,
                            rhs: b_reg + 3,
                        });
                        code.push(Opcode::Mul {
                            dst: 13,
                            lhs: 13,
                            rhs: 15,
                        });
                        // CJump over the Fail.
                        let fail_skip = code.len() as u32 + 2; // +1 for CJump, +1 for Fail
                        code.push(Opcode::CJump {
                            cond: 13,
                            target: fail_skip,
                        });
                        code.push(Opcode::Fail);
                    } else {
                        // Scalar comparison.
                        code.push(Opcode::Eq {
                            dst: 13,
                            lhs: a_reg,
                            rhs: b_reg,
                        });
                        let fail_skip = code.len() as u32 + 2;
                        code.push(Opcode::CJump {
                            cond: 13,
                            target: fail_skip,
                        });
                        code.push(Opcode::Fail);
                    }
                }
                Op::Emit(var) => {
                    let reg = alloc.get(*var);
                    code.push(Opcode::EmitOutput { src: reg });
                }
                Op::Nullify(var) => {
                    let reg = alloc.get(*var);
                    code.push(Opcode::EmitNullifier { src: reg });
                }
            }
        }

        code.push(Opcode::Halt);
        code
    }
}

// ── Register Allocator ──────────────────────────────────────────────────

/// Simple register allocator.
///
/// Pre-assigned by dispatch: r0-r3 (selector), r4-r7 (caller), r8-r11 (params).
/// The allocator hands out r12, r0, r1, r2, r3 for new scalar vars (avoiding
/// r13-r15 which are used as scratch by the compiler).
struct RegAlloc {
    /// Maps Var(id) -> register number.
    var_regs: Vec<Option<u8>>,
    /// Maps RecordRef(id) -> register number.
    rr_regs: Vec<Option<u8>>,
    /// Next available register from the pool.
    next_pool_idx: usize,
}

/// Registers available for allocation. Avoids r13, r14, r15 (scratch) and
/// r4-r11 (pre-assigned by dispatch for caller + params).
const ALLOC_POOL: [u8; 5] = [12, 0, 1, 2, 3];

/// Registers for 4-felt identity values. We only have one block: r0-r3.
/// If caller occupies r4-r7 and params r8-r11, the only 4-consecutive
/// block left is r0-r3.
const IDENTITY_POOL: [u8; 1] = [0];

impl RegAlloc {
    fn new() -> Self {
        Self {
            var_regs: Vec::new(),
            rr_regs: Vec::new(),
            next_pool_idx: 0,
        }
    }

    fn ensure_var(&mut self, var: Var) {
        let id = var.0 as usize;
        if id >= self.var_regs.len() {
            self.var_regs.resize(id + 1, None);
        }
    }

    fn ensure_rr(&mut self, rr: RecordRef) {
        let id = rr.0 as usize;
        if id >= self.rr_regs.len() {
            self.rr_regs.resize(id + 1, None);
        }
    }

    fn assign(&mut self, var: Var, reg: u8) {
        self.ensure_var(var);
        self.var_regs[var.0 as usize] = Some(reg);
    }

    fn assign_identity(&mut self, var: Var, start_reg: u8) {
        self.ensure_var(var);
        self.var_regs[var.0 as usize] = Some(start_reg);
    }

    fn assign_rr(&mut self, rr: RecordRef, reg: u8) {
        self.ensure_rr(rr);
        self.rr_regs[rr.0 as usize] = Some(reg);
    }

    fn get(&self, var: Var) -> u8 {
        self.var_regs
            .get(var.0 as usize)
            .and_then(|r| *r)
            .unwrap_or_else(|| panic!("Var({}) not assigned a register", var.0))
    }

    fn get_rr(&self, rr: RecordRef) -> u8 {
        self.rr_regs
            .get(rr.0 as usize)
            .and_then(|r| *r)
            .unwrap_or_else(|| panic!("RecordRef({}) not assigned a register", rr.0))
    }

    fn alloc_scalar(&mut self) -> u8 {
        if self.next_pool_idx < ALLOC_POOL.len() {
            let reg = ALLOC_POOL[self.next_pool_idx];
            self.next_pool_idx += 1;
            reg
        } else {
            panic!("out of registers — contract function too complex for 16 registers");
        }
    }

    fn alloc_identity(&mut self) -> u8 {
        // Use r0-r3 block for identity values loaded from memory.
        IDENTITY_POOL[0]
    }
}

/// Compile a ContractBuilder into VM bytecode with proper jump target offsetting.
fn compile(builder: ContractBuilder) -> ContractCode {
    let mut ctx = CompileCtx::new(&builder);

    // Build dispatch section.
    let dispatch = ctx.build_dispatch(builder.functions.len());
    let dispatch_len = dispatch.len() as u32;

    // Build each function section and track their lengths.
    let mut func_sections: Vec<Vec<Opcode>> = Vec::new();
    for func in &builder.functions {
        let section = ctx.compile_function(func);
        func_sections.push(section);
    }

    // Compute function start offsets.
    let mut func_offsets = Vec::new();
    let mut pos = dispatch_len;
    for section in &func_sections {
        func_offsets.push(pos);
        pos += section.len() as u32;
    }

    // Patch dispatch CJump targets.
    let mut code = dispatch;
    for (i, &offset) in func_offsets.iter().enumerate() {
        let cjump_idx = 5 + i * 3; // 3 LoadInputs + (Const, Eq, CJump) * i + CJump
        if let Some(Opcode::CJump { cond, .. }) = code.get(cjump_idx) {
            code[cjump_idx] = Opcode::CJump {
                cond: *cond,
                target: offset,
            };
        }
    }

    // Offset CJump targets in function sections and concatenate.
    for (i, mut section) in func_sections.into_iter().enumerate() {
        let base = func_offsets[i];
        for op in &mut section {
            if let Opcode::CJump { target, .. } = op {
                *target += base;
            }
        }
        code.extend(section);
    }

    ContractCode::new(code).expect("DSL should produce valid bytecode")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::execute;
    use crate::vm::executor::VmInput;
    use winterfell::math::fields::f64::BaseElement as Felt;
    use winterfell::math::FieldElement;

    #[test]
    fn record_layout_offsets() {
        let builder = ContractBuilder::new().record(
            "Item",
            &[
                ("owner", FieldType::Identity),
                ("value", FieldType::U64),
                ("active", FieldType::Bool),
            ],
        );
        let rec = &builder.records[0];
        assert_eq!(rec.fields[0].offset, 0); // owner: 4 felts
        assert_eq!(rec.fields[1].offset, 4); // value: 1 felt
        assert_eq!(rec.fields[2].offset, 5); // active: 1 felt
        assert_eq!(rec.size, 6);
    }

    #[test]
    fn memory_layout_state_and_array() {
        let builder = ContractBuilder::new()
            .state("count", StateType::U64)
            .record("Rec", &[("a", FieldType::U64), ("b", FieldType::U64)])
            .array("items", "Rec", 100);

        assert_eq!(builder.states[0].addr, 0);
        // Record size = 2, state header = 1, aligned to 2 -> base = 2.
        assert_eq!(builder.arrays[0].base_addr, 2);
        assert_eq!(builder.arrays[0].record_size, 2);
    }

    #[test]
    fn compile_minimal_contract() {
        let contract = ContractBuilder::new()
            .state("x", StateType::U64)
            .function("init", |f| {
                let one = f.lit(1);
                f.store("x", one);
            })
            .build();

        assert!(!contract.bytecode.is_empty());
        assert!(matches!(
            contract.bytecode.last(),
            Some(Opcode::Halt) | Some(Opcode::Fail)
        ));

        // Execute with selector = 1.
        let selector = [Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let identity = [Felt::ZERO; 4];
        let params = [Felt::ZERO; 4];
        let input = VmInput {
            program: contract.bytecode,
            input_commitments: vec![selector, identity, params],
            initial_memory: vec![],
        };
        let output = execute(&input).expect("should execute");
        assert!(output.success);
        // Check that x (mem[0]) is now 1.
        assert_eq!(output.final_state.memory.data()[0], Felt::new(1));
    }

    #[test]
    fn unknown_selector_fails() {
        let contract = ContractBuilder::new()
            .function("only_func", |_f| {})
            .build();

        let selector = [Felt::new(99), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let input = VmInput {
            program: contract.bytecode,
            input_commitments: vec![selector, [Felt::ZERO; 4], [Felt::ZERO; 4]],
            initial_memory: vec![],
        };
        let result = execute(&input);
        assert!(matches!(
            result,
            Err(crate::vm::VmError::ExecutionFailed(_))
        ));
    }

    #[test]
    fn require_eq_scalar_passes() {
        let contract = ContractBuilder::new()
            .state("val", StateType::U64)
            .function("check", |f| {
                let val = f.load("val");
                let expected = f.lit(42);
                f.require_eq(val, expected);
            })
            .build();

        let selector = [Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let input = VmInput {
            program: contract.bytecode,
            input_commitments: vec![selector, [Felt::ZERO; 4], [Felt::ZERO; 4]],
            initial_memory: vec![Felt::new(42)],
        };
        let output = execute(&input).expect("should pass");
        assert!(output.success);
    }

    #[test]
    fn require_eq_scalar_fails() {
        let contract = ContractBuilder::new()
            .state("val", StateType::U64)
            .function("check", |f| {
                let val = f.load("val");
                let expected = f.lit(42);
                f.require_eq(val, expected);
            })
            .build();

        let selector = [Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let input = VmInput {
            program: contract.bytecode,
            input_commitments: vec![selector, [Felt::ZERO; 4], [Felt::ZERO; 4]],
            initial_memory: vec![Felt::new(99)],
        };
        let result = execute(&input);
        assert!(matches!(
            result,
            Err(crate::vm::VmError::ExecutionFailed(_))
        ));
    }

    #[test]
    fn identity_require_eq_passes() {
        let contract = ContractBuilder::new()
            .record("Rec", &[("owner", FieldType::Identity)])
            .array("items", "Rec", 10)
            .function("check_owner", |f| {
                let caller = f.caller();
                let idx = f.param(0);
                let rec = f.index("items", idx);
                let owner = f.get(&rec, "owner");
                f.require_eq(owner, caller);
            })
            .build();

        let caller_id = [Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)];
        let selector = [Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let params = [Felt::new(0), Felt::ZERO, Felt::ZERO, Felt::ZERO]; // index 0

        // Pre-populate memory with matching owner at address 0..3.
        let initial_memory = vec![Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)];

        let input = VmInput {
            program: contract.bytecode,
            input_commitments: vec![selector, caller_id, params],
            initial_memory,
        };
        let output = execute(&input).expect("should pass");
        assert!(output.success);
    }

    #[test]
    fn identity_require_eq_fails() {
        let contract = ContractBuilder::new()
            .record("Rec", &[("owner", FieldType::Identity)])
            .array("items", "Rec", 10)
            .function("check_owner", |f| {
                let caller = f.caller();
                let idx = f.param(0);
                let rec = f.index("items", idx);
                let owner = f.get(&rec, "owner");
                f.require_eq(owner, caller);
            })
            .build();

        let caller_id = [Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)];
        let selector = [Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let params = [Felt::new(0), Felt::ZERO, Felt::ZERO, Felt::ZERO];

        // Different owner.
        let initial_memory = vec![Felt::new(99), Felt::new(20), Felt::new(30), Felt::new(40)];

        let input = VmInput {
            program: contract.bytecode,
            input_commitments: vec![selector, caller_id, params],
            initial_memory,
        };
        let result = execute(&input);
        assert!(matches!(
            result,
            Err(crate::vm::VmError::ExecutionFailed(_))
        ));
    }

    #[test]
    fn state_store_and_load_roundtrip() {
        let contract = ContractBuilder::new()
            .state("counter", StateType::U64)
            .function("increment", |f| {
                let count = f.load("counter");
                let one = f.lit(1);
                let new_count = f.add(count, one);
                f.store("counter", new_count);
            })
            .build();

        let selector = [Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let identity = [Felt::ZERO; 4];
        let params = [Felt::ZERO; 4];

        // First call: 0 -> 1.
        let input = VmInput {
            program: contract.bytecode.clone(),
            input_commitments: vec![selector, identity, params],
            initial_memory: vec![Felt::new(0)],
        };
        let out1 = execute(&input).expect("should execute");
        assert_eq!(out1.final_state.memory.data()[0], Felt::new(1));

        // Second call: 1 -> 2.
        let input2 = VmInput {
            program: contract.bytecode,
            input_commitments: vec![selector, identity, params],
            initial_memory: out1.final_state.memory.data().to_vec(),
        };
        let out2 = execute(&input2).expect("should execute");
        assert_eq!(out2.final_state.memory.data()[0], Felt::new(2));
    }
}
