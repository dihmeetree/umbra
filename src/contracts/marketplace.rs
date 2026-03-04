//! Marketplace smart contract for the Umbra VM.
//!
//! Demonstrates listing, buying, and cancelling items using the register-based
//! VM over the Goldilocks field. State (listings) persists across calls via
//! the on-chain state hash mechanism.
//!
//! # Memory Layout
//!
//! - Address 0: `listing_count` (monotonic counter / next listing ID)
//! - Addresses 1-7: reserved
//! - Each listing record = 8 felts at address `8 + listing_id * 8`:
//!   - `+0..+3`: seller identity (4 felts)
//!   - `+4`: item_id
//!   - `+5`: price
//!   - `+6`: active flag (1 = active, 0 = sold/cancelled)
//!   - `+7`: reserved
//!
//! # Function Dispatch
//!
//! `input_commitments[0][0]` selects the function:
//! - `1` = list, `2` = buy, `3` = cancel

use crate::vm::{ContractCode, Opcode};
use crate::Hash;
use winterfell::math::fields::f64::BaseElement as Felt;
use winterfell::math::FieldElement;

// ── Constants ────────────────────────────────────────────────────────────

/// Function selector for the "list" operation.
pub const LIST_SELECTOR: u64 = 1;
/// Function selector for the "buy" operation.
pub const BUY_SELECTOR: u64 = 2;
/// Function selector for the "cancel" operation.
pub const CANCEL_SELECTOR: u64 = 3;

/// Size of the memory header (reserved addresses 0-7).
pub const HEADER_SIZE: u64 = 8;
/// Size of each listing record in memory (8 felts).
pub const RECORD_SIZE: u64 = 8;
/// Maximum number of listings supported.
pub const MAX_LISTINGS: u64 = 2000;

// Field offsets within a listing record.
const FIELD_ACTIVE: u64 = 6;

// ── Types ────────────────────────────────────────────────────────────────

/// A decoded marketplace listing.
#[derive(Debug, Clone, PartialEq)]
pub struct Listing {
    pub listing_id: u64,
    pub seller: [Felt; 4],
    pub item_id: Felt,
    pub price: Felt,
    pub active: bool,
}

// ── Bytecode Generation ──────────────────────────────────────────────────

/// Build the marketplace contract bytecode.
pub fn marketplace_contract() -> ContractCode {
    // Build each section separately, then compute jump targets.
    let dispatch = build_dispatch_section();
    let list = build_list_section();
    let mut buy = build_buy_section();
    let mut cancel = build_cancel_section();

    let list_start = dispatch.len() as u32;
    let buy_start = list_start + list.len() as u32;
    let cancel_start = buy_start + buy.len() as u32;

    // Patch dispatch jump targets (indices 5, 8, 11).
    let mut code = dispatch;
    patch_jump(&mut code, 5, list_start);
    patch_jump(&mut code, 8, buy_start);
    patch_jump(&mut code, 11, cancel_start);

    // Patch BUY internal CJump: buy[9] skips Fail at buy[10] -> buy_start + 11
    patch_jump(&mut buy, 9, buy_start + 11);

    // Patch CANCEL internal CJumps:
    // cancel[9] skips Fail at cancel[10] (active check) -> cancel_start + 11
    // cancel[26] skips Fail at cancel[27] (seller check) -> cancel_start + 28
    patch_jump(&mut cancel, 9, cancel_start + 11);
    patch_jump(&mut cancel, 26, cancel_start + 28);

    code.extend(list);
    code.extend(buy);
    code.extend(cancel);

    ContractCode::new(code).expect("marketplace bytecode is valid")
}

/// Build the dispatch preamble (13 instructions).
fn build_dispatch_section() -> Vec<Opcode> {
    use Opcode::*;
    vec![
        LoadInput { dst: 0, index: 0 }, // 0: r0..r3 = selector
        LoadInput { dst: 4, index: 1 }, // 1: r4..r7 = identity
        LoadInput { dst: 8, index: 2 }, // 2: r8..r11 = parameters
        Const {
            dst: 14,
            value: LIST_SELECTOR,
        }, // 3
        Eq {
            dst: 13,
            lhs: 0,
            rhs: 14,
        }, // 4
        CJump {
            cond: 13,
            target: 0,
        }, // 5: -> LIST (patched)
        Const {
            dst: 14,
            value: BUY_SELECTOR,
        }, // 6
        Eq {
            dst: 13,
            lhs: 0,
            rhs: 14,
        }, // 7
        CJump {
            cond: 13,
            target: 0,
        }, // 8: -> BUY (patched)
        Const {
            dst: 14,
            value: CANCEL_SELECTOR,
        }, // 9
        Eq {
            dst: 13,
            lhs: 0,
            rhs: 14,
        }, // 10
        CJump {
            cond: 13,
            target: 0,
        }, // 11: -> CANCEL (patched)
        Fail,                           // 12: unknown selector
    ]
}

/// Build the LIST handler (~24 instructions).
fn build_list_section() -> Vec<Opcode> {
    use Opcode::*;
    vec![
        // Load listing_count from mem[0]
        Const { dst: 12, value: 0 }, // 0
        Load { dst: 15, addr: 12 },  // 1: r15 = listing_count
        // Compute base = 8 + listing_count * 8
        Const {
            dst: 14,
            value: RECORD_SIZE,
        }, // 2: r14 = 8
        Mul {
            dst: 13,
            lhs: 15,
            rhs: 14,
        }, // 3: r13 = count * 8
        Const {
            dst: 14,
            value: HEADER_SIZE,
        }, // 4: r14 = 8
        Add {
            dst: 12,
            lhs: 14,
            rhs: 13,
        }, // 5: r12 = 8 + count*8 = base
        // Store seller identity (r4..r7) at base+0..base+3
        Store { src: 4, addr: 12 },  // 6: mem[base+0] = seller_0
        Const { dst: 14, value: 1 }, // 7
        Add {
            dst: 12,
            lhs: 12,
            rhs: 14,
        }, // 8: r12 = base+1
        Store { src: 5, addr: 12 },  // 9: mem[base+1] = seller_1
        Add {
            dst: 12,
            lhs: 12,
            rhs: 14,
        }, // 10: r12 = base+2
        Store { src: 6, addr: 12 },  // 11: mem[base+2] = seller_2
        Add {
            dst: 12,
            lhs: 12,
            rhs: 14,
        }, // 12: r12 = base+3
        Store { src: 7, addr: 12 },  // 13: mem[base+3] = seller_3
        // Store item_id (r8) at base+4
        Add {
            dst: 12,
            lhs: 12,
            rhs: 14,
        }, // 14: r12 = base+4
        Store { src: 8, addr: 12 }, // 15: mem[base+4] = item_id
        // Store price (r9) at base+5
        Add {
            dst: 12,
            lhs: 12,
            rhs: 14,
        }, // 16: r12 = base+5
        Store { src: 9, addr: 12 }, // 17: mem[base+5] = price
        // Store active = 1 at base+6
        Add {
            dst: 12,
            lhs: 12,
            rhs: 14,
        }, // 18: r12 = base+6
        Store { src: 14, addr: 12 }, // 19: mem[base+6] = 1 (r14=1)
        // Increment listing_count
        Add {
            dst: 15,
            lhs: 15,
            rhs: 14,
        }, // 20: r15 = count + 1
        Const { dst: 12, value: 0 }, // 21
        Store { src: 15, addr: 12 }, // 22: mem[0] = count + 1
        // Emit listing receipt
        EmitOutput { src: 4 }, // 23: emit [seller_0..seller_3]
        Halt,                  // 24
    ]
}

/// Build the BUY handler (~27 instructions).
fn build_buy_section() -> Vec<Opcode> {
    use Opcode::*;
    vec![
        // Compute base = 8 + listing_id * 8  (r8 = listing_id)
        Const {
            dst: 14,
            value: RECORD_SIZE,
        }, // 0
        Mul {
            dst: 13,
            lhs: 8,
            rhs: 14,
        }, // 1: r13 = listing_id * 8
        Const {
            dst: 14,
            value: HEADER_SIZE,
        }, // 2
        Add {
            dst: 12,
            lhs: 14,
            rhs: 13,
        }, // 3: r12 = base
        // Load active flag at base+6
        Const {
            dst: 14,
            value: FIELD_ACTIVE,
        }, // 4
        Add {
            dst: 13,
            lhs: 12,
            rhs: 14,
        }, // 5: r13 = base+6
        Load { dst: 15, addr: 13 }, // 6: r15 = active
        // Check active == 1
        Const { dst: 14, value: 1 }, // 7
        Eq {
            dst: 13,
            lhs: 15,
            rhs: 14,
        }, // 8: r13 = (active==1)?
        CJump {
            cond: 13,
            target: 0,
        }, // 9: skip Fail (patched)
        Fail,                        // 10: listing not active
        // Load seller identity from base+0..base+3 into r0..r3
        Load { dst: 0, addr: 12 },   // 11: r0 = mem[base+0]
        Const { dst: 14, value: 1 }, // 12
        Add {
            dst: 13,
            lhs: 12,
            rhs: 14,
        }, // 13: r13 = base+1
        Load { dst: 1, addr: 13 },   // 14: r1 = mem[base+1]
        Add {
            dst: 13,
            lhs: 13,
            rhs: 14,
        }, // 15: r13 = base+2
        Load { dst: 2, addr: 13 },   // 16: r2 = mem[base+2]
        Add {
            dst: 13,
            lhs: 13,
            rhs: 14,
        }, // 17: r13 = base+3
        Load { dst: 3, addr: 13 },   // 18: r3 = mem[base+3]
        // Mark inactive: mem[base+6] = 0
        Const {
            dst: 14,
            value: FIELD_ACTIVE,
        }, // 19
        Add {
            dst: 13,
            lhs: 12,
            rhs: 14,
        }, // 20: r13 = base+6
        Const { dst: 15, value: 0 }, // 21
        Store { src: 15, addr: 13 }, // 22: mem[base+6] = 0
        // Emit buyer receipt and listing nullifier
        EmitOutput { src: 4 },    // 23: emit buyer identity
        EmitNullifier { src: 0 }, // 24: emit seller identity as nullifier
        Halt,                     // 25
    ]
}

/// Build the CANCEL handler (~32 instructions).
fn build_cancel_section() -> Vec<Opcode> {
    use Opcode::*;
    vec![
        // Compute base = 8 + listing_id * 8  (r8 = listing_id)
        Const {
            dst: 14,
            value: RECORD_SIZE,
        }, // 0
        Mul {
            dst: 13,
            lhs: 8,
            rhs: 14,
        }, // 1
        Const {
            dst: 14,
            value: HEADER_SIZE,
        }, // 2
        Add {
            dst: 12,
            lhs: 14,
            rhs: 13,
        }, // 3: r12 = base
        // Load active flag at base+6
        Const {
            dst: 14,
            value: FIELD_ACTIVE,
        }, // 4
        Add {
            dst: 13,
            lhs: 12,
            rhs: 14,
        }, // 5: r13 = base+6
        Load { dst: 15, addr: 13 }, // 6: r15 = active
        // Check active == 1
        Const { dst: 14, value: 1 }, // 7
        Eq {
            dst: 13,
            lhs: 15,
            rhs: 14,
        }, // 8
        CJump {
            cond: 13,
            target: 0,
        }, // 9: skip Fail (patched)
        Fail,                        // 10: listing not active
        // Load seller from base+0..base+3 into r0..r3
        Load { dst: 0, addr: 12 },   // 11: r0 = mem[base+0]
        Const { dst: 14, value: 1 }, // 12
        Add {
            dst: 13,
            lhs: 12,
            rhs: 14,
        }, // 13
        Load { dst: 1, addr: 13 },   // 14
        Add {
            dst: 13,
            lhs: 13,
            rhs: 14,
        }, // 15
        Load { dst: 2, addr: 13 },   // 16
        Add {
            dst: 13,
            lhs: 13,
            rhs: 14,
        }, // 17
        Load { dst: 3, addr: 13 },   // 18
        // Compare stored seller (r0..r3) with input seller (r4..r7)
        Eq {
            dst: 13,
            lhs: 0,
            rhs: 4,
        }, // 19
        Eq {
            dst: 15,
            lhs: 1,
            rhs: 5,
        }, // 20
        Mul {
            dst: 13,
            lhs: 13,
            rhs: 15,
        }, // 21: AND
        Eq {
            dst: 15,
            lhs: 2,
            rhs: 6,
        }, // 22
        Mul {
            dst: 13,
            lhs: 13,
            rhs: 15,
        }, // 23: AND
        Eq {
            dst: 15,
            lhs: 3,
            rhs: 7,
        }, // 24
        Mul {
            dst: 13,
            lhs: 13,
            rhs: 15,
        }, // 25: AND (all 4 match?)
        CJump {
            cond: 13,
            target: 0,
        }, // 26: skip Fail (patched)
        Fail, // 27: seller mismatch
        // Mark inactive
        Const {
            dst: 14,
            value: FIELD_ACTIVE,
        }, // 28
        Add {
            dst: 13,
            lhs: 12,
            rhs: 14,
        }, // 29
        Const { dst: 15, value: 0 }, // 30
        Store { src: 15, addr: 13 }, // 31: mem[base+6] = 0
        Halt,                        // 32
    ]
}

fn patch_jump(code: &mut [Opcode], index: usize, target: u32) {
    match &mut code[index] {
        Opcode::CJump { target: t, .. } => *t = target,
        Opcode::Jump { target: t } => *t = target,
        _ => panic!("not a jump at index {index}"),
    }
}

// ── Function Hashes ──────────────────────────────────────────────────────

/// Function hash for the "list" operation.
pub fn list_function_hash() -> Hash {
    crate::hash_domain(b"umbra.marketplace", b"list")
}

/// Function hash for the "buy" operation.
pub fn buy_function_hash() -> Hash {
    crate::hash_domain(b"umbra.marketplace", b"buy")
}

/// Function hash for the "cancel" operation.
pub fn cancel_function_hash() -> Hash {
    crate::hash_domain(b"umbra.marketplace", b"cancel")
}

// ── Client-Side Call Builders ────────────────────────────────────────────

/// Build inputs for a "list" operation.
pub fn build_list_inputs(seller_id: [Felt; 4], item_id: u64, price: u64) -> (Hash, Vec<[Felt; 4]>) {
    let selector = [Felt::new(LIST_SELECTOR), Felt::ZERO, Felt::ZERO, Felt::ZERO];
    let params = [Felt::new(item_id), Felt::new(price), Felt::ZERO, Felt::ZERO];
    (list_function_hash(), vec![selector, seller_id, params])
}

/// Build inputs for a "buy" operation.
pub fn build_buy_inputs(buyer_id: [Felt; 4], listing_id: u64) -> (Hash, Vec<[Felt; 4]>) {
    let selector = [Felt::new(BUY_SELECTOR), Felt::ZERO, Felt::ZERO, Felt::ZERO];
    let params = [Felt::new(listing_id), Felt::ZERO, Felt::ZERO, Felt::ZERO];
    (buy_function_hash(), vec![selector, buyer_id, params])
}

/// Build inputs for a "cancel" operation.
pub fn build_cancel_inputs(seller_id: [Felt; 4], listing_id: u64) -> (Hash, Vec<[Felt; 4]>) {
    let selector = [
        Felt::new(CANCEL_SELECTOR),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    let params = [Felt::new(listing_id), Felt::ZERO, Felt::ZERO, Felt::ZERO];
    (cancel_function_hash(), vec![selector, seller_id, params])
}

// ── Memory Readers ───────────────────────────────────────────────────────

/// Get the current listing count from contract memory.
pub fn listing_count(memory: &[Felt]) -> u64 {
    if memory.is_empty() {
        return 0;
    }
    memory[0].as_int()
}

/// Read a listing from contract memory. Returns None if out of range.
pub fn read_listing(memory: &[Felt], listing_id: u64) -> Option<Listing> {
    let count = listing_count(memory);
    if listing_id >= count {
        return None;
    }
    let base = (HEADER_SIZE + listing_id * RECORD_SIZE) as usize;
    if base + 7 >= memory.len() {
        return None;
    }
    Some(Listing {
        listing_id,
        seller: [
            memory[base],
            memory[base + 1],
            memory[base + 2],
            memory[base + 3],
        ],
        item_id: memory[base + 4],
        price: memory[base + 5],
        active: memory[base + 6] != Felt::ZERO,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::{execute, VmInput};

    fn seller_id() -> [Felt; 4] {
        [Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]
    }

    fn buyer_id() -> [Felt; 4] {
        [Felt::new(50), Felt::new(60), Felt::new(70), Felt::new(80)]
    }

    fn run_marketplace(
        input_commitments: Vec<[Felt; 4]>,
        initial_memory: Vec<Felt>,
    ) -> crate::vm::VmOutput {
        let contract = marketplace_contract();
        let input = VmInput {
            program: contract.bytecode,
            input_commitments,
            initial_memory,
        };
        execute(&input).expect("VM execution should not error")
    }

    fn run_marketplace_expect_fail(input_commitments: Vec<[Felt; 4]>, initial_memory: Vec<Felt>) {
        let contract = marketplace_contract();
        let input = VmInput {
            program: contract.bytecode,
            input_commitments,
            initial_memory,
        };
        let result = execute(&input);
        assert!(
            matches!(result, Err(crate::vm::VmError::ExecutionFailed(_))),
            "expected ExecutionFailed, got Ok(..)"
        );
    }

    /// Build initial memory with a pre-populated listing for testing.
    fn memory_with_listing(
        listing_id: u64,
        seller: [Felt; 4],
        item_id: u64,
        price: u64,
        active: bool,
    ) -> Vec<Felt> {
        let mut mem = vec![Felt::ZERO; 100];
        mem[0] = Felt::new(listing_id + 1); // listing_count
        let base = (HEADER_SIZE + listing_id * RECORD_SIZE) as usize;
        mem[base] = seller[0];
        mem[base + 1] = seller[1];
        mem[base + 2] = seller[2];
        mem[base + 3] = seller[3];
        mem[base + 4] = Felt::new(item_id);
        mem[base + 5] = Felt::new(price);
        mem[base + 6] = if active { Felt::new(1) } else { Felt::ZERO };
        mem
    }

    #[test]
    fn marketplace_contract_creation() {
        let c1 = marketplace_contract();
        let c2 = marketplace_contract();
        assert_eq!(c1.id, c2.id, "contract ID should be deterministic");
        assert!(!c1.bytecode.is_empty());
    }

    #[test]
    fn list_item() {
        let (_, inputs) = build_list_inputs(seller_id(), 100, 500);
        let output = run_marketplace(inputs, vec![]);
        assert!(output.success, "list should succeed");
        let mem = output.final_state.memory.data();
        assert_eq!(mem[0].as_int(), 1, "listing_count should be 1");
        let base = HEADER_SIZE as usize;
        assert_eq!(mem[base], seller_id()[0]);
        assert_eq!(mem[base + 1], seller_id()[1]);
        assert_eq!(mem[base + 2], seller_id()[2]);
        assert_eq!(mem[base + 3], seller_id()[3]);
        assert_eq!(mem[base + 4].as_int(), 100, "item_id");
        assert_eq!(mem[base + 5].as_int(), 500, "price");
        assert_eq!(mem[base + 6].as_int(), 1, "active");
        assert_eq!(output.output_commitments.len(), 1, "should emit one output");
    }

    #[test]
    fn list_multiple_items() {
        // First listing
        let (_, inputs1) = build_list_inputs(seller_id(), 100, 500);
        let out1 = run_marketplace(inputs1, vec![]);
        assert!(out1.success);

        // Second listing using first listing's final memory
        let other_seller = [Felt::new(11), Felt::new(21), Felt::new(31), Felt::new(41)];
        let (_, inputs2) = build_list_inputs(other_seller, 200, 1000);
        let out2 = run_marketplace(inputs2, out1.final_state.memory.data().to_vec());
        assert!(out2.success);

        let mem = out2.final_state.memory.data();
        assert_eq!(mem[0].as_int(), 2, "listing_count should be 2");
        // First listing at base=8
        assert_eq!(mem[8], seller_id()[0]);
        assert_eq!(mem[12].as_int(), 100); // item_id
                                           // Second listing at base=16
        assert_eq!(mem[16], other_seller[0]);
        assert_eq!(mem[20].as_int(), 200); // item_id
    }

    #[test]
    fn buy_active_listing() {
        let mem = memory_with_listing(0, seller_id(), 100, 500, true);
        let (_, inputs) = build_buy_inputs(buyer_id(), 0);
        let output = run_marketplace(inputs, mem);
        assert!(output.success, "buy should succeed");
        let final_mem = output.final_state.memory.data();
        let base = HEADER_SIZE as usize;
        assert_eq!(
            final_mem[base + 6].as_int(),
            0,
            "listing should be inactive"
        );
        assert_eq!(output.output_commitments.len(), 1, "buyer receipt");
        assert_eq!(output.emitted_nullifiers.len(), 1, "listing nullifier");
    }

    #[test]
    fn buy_inactive_listing_fails() {
        let mem = memory_with_listing(0, seller_id(), 100, 500, false);
        let (_, inputs) = build_buy_inputs(buyer_id(), 0);
        run_marketplace_expect_fail(inputs, mem);
    }

    #[test]
    fn cancel_by_seller() {
        let mem = memory_with_listing(0, seller_id(), 100, 500, true);
        let (_, inputs) = build_cancel_inputs(seller_id(), 0);
        let output = run_marketplace(inputs, mem);
        assert!(output.success, "cancel by seller should succeed");
        let final_mem = output.final_state.memory.data();
        let base = HEADER_SIZE as usize;
        assert_eq!(
            final_mem[base + 6].as_int(),
            0,
            "listing should be inactive"
        );
    }

    #[test]
    fn cancel_by_wrong_seller_fails() {
        let mem = memory_with_listing(0, seller_id(), 100, 500, true);
        let wrong_seller = [Felt::new(99), Felt::new(98), Felt::new(97), Felt::new(96)];
        let (_, inputs) = build_cancel_inputs(wrong_seller, 0);
        run_marketplace_expect_fail(inputs, mem);
    }

    #[test]
    fn unknown_selector_fails() {
        let selector = [Felt::new(99), Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let identity = [Felt::ZERO; 4];
        let params = [Felt::ZERO; 4];
        run_marketplace_expect_fail(vec![selector, identity, params], vec![]);
    }

    #[test]
    fn buy_then_buy_again_fails() {
        let mem = memory_with_listing(0, seller_id(), 100, 500, true);
        let (_, inputs) = build_buy_inputs(buyer_id(), 0);
        let out1 = run_marketplace(inputs, mem);
        assert!(out1.success, "first buy should succeed");

        // Try buying again with updated memory
        let (_, inputs2) = build_buy_inputs(buyer_id(), 0);
        run_marketplace_expect_fail(inputs2, out1.final_state.memory.data().to_vec());
    }

    #[test]
    fn list_then_cancel_then_buy_fails() {
        // List
        let (_, list_inputs) = build_list_inputs(seller_id(), 100, 500);
        let list_out = run_marketplace(list_inputs, vec![]);
        assert!(list_out.success);

        // Cancel
        let (_, cancel_inputs) = build_cancel_inputs(seller_id(), 0);
        let cancel_out =
            run_marketplace(cancel_inputs, list_out.final_state.memory.data().to_vec());
        assert!(cancel_out.success);

        // Buy should fail
        let (_, buy_inputs) = build_buy_inputs(buyer_id(), 0);
        run_marketplace_expect_fail(buy_inputs, cancel_out.final_state.memory.data().to_vec());
    }

    #[test]
    fn function_hashes_are_distinct() {
        let list = list_function_hash();
        let buy = buy_function_hash();
        let cancel = cancel_function_hash();
        assert_ne!(list, buy);
        assert_ne!(buy, cancel);
        assert_ne!(list, cancel);
    }

    #[test]
    fn build_list_inputs_format() {
        let (hash, inputs) = build_list_inputs(seller_id(), 42, 100);
        assert_eq!(hash, list_function_hash());
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs[0][0], Felt::new(LIST_SELECTOR));
        assert_eq!(inputs[1], seller_id());
        assert_eq!(inputs[2][0].as_int(), 42); // item_id
        assert_eq!(inputs[2][1].as_int(), 100); // price
    }

    #[test]
    fn build_buy_inputs_format() {
        let (hash, inputs) = build_buy_inputs(buyer_id(), 5);
        assert_eq!(hash, buy_function_hash());
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs[0][0], Felt::new(BUY_SELECTOR));
        assert_eq!(inputs[1], buyer_id());
        assert_eq!(inputs[2][0].as_int(), 5); // listing_id
    }

    #[test]
    fn build_cancel_inputs_format() {
        let (hash, inputs) = build_cancel_inputs(seller_id(), 3);
        assert_eq!(hash, cancel_function_hash());
        assert_eq!(inputs.len(), 3);
        assert_eq!(inputs[0][0], Felt::new(CANCEL_SELECTOR));
        assert_eq!(inputs[1], seller_id());
        assert_eq!(inputs[2][0].as_int(), 3); // listing_id
    }

    #[test]
    fn read_listing_from_memory() {
        let mem = memory_with_listing(0, seller_id(), 42, 999, true);
        let listing = read_listing(&mem, 0).unwrap();
        assert_eq!(listing.listing_id, 0);
        assert_eq!(listing.seller, seller_id());
        assert_eq!(listing.item_id.as_int(), 42);
        assert_eq!(listing.price.as_int(), 999);
        assert!(listing.active);
    }

    #[test]
    fn read_listing_out_of_range() {
        let mem = memory_with_listing(0, seller_id(), 42, 999, true);
        assert!(read_listing(&mem, 5).is_none());
    }

    #[test]
    fn listing_count_empty() {
        assert_eq!(listing_count(&[]), 0);
        assert_eq!(listing_count(&[Felt::ZERO; 10]), 0);
    }

    #[test]
    fn list_with_stark_proof() {
        let contract = marketplace_contract();
        let (function_hash, input_commitments) = build_list_inputs(seller_id(), 100, 500);
        let proof_options = winterfell::ProofOptions::new(
            42,
            8,
            10,
            winterfell::FieldExtension::Cubic,
            8,
            255,
            winterfell::BatchingMethod::Linear,
            winterfell::BatchingMethod::Linear,
        );
        let result = crate::vm::build_contract_call(
            &contract,
            function_hash,
            input_commitments,
            vec![],
            proof_options,
        );
        assert!(
            result.is_ok(),
            "STARK proof generation failed: {:?}",
            result.err()
        );
        let call = result.unwrap();
        assert_eq!(call.contract_id, contract.id);
        assert!(!call.execution_proof.proof_bytes.is_empty());
        assert_eq!(call.output_commitments.len(), 1);
    }
}
