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

use crate::contracts::dsl::{ContractBuilder, FieldType, StateType};
use crate::vm::ContractCode;
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

// ── Contract Definition ──────────────────────────────────────────────────

/// Build the marketplace contract bytecode using the high-level DSL.
pub fn marketplace_contract() -> ContractCode {
    ContractBuilder::new()
        .state("listing_count", StateType::U64)
        .record(
            "Listing",
            &[
                ("seller", FieldType::Identity), // 4 felts
                ("item_id", FieldType::U64),
                ("price", FieldType::U64),
                ("active", FieldType::Bool),
                ("_reserved", FieldType::U64),
            ],
        )
        .array("listings", "Listing", MAX_LISTINGS)
        .function("list", |f| {
            let seller = f.caller();
            let item_id = f.param(0);
            let price = f.param(1);

            let count = f.load("listing_count");
            let rec = f.index("listings", count);
            f.set(&rec, "seller", seller);
            f.set(&rec, "item_id", item_id);
            f.set(&rec, "price", price);
            f.set_const(&rec, "active", 1);

            let one = f.lit(1);
            let new_count = f.add(count, one);
            f.store("listing_count", new_count);
            f.emit(seller);
        })
        .function("buy", |f| {
            let _buyer = f.caller();
            let listing_id = f.param(0);

            let rec = f.index("listings", listing_id);
            let active = f.get(&rec, "active");
            let one = f.lit(1);
            f.require_eq(active, one);
            f.set_const(&rec, "active", 0);

            let seller = f.get(&rec, "seller");
            f.emit(seller);
            f.nullify(seller);
        })
        .function("cancel", |f| {
            let seller = f.caller();
            let listing_id = f.param(0);

            let rec = f.index("listings", listing_id);
            let stored_seller = f.get(&rec, "seller");
            f.require_eq(stored_seller, seller);
            let active = f.get(&rec, "active");
            let one = f.lit(1);
            f.require_eq(active, one);
            f.set_const(&rec, "active", 0);
        })
        .build()
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
