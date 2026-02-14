//! AIR for the spend STARK proof.
//!
//! Proves in zero knowledge:
//! 1. Nullifier is correctly derived: Rescue(spend_auth, commitment) == nullifier
//! 2. A commitment exists in the Merkle tree with the given root
//! 3. proof_link is correctly derived: Rescue(commitment, link_nonce) == proof_link
//!
//! The commitment is a **private witness** — it never appears in public inputs.
//! Instead, the proof_link (a random-nonce hash of the commitment) is public,
//! preventing graph analysis between inputs and outputs.
//!
//! Trace layout (SPEND_TRACE_WIDTH = 30 columns):
//!
//! Columns 0-11:  Rescue Prime state (12 elements)
//! Columns 12-23: Rescue Prime mid-state (after forward half-round)
//! Column  24:    Merkle path bit (0 or 1, constant within each block)
//! Column  25:    Chain flag (1 = chain digest from previous block, 0 = no chain)
//! Columns 26-29: Commitment register (constant throughout entire trace)
//!
//! Block layout:
//! Block 0:                        Nullifier hash
//! Blocks 1..MERKLE_DEPTH:         Merkle path verification (chained)
//! Block MERKLE_DEPTH+1:           Proof_link hash
//! Remaining blocks:               Padding
//!
//! Transition constraints (52 total):
//! 0-11:  Forward Rescue half-round (degree 7)
//! 12-23: Inverse Rescue half-round (degree 7)
//! 24:    path_bit constant within blocks (degree 1)
//! 25:    chain_flag constant within blocks (degree 1)
//! 26:    path_bit boolean at first rows (degree 2)
//! 27:    chain_flag boolean at first rows (degree 2)
//! 28-31: Merkle chain: digest from prev block enters next block's rate (degree 3)
//! 32-35: Capacity at chained Merkle blocks: [MERGE_DOMAIN, 0, 0, 0] (degree 2)
//! 36-39: Commitment register constancy (degree 1, no periodic)
//! 40-43: Nullifier binding: state[8..12] = reg at block 0 (degree 1, period=trace_len)
//! 44-47: Merkle leaf binding: state[4/8..] = reg at block 1 (degree 2, period=trace_len)
//! 48-51: Proof_link binding: state[4..8] = reg at proof_link block (degree 1, period=trace_len)

use winterfell::math::FieldElement;
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use super::convert::{exp7, Felt};
use super::rescue;
use super::types::SpendPublicInputs;

/// Trace width for the spend AIR.
pub const SPEND_TRACE_WIDTH: usize = 30;

/// First column index of the commitment register.
const REG_COL_START: usize = 26;

/// Rows per hash.
pub const HASH_CYCLE: usize = rescue::HASH_CYCLE_LEN;

/// Merkle tree depth (supports ~1M commitments).
pub const MERKLE_DEPTH: usize = 20;

/// Domain separator for nullifier hashing.
const NULLIFIER_DOMAIN: u64 = 0x6E756C6C00000000;

/// Domain separator for Merkle merge hashing.
const MERGE_DOMAIN: u64 = rescue::MERGE_DOMAIN;

/// Block index of the proof_link hash.
const PROOF_LINK_BLOCK: usize = 1 + MERKLE_DEPTH; // = 21

/// Total blocks: 1 (nullifier) + MERKLE_DEPTH (path) + 1 (proof_link) = 22
const TOTAL_REAL_BLOCKS: usize = 1 + MERKLE_DEPTH + 1;

/// Index of periodic columns for binding constraints.
/// These come after the standard 26 periodic columns (hash_flag, ARK1×12, ARK2×12, first_row_flag).
const PERIODIC_NULLIFIER_BIND: usize = 26;
const PERIODIC_MERKLE_BIND: usize = 27;
const PERIODIC_PROOF_LINK_BIND: usize = 28;

/// The Spend AIR definition.
pub struct SpendAir {
    context: AirContext<Felt>,
    pub_inputs: SpendPublicInputs,
    num_hash_blocks: usize,
    trace_length: usize,
}

impl Air for SpendAir {
    type BaseField = Felt;
    type PublicInputs = SpendPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let trace_length = trace_info.length();

        // All constraints use periodic columns (cycle 8) and must declare them.
        // 24 Rescue constraints: degree 7 × hash_flag (cycle 8)
        let mut degrees = vec![TransitionConstraintDegree::with_cycles(7, vec![8]); 24];
        // path_bit constant: hash_flag × degree 1
        degrees.push(TransitionConstraintDegree::with_cycles(1, vec![8]));
        // chain_flag constant: hash_flag × degree 1
        degrees.push(TransitionConstraintDegree::with_cycles(1, vec![8]));
        // path_bit boolean: first_row_flag × degree 2
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![8]));
        // chain_flag boolean: first_row_flag × degree 2
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![8]));
        // Merkle chain: (1-hash_flag) × degree 3 (next[25]*next[24]*next[...])
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::with_cycles(3, vec![8]));
        }
        // Capacity at chained Merkle blocks: (1-hash_flag) × degree 2
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![8]));
        }
        // Commitment register constancy: degree 1, no periodic columns
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // Nullifier binding: periodic(trace_len) × degree 1
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                1,
                vec![trace_length],
            ));
        }
        // Merkle leaf binding: periodic(trace_len) × degree 2 (path_bit interaction)
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                2,
                vec![trace_length],
            ));
        }
        // Proof_link binding: periodic(trace_len) × degree 1
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                1,
                vec![trace_length],
            ));
        }

        let num_hash_blocks = trace_length / HASH_CYCLE;
        let num_padding_blocks = num_hash_blocks - TOTAL_REAL_BLOCKS;

        // Assertions:
        // - 4 nullifier domain capacity at row 0
        // - 4 nullifier digest at row 7
        // - 4 first Merkle block capacity (MERGE_DOMAIN) at block 1
        // - 4 Merkle root at last Merkle block's final row
        // - 4 proof_link domain capacity at proof_link block first row
        // - 4 proof_link digest at proof_link block final row
        // - 1 chain_flag = 0 at block 0 (nullifier)
        // - 1 chain_flag = 0 at block 1 (first Merkle level)
        // - (MERKLE_DEPTH - 1) chain_flag = 1 at blocks 2..MERKLE_DEPTH
        // - 1 chain_flag = 0 at proof_link block
        // - 1 path_bit = 1 at proof_link block
        // - num_padding chain_flag = 0 at padding blocks
        // - num_padding path_bit = 1 at padding blocks
        let num_assertions =
            4 + 4 + 4 + 4 + 4 + 4 + 2 + (MERKLE_DEPTH - 1) + 2 + num_padding_blocks * 2;

        let context = AirContext::new(trace_info, degrees, num_assertions, options);

        SpendAir {
            context,
            pub_inputs,
            num_hash_blocks,
            trace_length,
        }
    }

    fn context(&self) -> &AirContext<Felt> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Felt>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        let hash_flag = periodic_values[0];
        let ark1 = &periodic_values[1..13];
        let ark2 = &periodic_values[13..25];
        let first_row_flag = periodic_values[25];
        let nullifier_bind_flag = periodic_values[PERIODIC_NULLIFIER_BIND];
        let merkle_bind_flag = periodic_values[PERIODIC_MERKLE_BIND];
        let proof_link_bind_flag = periodic_values[PERIODIC_PROOF_LINK_BIND];

        // Forward Rescue half-round constraints (12)
        let mds = rescue::mds();
        for j in 0..12 {
            let mut expected = E::ZERO;
            for k in 0..12 {
                let sbox_out = exp7(current[k]);
                expected += E::from(mds[j][k]) * sbox_out;
            }
            expected += ark1[j];
            result[j] = hash_flag * (current[12 + j] - expected);
        }

        // Inverse Rescue half-round constraints (12)
        let inv_mds = rescue::inv_mds();
        for j in 0..12 {
            let mut y = E::ZERO;
            for k in 0..12 {
                y += E::from(inv_mds[j][k]) * (next[k] - ark2[k]);
            }
            let lhs = exp7(y);
            result[12 + j] = hash_flag * (lhs - current[12 + j]);
        }

        // Constraint 24: path_bit constant within blocks
        result[24] = hash_flag * (next[24] - current[24]);

        // Constraint 25: chain_flag constant within blocks
        result[25] = hash_flag * (next[25] - current[25]);

        // Constraint 26: path_bit is boolean at first rows
        result[26] = first_row_flag * current[24] * (current[24] - E::ONE);

        // Constraint 27: chain_flag is boolean at first rows
        result[27] = first_row_flag * current[25] * (current[25] - E::ONE);

        // Constraints 28-31: Merkle chain
        let boundary_flag = E::ONE - hash_flag;
        for j in 0..4 {
            let digest_target =
                next[4 + j] + next[24] * (next[8 + j] - next[4 + j]) - current[4 + j];
            result[28 + j] = boundary_flag * next[25] * digest_target;
        }

        // Constraints 32-35: Capacity at chained Merkle block starts
        // state[0] must equal MERGE_DOMAIN; state[1..4] must be zero.
        result[32] = boundary_flag * next[25] * (next[0] - E::from(Felt::new(MERGE_DOMAIN)));
        for j in 1..4 {
            result[32 + j] = boundary_flag * next[25] * next[j];
        }

        // Constraints 36-39: Commitment register constancy
        // These columns must be the same at every row transition.
        for j in 0..4 {
            result[36 + j] = next[REG_COL_START + j] - current[REG_COL_START + j];
        }

        // Constraints 40-43: Nullifier binding
        // At block 0 row 0: state[8+j] must equal commitment_reg[j]
        for j in 0..4 {
            result[40 + j] = nullifier_bind_flag * (current[8 + j] - current[REG_COL_START + j]);
        }

        // Constraints 44-47: Merkle leaf binding
        // At block 1 first row: commitment_reg appears at state[4..8] or state[8..12]
        // depending on path_bit (same formula as Merkle chain digest positioning)
        for j in 0..4 {
            let positioned = current[4 + j] + current[24] * (current[8 + j] - current[4 + j]);
            result[44 + j] = merkle_bind_flag * (positioned - current[REG_COL_START + j]);
        }

        // Constraints 48-51: Proof_link binding
        // At proof_link block first row: state[4+j] must equal commitment_reg[j]
        for j in 0..4 {
            result[48 + j] = proof_link_bind_flag * (current[4 + j] - current[REG_COL_START + j]);
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let mut assertions = vec![
            // Nullifier block (block 0): capacity/domain at row 0
            Assertion::single(0, 0, Felt::new(NULLIFIER_DOMAIN)),
            Assertion::single(1, 0, Felt::ZERO),
            Assertion::single(2, 0, Felt::ZERO),
            Assertion::single(3, 0, Felt::ZERO),
        ];

        // Nullifier digest at row 7
        for j in 0..4 {
            assertions.push(Assertion::single(
                4 + j,
                HASH_CYCLE - 1,
                self.pub_inputs.nullifier[j],
            ));
        }

        // First Merkle block (block 1): capacity = [MERGE_DOMAIN, 0, 0, 0]
        // (Blocks 2..MERKLE_DEPTH are enforced by constraint 32 via chain_flag.)
        let merkle1_first_row = HASH_CYCLE;
        assertions.push(Assertion::single(
            0,
            merkle1_first_row,
            Felt::new(MERGE_DOMAIN),
        ));
        assertions.push(Assertion::single(1, merkle1_first_row, Felt::ZERO));
        assertions.push(Assertion::single(2, merkle1_first_row, Felt::ZERO));
        assertions.push(Assertion::single(3, merkle1_first_row, Felt::ZERO));

        // Merkle root at the last Merkle block's final row
        let last_merkle_row = (1 + MERKLE_DEPTH) * HASH_CYCLE - 1;
        for j in 0..4 {
            assertions.push(Assertion::single(
                4 + j,
                last_merkle_row,
                self.pub_inputs.merkle_root[j],
            ));
        }

        // Proof_link block (block PROOF_LINK_BLOCK): capacity/domain
        let pl_first_row = PROOF_LINK_BLOCK * HASH_CYCLE;
        assertions.push(Assertion::single(
            0,
            pl_first_row,
            Felt::new(rescue::PROOF_LINK_DOMAIN),
        ));
        assertions.push(Assertion::single(1, pl_first_row, Felt::ZERO));
        assertions.push(Assertion::single(2, pl_first_row, Felt::ZERO));
        assertions.push(Assertion::single(3, pl_first_row, Felt::ZERO));

        // Proof_link digest at final row of proof_link block
        let pl_final_row = PROOF_LINK_BLOCK * HASH_CYCLE + HASH_CYCLE - 1;
        for j in 0..4 {
            assertions.push(Assertion::single(
                4 + j,
                pl_final_row,
                self.pub_inputs.proof_link[j],
            ));
        }

        // Chain flag assertions:
        // Block 0 (nullifier): chain_flag = 0
        assertions.push(Assertion::single(25, 0, Felt::ZERO));
        // Block 1 (first Merkle level): chain_flag = 0
        assertions.push(Assertion::single(25, HASH_CYCLE, Felt::ZERO));
        // Blocks 2..MERKLE_DEPTH: chain_flag = 1
        for block in 2..=MERKLE_DEPTH {
            let first_row = block * HASH_CYCLE;
            assertions.push(Assertion::single(25, first_row, Felt::ONE));
        }
        // Proof_link block: chain_flag = 0, path_bit = 1
        assertions.push(Assertion::single(25, pl_first_row, Felt::ZERO));
        assertions.push(Assertion::single(24, pl_first_row, Felt::ONE));

        // Padding blocks: chain_flag = 0, path_bit = 1
        for block in TOTAL_REAL_BLOCKS..self.num_hash_blocks {
            let first_row = block * HASH_CYCLE;
            assertions.push(Assertion::single(25, first_row, Felt::ZERO));
            assertions.push(Assertion::single(24, first_row, Felt::ONE));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        let mut columns = Vec::with_capacity(29);

        // Column 0: hash_flag (period 8)
        let mut flag = vec![Felt::ONE; HASH_CYCLE];
        flag[HASH_CYCLE - 1] = Felt::ZERO;
        columns.push(flag);

        // Columns 1-12: ARK1 (period 8)
        let ark1 = rescue::ark1();
        for j in 0..12 {
            let mut col = Vec::with_capacity(HASH_CYCLE);
            for round_constants in ark1 {
                col.push(round_constants[j]);
            }
            col.push(Felt::ZERO);
            columns.push(col);
        }

        // Columns 13-24: ARK2 (period 8)
        let ark2 = rescue::ark2();
        for j in 0..12 {
            let mut col = Vec::with_capacity(HASH_CYCLE);
            for round_constants in ark2 {
                col.push(round_constants[j]);
            }
            col.push(Felt::ZERO);
            columns.push(col);
        }

        // Column 25: first_row_flag (period 8)
        let mut first_flag = vec![Felt::ZERO; HASH_CYCLE];
        first_flag[0] = Felt::ONE;
        columns.push(first_flag);

        // Column 26: nullifier_bind_flag (period = trace_length)
        // 1 at row 0 (block 0, first row), 0 elsewhere
        let mut null_bind = vec![Felt::ZERO; self.trace_length];
        null_bind[0] = Felt::ONE;
        columns.push(null_bind);

        // Column 27: merkle_leaf_bind_flag (period = trace_length)
        // 1 at row 8 (block 1, first row), 0 elsewhere
        let mut merkle_bind = vec![Felt::ZERO; self.trace_length];
        merkle_bind[HASH_CYCLE] = Felt::ONE;
        columns.push(merkle_bind);

        // Column 28: proof_link_bind_flag (period = trace_length)
        // 1 at first row of proof_link block, 0 elsewhere
        let mut pl_bind = vec![Felt::ZERO; self.trace_length];
        pl_bind[PROOF_LINK_BLOCK * HASH_CYCLE] = Felt::ONE;
        columns.push(pl_bind);

        columns
    }
}

/// Compute the trace length for a spend proof.
pub fn spend_trace_length() -> usize {
    let min_rows = TOTAL_REAL_BLOCKS * HASH_CYCLE;
    let mut len = 8;
    while len < min_rows {
        len *= 2;
    }
    // Ensure at least one padding block
    if len == min_rows {
        len *= 2;
    }
    len
}
