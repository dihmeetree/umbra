//! AIR (Algebraic Intermediate Representation) for the balance STARK proof.
//!
//! Proves in zero knowledge:
//! 1. Each input/output commitment opens correctly: Rescue(value, blinding) == commitment
//! 2. sum(input_values) == sum(output_values) + fee
//! 3. All committed values are in [0, 2^RANGE_BITS) (prevents field-arithmetic inflation)
//! 4. Each input proof_link is correctly derived: Rescue(commitment, link_nonce) == proof_link
//!
//! Input commitments are private — only proof_links are public, preventing
//! graph analysis between inputs and outputs.
//!
//! Trace layout (TRACE_WIDTH = 86 columns):
//!
//! Columns 0-11:  Rescue Prime state (12 elements)
//! Columns 12-23: Rescue Prime mid-state (after forward half-round)
//! Column  24:    Signed block value (+value for inputs, -value for outputs, 0 for padding/link)
//! Column  25:    Running net balance (accumulated sum of block values)
//! Columns 26-84: Bit decomposition of the committed value (59 bits for range proof)
//! Column  85:    Chain flag (1 = proof_link block chained from commitment block)
//!
//! The trace is organized in hash blocks of HASH_CYCLE_LEN (8) rows each.
//! For N_IN inputs + N_OUT outputs, we have 2*N_IN + N_OUT hash blocks
//! (each input gets a commitment block + a proof_link block), padded to
//! a power of 2 total rows.
//!
//! Periodic columns (26 total):
//! [0]:     hash_flag — 1 during rounds 0-6, 0 at hash boundary (period 8)
//! [1..13]: ARK1 round constants for 12 positions (period 8)
//! [13..25]:ARK2 round constants for 12 positions (period 8)
//! [25]:    first_row_flag — 1 at first row of each block (period 8)
//!
//! Transition constraints (154 total):
//! 0-11:    Forward half-round (degree 7)
//! 12-23:   Inverse half-round (degree 7)
//! 24:      Block value constant within blocks (degree 1)
//! 25:      Block value squared = state[4] squared at first rows, skip at chain_flag=1 (degree 3)
//! 26:      Net balance update at first rows (degree 1)
//! 27:      Net balance constant at non-first rows (degree 1)
//! 28-86:   Range proof: each bit is boolean at first rows (degree 2)
//! 87:      Range proof: reconstruction check, skip at chain_flag=1 (degree 3)
//! 88-146:  Range proof: bits constant within blocks (degree 1)
//! 147:     Chain flag constant within blocks (degree 1)
//! 148:     Chain flag boolean at first rows (degree 2)
//! 149-152: Digest chaining: commitment flows to proof_link block (degree 2)
//! 153:     Block value zero at proof_link blocks (degree 2)

use winterfell::math::FieldElement;
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use super::convert::{exp7, Felt};
use super::rescue;
use super::types::BalancePublicInputs;

/// Maximum inputs + outputs supported.
pub const MAX_IO: usize = 16;

/// Number of bits for value range proofs.
pub const RANGE_BITS: usize = 59;

/// Trace width: 26 base + 59 range proof bits + 1 chain_flag.
pub const TRACE_WIDTH: usize = 26 + RANGE_BITS + 1;

/// Rows per hash (1 init + 7 rounds).
pub const HASH_CYCLE: usize = rescue::HASH_CYCLE_LEN;

/// Domain separator for commitment hashing.
const COMMITMENT_DOMAIN: u64 = 0x636F6D6D69740000;

/// Number of periodic columns (unchanged from base).
const NUM_PERIODIC: usize = 26;

/// First column index of the bit decomposition.
const BIT_COL_START: usize = 26;

/// Column index of the chain flag.
const CHAIN_FLAG_COL: usize = 85;

/// The Balance AIR definition.
pub struct BalanceAir {
    context: AirContext<Felt>,
    pub_inputs: BalancePublicInputs,
    num_hash_blocks: usize,
}

impl Air for BalanceAir {
    type BaseField = Felt;
    type PublicInputs = BalancePublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // 24 Rescue constraints: degree 7 in trace × hash_flag (cycle 8)
        let mut degrees = vec![TransitionConstraintDegree::with_cycles(7, vec![8]); 24];
        // block_value constant: hash_flag × degree 1
        degrees.push(TransitionConstraintDegree::with_cycles(1, vec![8]));
        // block_value^2 == state[4]^2 × (1-chain_flag): first_row_flag × degree 3
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![8]));
        // net_balance update: first_row_flag × degree 1
        degrees.push(TransitionConstraintDegree::with_cycles(1, vec![8]));
        // net_balance constant: (1-first_row_flag) × degree 1
        degrees.push(TransitionConstraintDegree::with_cycles(1, vec![8]));

        // Range proof boolean constraints: 59 × first_row_flag × degree 2
        for _ in 0..RANGE_BITS {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![8]));
        }
        // Reconstruction constraint × (1-chain_flag): first_row_flag × degree 3
        degrees.push(TransitionConstraintDegree::with_cycles(3, vec![8]));
        // Bit constancy: 59 × hash_flag × degree 1
        for _ in 0..RANGE_BITS {
            degrees.push(TransitionConstraintDegree::with_cycles(1, vec![8]));
        }

        // Chain flag constant within blocks: hash_flag × degree 1
        degrees.push(TransitionConstraintDegree::with_cycles(1, vec![8]));
        // Chain flag boolean: first_row_flag × degree 2
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![8]));
        // Digest chaining: 4 × (1-hash_flag) × next_chain_flag × ... = degree 2
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::with_cycles(2, vec![8]));
        }
        // Block value zero at proof_link blocks: first_row_flag × chain_flag × block_value = degree 2
        degrees.push(TransitionConstraintDegree::with_cycles(2, vec![8]));

        let num_hash_blocks = trace_info.length() / HASH_CYCLE;
        let n_in = pub_inputs.num_inputs();
        let total_real_blocks = pub_inputs.total_blocks();
        let num_padding_blocks = num_hash_blocks - total_real_blocks;

        // Assertions:
        // Even input blocks (n_in): 4 capacity domain each = 4*n_in
        // Odd input blocks (n_in): 4 capacity domain + 4 digest each = 8*n_in
        // Output blocks (n_out): 4 capacity + 4 digest = 8*n_out
        // net_balance = 0 at row 0, net_balance = fee at last row = 2
        // Padding: state[4] = 0 at each = num_padding
        // Chain_flag: 1 per block = num_hash_blocks
        let n_out = pub_inputs.output_commitments.len();
        let num_assertions =
            4 * n_in + 8 * n_in + 8 * n_out + 2 + num_padding_blocks + num_hash_blocks;

        let context = AirContext::new(trace_info, degrees, num_assertions, options);

        BalanceAir {
            context,
            pub_inputs,
            num_hash_blocks,
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

        // Forward half-round constraints (12)
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

        // Inverse half-round constraints (12)
        let inv_mds = rescue::inv_mds();
        for j in 0..12 {
            let mut y = E::ZERO;
            for k in 0..12 {
                y += E::from(inv_mds[j][k]) * (next[k] - ark2[k]);
            }
            let lhs = exp7(y);
            result[12 + j] = hash_flag * (lhs - current[12 + j]);
        }

        // Constraint 24: block_value stays constant within hash blocks
        result[24] = hash_flag * (next[24] - current[24]);

        // Constraint 25: block_value^2 == state[4]^2 at first row, skipped at chain_flag=1
        // (1-chain_flag) relaxes at proof_link blocks where state[4] is commitment digest
        result[25] = first_row_flag
            * (E::ONE - current[CHAIN_FLAG_COL])
            * (current[24] * current[24] - current[4] * current[4]);

        // Constraint 26: net_balance updates at first row of each block
        result[26] = first_row_flag * (next[25] - current[25] - current[24]);

        // Constraint 27: net_balance stays constant at all other rows
        result[27] = (E::ONE - first_row_flag) * (next[25] - current[25]);

        // ── Range proof constraints ──

        // Constraints 28..87: Each bit column is boolean at first rows
        for j in 0..RANGE_BITS {
            let bit = current[BIT_COL_START + j];
            result[28 + j] = first_row_flag * bit * (bit - E::ONE);
        }

        // Constraint 87: Bit reconstruction equals state[4], skipped at chain_flag=1.
        //
        // The constraint includes a state[4] factor:
        //   first_row × (1-chain_flag) × state[4] × (reconstructed - state[4]) = 0
        //
        // The state[4] factor is required for two reasons:
        //
        // 1. Prover correctness: padding blocks have all-zero state (state[4]=0) but
        //    use non-zero bit columns to prevent polynomial degree collapse in the
        //    FRI prover. Without the state[4] factor, the constraint would reject
        //    valid padding blocks where bits != 0 but state[4] = 0.
        //
        // 2. Security: the state[4] factor does NOT weaken the range proof because:
        //    a) For real commitment blocks, state[4] is a Rescue hash digest word.
        //       The Rescue round constraints enforce correct computation from
        //       (value, blinding), so a malicious prover cannot set state[4] = 0
        //       for a non-zero committed value (Rescue is a bijection).
        //    b) For padding blocks, state[4] = 0 is asserted directly (get_assertions()),
        //       and block_value is also 0, so no range bypass occurs.
        //    c) The commitment digest is further verified via proof_link chaining and
        //       the public assertion on the proof_link output.
        let mut reconstructed = E::ZERO;
        for j in 0..RANGE_BITS {
            let power_of_two = E::from(Felt::new(1u64 << j));
            reconstructed += current[BIT_COL_START + j] * power_of_two;
        }
        result[28 + RANGE_BITS] = first_row_flag
            * (E::ONE - current[CHAIN_FLAG_COL])
            * current[4]
            * (reconstructed - current[4]);

        // Constraints 88..146: Bits stay constant within hash blocks
        for j in 0..RANGE_BITS {
            result[29 + RANGE_BITS + j] =
                hash_flag * (next[BIT_COL_START + j] - current[BIT_COL_START + j]);
        }

        // Constraint 147: chain_flag constant within blocks
        result[29 + RANGE_BITS + RANGE_BITS] =
            hash_flag * (next[CHAIN_FLAG_COL] - current[CHAIN_FLAG_COL]);

        // Constraint 148: chain_flag boolean at first rows
        result[30 + RANGE_BITS + RANGE_BITS] =
            first_row_flag * current[CHAIN_FLAG_COL] * (current[CHAIN_FLAG_COL] - E::ONE);

        // Constraints 149-152: Digest chaining
        // At block boundaries (hash_flag=0) where next chain_flag=1,
        // the commitment digest (current[4..8]) flows to the proof_link block (next[4..8])
        let boundary_flag = E::ONE - hash_flag;
        for j in 0..4 {
            result[31 + RANGE_BITS + RANGE_BITS + j] =
                boundary_flag * next[CHAIN_FLAG_COL] * (next[4 + j] - current[4 + j]);
        }

        // Constraint 153: block_value must be zero at proof_link blocks
        result[35 + RANGE_BITS + RANGE_BITS] =
            first_row_flag * current[CHAIN_FLAG_COL] * current[24];
    }

    fn get_assertions(&self) -> Vec<Assertion<Felt>> {
        let mut assertions = Vec::new();
        let n_in = self.pub_inputs.num_inputs();
        let n_out = self.pub_inputs.output_commitments.len();
        let total_real = self.pub_inputs.total_blocks();
        let trace_len = self.context.trace_len();

        // Even input blocks (commitment computation): capacity domain only
        for i in 0..n_in {
            let block = 2 * i;
            let first_row = block * HASH_CYCLE;
            assertions.push(Assertion::single(
                0,
                first_row,
                Felt::new(COMMITMENT_DOMAIN),
            ));
            assertions.push(Assertion::single(1, first_row, Felt::ZERO));
            assertions.push(Assertion::single(2, first_row, Felt::ZERO));
            assertions.push(Assertion::single(3, first_row, Felt::ZERO));
            // No digest assertion — commitment is private
        }

        // Odd input blocks (proof_link computation): capacity domain + digest
        for i in 0..n_in {
            let block = 2 * i + 1;
            let first_row = block * HASH_CYCLE;
            let final_row = first_row + HASH_CYCLE - 1;

            // Capacity: PROOF_LINK_DOMAIN
            assertions.push(Assertion::single(
                0,
                first_row,
                Felt::new(rescue::PROOF_LINK_DOMAIN),
            ));
            assertions.push(Assertion::single(1, first_row, Felt::ZERO));
            assertions.push(Assertion::single(2, first_row, Felt::ZERO));
            assertions.push(Assertion::single(3, first_row, Felt::ZERO));

            // Digest: proof_link
            for (j, &val) in self.pub_inputs.input_proof_links[i]
                .iter()
                .enumerate()
                .take(4)
            {
                assertions.push(Assertion::single(4 + j, final_row, val));
            }
        }

        // Output blocks: capacity domain + commitment digest
        for j in 0..n_out {
            let block = 2 * n_in + j;
            let first_row = block * HASH_CYCLE;
            let final_row = first_row + HASH_CYCLE - 1;

            assertions.push(Assertion::single(
                0,
                first_row,
                Felt::new(COMMITMENT_DOMAIN),
            ));
            assertions.push(Assertion::single(1, first_row, Felt::ZERO));
            assertions.push(Assertion::single(2, first_row, Felt::ZERO));
            assertions.push(Assertion::single(3, first_row, Felt::ZERO));

            for (k, &val) in self.pub_inputs.output_commitments[j]
                .iter()
                .enumerate()
                .take(4)
            {
                assertions.push(Assertion::single(4 + k, final_row, val));
            }
        }

        // Net balance init: col[25] = 0 at row 0
        assertions.push(Assertion::single(25, 0, Felt::ZERO));

        // Net balance final: col[25] = fee at last row of trace
        assertions.push(Assertion::single(25, trace_len - 1, self.pub_inputs.fee));

        // Padding blocks: state[4] = 0 at first row
        for i in total_real..self.num_hash_blocks {
            let first_row = i * HASH_CYCLE;
            assertions.push(Assertion::single(4, first_row, Felt::ZERO));
        }

        // Chain_flag assertions: 1 at odd input blocks, 0 everywhere else
        for block in 0..self.num_hash_blocks {
            let first_row = block * HASH_CYCLE;
            let is_proof_link_block = block < 2 * n_in && block % 2 == 1;
            let expected = if is_proof_link_block {
                Felt::ONE
            } else {
                Felt::ZERO
            };
            assertions.push(Assertion::single(CHAIN_FLAG_COL, first_row, expected));
        }

        assertions
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Felt>> {
        let mut columns = Vec::with_capacity(NUM_PERIODIC);

        // Column 0: hash_flag
        let mut flag = vec![Felt::ONE; HASH_CYCLE];
        flag[HASH_CYCLE - 1] = Felt::ZERO;
        columns.push(flag);

        // Columns 1-12: ARK1 round constants
        let ark1 = rescue::ark1();
        for j in 0..12 {
            let mut col = Vec::with_capacity(HASH_CYCLE);
            for round_constants in ark1 {
                col.push(round_constants[j]);
            }
            col.push(Felt::ZERO);
            columns.push(col);
        }

        // Columns 13-24: ARK2 round constants
        let ark2 = rescue::ark2();
        for j in 0..12 {
            let mut col = Vec::with_capacity(HASH_CYCLE);
            for round_constants in ark2 {
                col.push(round_constants[j]);
            }
            col.push(Felt::ZERO);
            columns.push(col);
        }

        // Column 25: first_row_flag
        let mut first_flag = vec![Felt::ZERO; HASH_CYCLE];
        first_flag[0] = Felt::ONE;
        columns.push(first_flag);

        columns
    }
}

/// Compute the minimum trace length for a given number of inputs and outputs.
///
/// Each input requires 2 blocks (commitment + proof_link), each output 1 block.
pub fn trace_length(num_inputs: usize, num_outputs: usize) -> usize {
    let total = num_inputs * 2 + num_outputs;
    let min_rows = total * HASH_CYCLE;
    // Must be a power of 2 and at least 8 (winterfell minimum).
    // Ensure at least one padding block for proper net_balance propagation.
    let min_rows = if min_rows == 0 {
        HASH_CYCLE
    } else {
        min_rows + HASH_CYCLE
    };
    let mut len = 8;
    while len < min_rows {
        len *= 2;
    }
    len
}
