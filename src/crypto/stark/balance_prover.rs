//! Prover for the balance STARK proof.
//!
//! Builds the execution trace and generates a winterfell STARK proof that:
//! - Each commitment opens correctly to its value and blinding
//! - Each proof_link is correctly derived from (commitment, link_nonce)
//! - The balance equation holds: sum(inputs) == sum(outputs) + fee

use winterfell::crypto::hashers::Rp64_256;
use winterfell::crypto::{DefaultRandomCoin, MerkleTree};
use winterfell::math::FieldElement;
use winterfell::{
    AuxRandElements, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions, Proof, ProofOptions,
    ProverError, StarkDomain, TraceInfo, TraceTable,
};

use super::balance_air::{BalanceAir, HASH_CYCLE, RANGE_BITS, TRACE_WIDTH};
use super::convert::{exp7, Felt};
use super::rescue;
use super::types::{BalancePublicInputs, BalanceStarkProof, BalanceWitness, StarkError};

/// Maximum value allowed for range proofs: 2^RANGE_BITS - 1.
const MAX_RANGE_VALUE: u64 = (1u64 << RANGE_BITS) - 1;

/// First column index of the bit decomposition.
const BIT_COL_START: usize = 26;

/// Column index of the chain flag.
const CHAIN_FLAG_COL: usize = 85;

/// Build the execution trace for a balance proof.
///
/// Block layout: [commit_0, link_0, commit_1, link_1, ..., out_0, out_1, ..., padding]
///
/// Each input produces 2 blocks:
/// - Even block: commitment hash (chain_flag=0, block_value=+value)
/// - Odd block:  proof_link hash chained from commitment (chain_flag=1, block_value=0)
pub fn build_balance_trace(
    witness: &BalanceWitness,
    pub_inputs: &BalancePublicInputs,
) -> Result<TraceTable<Felt>, StarkError> {
    let n_in = witness.input_values.len();
    let n_out = witness.output_values.len();

    if n_in != pub_inputs.input_proof_links.len() {
        return Err(StarkError::InvalidWitness("input count mismatch".into()));
    }
    if n_out != pub_inputs.output_commitments.len() {
        return Err(StarkError::InvalidWitness("output count mismatch".into()));
    }
    if n_in != witness.input_link_nonces.len() {
        return Err(StarkError::InvalidWitness(
            "input link_nonce count mismatch".into(),
        ));
    }

    let trace_len = super::balance_air::trace_length(n_in, n_out);
    let total_real_blocks = 2 * n_in + n_out;
    let num_blocks = trace_len / HASH_CYCLE;

    // Compute bitwise OR of all values for padding blocks. Proof_link blocks
    // use the bitwise complement of each input value, guaranteeing every bit
    // column has both 0 and 1 across the trace (preventing degree collapse).
    // Padding blocks use or_all_values to break symmetry with proof_link
    // blocks: if padding used the complement too, the 4-block DFT degenerates
    // when input and output share the same bit pattern at some position.
    let or_all_values = witness
        .input_values
        .iter()
        .chain(witness.output_values.iter())
        .fold(0u64, |acc, &v| acc | v);

    // Pre-compute commitment digests for inputs (needed for proof_link blocks).
    // The commitment block computes Rescue(value, blinding) → digest in state[4..8].
    // The proof_link block uses this digest as input: Rescue(digest, link_nonce).
    let mut input_commitment_digests = Vec::with_capacity(n_in);
    for i in 0..n_in {
        let value = Felt::new(witness.input_values[i]);
        let digest = rescue::hash_commitment(value, &witness.input_blindings[i]);
        input_commitment_digests.push(digest);
    }

    // Build column-major trace
    let mut columns = vec![vec![Felt::ZERO; trace_len]; TRACE_WIDTH];

    let mds = rescue::mds();
    let ark1 = rescue::ark1();

    let mut net_balance = Felt::ZERO;

    for block in 0..num_blocks {
        let start_row = block * HASH_CYCLE;

        // Determine initial state, block value, chain flag, and bit decomposition value
        let (init_state, block_value, chain_flag, abs_value) = if block < 2 * n_in {
            let input_idx = block / 2;
            if block % 2 == 0 {
                // Commitment block: Rescue(value, blinding) → commitment digest
                let value = Felt::new(witness.input_values[input_idx]);
                let state =
                    rescue::commitment_init_state(value, &witness.input_blindings[input_idx]);
                (state, value, Felt::ZERO, witness.input_values[input_idx])
            } else {
                // Proof_link block: Rescue(commitment_digest, link_nonce) → proof_link
                // chain_flag=1 signals chaining from the preceding commitment block.
                // block_value=0, reconstruction constraint is skipped via chain_flag.
                // Use bitwise complement of the input value for bit columns to ensure
                // every bit position has both 0 and 1 between the commitment block
                // and its proof_link block (prevents polynomial degree collapse).
                let state = rescue::proof_link_init_state(
                    &input_commitment_digests[input_idx],
                    &witness.input_link_nonces[input_idx],
                );
                let complement_of_value = (!witness.input_values[input_idx]) & MAX_RANGE_VALUE;
                (state, Felt::ZERO, Felt::ONE, complement_of_value)
            }
        } else if block < total_real_blocks {
            // Output block: Rescue(value, blinding) → output commitment
            let output_idx = block - 2 * n_in;
            let value = Felt::new(witness.output_values[output_idx]);
            let state = rescue::commitment_init_state(value, &witness.output_blindings[output_idx]);
            (
                state,
                Felt::ZERO - value,
                Felt::ZERO,
                witness.output_values[output_idx],
            )
        } else {
            // Padding block: all-zero state, zero value.
            // Use or_all_values for bit columns to break symmetry with
            // proof_link blocks (which use complement of individual inputs).
            let state = [Felt::ZERO; 12];
            (state, Felt::ZERO, Felt::ZERO, or_all_values)
        };

        let mut state = init_state;

        // Fill the first row (round 0)
        for j in 0..12 {
            columns[j][start_row] = state[j];
        }

        // Compute mid-state for round 0: mid = MDS * (state^7) + ARK1[0]
        let mid = compute_mid_state(&state, 0, mds, ark1);
        for j in 0..12 {
            columns[12 + j][start_row] = mid[j];
        }

        columns[24][start_row] = block_value;
        columns[25][start_row] = net_balance;
        columns[CHAIN_FLAG_COL][start_row] = chain_flag;

        // Apply round 0 to get state for row 1
        rescue::apply_round(&mut state, 0);

        // Net balance updates between row 0 and row 1 (first_row_flag transition)
        net_balance += block_value;

        // Fill rows 1 through NUM_ROUNDS-1 (rounds 1-6)
        for round in 1..rescue::NUM_ROUNDS {
            let row = start_row + round;
            for j in 0..12 {
                columns[j][row] = state[j];
            }

            let mid = compute_mid_state(&state, round, mds, ark1);
            for j in 0..12 {
                columns[12 + j][row] = mid[j];
            }

            columns[24][row] = block_value;
            columns[25][row] = net_balance;
            columns[CHAIN_FLAG_COL][row] = chain_flag;

            rescue::apply_round(&mut state, round);
        }

        // Fill the boundary row (hash_flag = 0).
        // State here is the final post-permutation state (digest in state[4..8]).
        // Mid-state values don't matter (multiplied by hash_flag = 0).
        let boundary_row = start_row + HASH_CYCLE - 1;
        for j in 0..12 {
            columns[j][boundary_row] = state[j];
        }
        for j in 0..12 {
            columns[12 + j][boundary_row] = Felt::ZERO;
        }
        columns[24][boundary_row] = block_value;
        columns[25][boundary_row] = net_balance;
        columns[CHAIN_FLAG_COL][boundary_row] = chain_flag;

        // Fill bit decomposition columns (26..85) for range proof.
        // For commitment/output blocks: decompose the committed value into bits.
        // For proof_link blocks: use bitwise complement of the input value.
        // For padding blocks: use or_all_values (breaks symmetry with proof_link blocks).
        for j in 0..RANGE_BITS {
            let bit = if (abs_value >> j) & 1 == 1 {
                Felt::ONE
            } else {
                Felt::ZERO
            };
            // Bits are constant within the entire hash block
            for col_row in &mut columns[BIT_COL_START + j][start_row..start_row + HASH_CYCLE] {
                *col_row = bit;
            }
        }
    }

    Ok(TraceTable::init(columns))
}

/// Compute the forward half-round mid-state: MDS * (state^7) + ARK1[round]
///
/// Rescue round order: S-box first, then MDS, then add ARK.
fn compute_mid_state(
    state: &[Felt; 12],
    round: usize,
    mds: &[[Felt; 12]; 12],
    ark1: &[[Felt; 12]; 7],
) -> [Felt; 12] {
    let mut mid = [Felt::ZERO; 12];
    for j in 0..12 {
        for k in 0..12 {
            let sbox_out = exp7(state[k]);
            mid[j] += mds[j][k] * sbox_out;
        }
        mid[j] += ark1[round][j];
    }
    mid
}

// ── Prover implementation ──

struct BalanceProver {
    options: ProofOptions,
    pub_inputs: BalancePublicInputs,
}

impl winterfell::Prover for BalanceProver {
    type BaseField = Felt;
    type Air = BalanceAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Rp64_256;
    type VC = MerkleTree<Rp64_256>;
    type RandomCoin = DefaultRandomCoin<Rp64_256>;
    type TraceLde<E: FieldElement<BaseField = Felt>> =
        DefaultTraceLde<E, Rp64_256, MerkleTree<Rp64_256>>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, BalanceAir, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, Rp64_256, MerkleTree<Rp64_256>>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> BalancePublicInputs {
        self.pub_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Felt>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &winterfell::matrix::ColMatrix<Felt>,
        domain: &StarkDomain<Felt>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, winterfell::TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Felt>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Felt>>(
        &self,
        composition_poly_trace: winterfell::CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Felt>,
        partition_options: PartitionOptions,
    ) -> (
        Self::ConstraintCommitment<E>,
        winterfell::CompositionPoly<E>,
    ) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

/// Generate a balance STARK proof.
pub fn prove_balance(
    witness: &BalanceWitness,
    pub_inputs: &BalancePublicInputs,
    options: ProofOptions,
) -> Result<BalanceStarkProof, StarkError> {
    // Validate witness counts
    if witness.input_link_nonces.len() != witness.input_values.len() {
        return Err(StarkError::InvalidWitness(
            "input_link_nonces count mismatch".into(),
        ));
    }

    // Validate witness: all values must be in [0, 2^RANGE_BITS)
    for (i, &v) in witness.input_values.iter().enumerate() {
        if v > MAX_RANGE_VALUE {
            return Err(StarkError::InvalidWitness(format!(
                "input value[{i}] = {v} exceeds range limit {MAX_RANGE_VALUE}"
            )));
        }
    }
    for (i, &v) in witness.output_values.iter().enumerate() {
        if v > MAX_RANGE_VALUE {
            return Err(StarkError::InvalidWitness(format!(
                "output value[{i}] = {v} exceeds range limit {MAX_RANGE_VALUE}"
            )));
        }
    }

    let input_sum: u64 = witness
        .input_values
        .iter()
        .copied()
        .try_fold(0u64, |acc, v| acc.checked_add(v))
        .ok_or_else(|| StarkError::InvalidWitness("input sum overflow".into()))?;
    let output_sum: u64 = witness
        .output_values
        .iter()
        .copied()
        .try_fold(0u64, |acc, v| acc.checked_add(v))
        .ok_or_else(|| StarkError::InvalidWitness("output sum overflow".into()))?;
    let fee = pub_inputs.fee.as_int();
    if input_sum
        != output_sum
            .checked_add(fee)
            .ok_or_else(|| StarkError::InvalidWitness("output + fee overflow".into()))?
    {
        return Err(StarkError::InvalidWitness(format!(
            "balance mismatch: inputs={input_sum}, outputs={output_sum}, fee={fee}"
        )));
    }

    // Validate proof_links match witness
    for (i, expected_proof_link) in pub_inputs.input_proof_links.iter().enumerate() {
        let commitment = rescue::hash_commitment(
            Felt::new(witness.input_values[i]),
            &witness.input_blindings[i],
        );
        let computed = rescue::hash_proof_link(&commitment, &witness.input_link_nonces[i]);
        if computed != *expected_proof_link {
            return Err(StarkError::InvalidWitness(format!(
                "proof_link[{i}] does not match commitment and link_nonce"
            )));
        }
    }

    let trace = build_balance_trace(witness, pub_inputs)?;

    let prover = BalanceProver {
        options,
        pub_inputs: pub_inputs.clone(),
    };

    let proof: Proof = winterfell::Prover::prove(&prover, trace)
        .map_err(|e: ProverError| StarkError::ProvingFailed(e.to_string()))?;

    // Serialize proof and public inputs
    let proof_bytes = proof.to_bytes();
    let public_inputs_bytes = pub_inputs.to_bytes();

    Ok(BalanceStarkProof {
        proof_bytes,
        public_inputs_bytes,
    })
}
