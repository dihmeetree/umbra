//! Prover for the spend STARK proof.
//!
//! Builds the execution trace and generates a STARK proof that:
//! - The nullifier is correctly derived from (spend_auth, commitment)
//! - The commitment exists in the Merkle tree with the given root
//! - The proof_link is correctly derived from (commitment, link_nonce)
//!
//! The commitment is a private witness — only proof_link is public.

use winterfell::crypto::hashers::Rp64_256;
use winterfell::crypto::{DefaultRandomCoin, MerkleTree};
use winterfell::math::FieldElement;
use winterfell::{
    AuxRandElements, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions, Proof, ProofOptions,
    ProverError, StarkDomain, TraceInfo, TraceTable,
};

use super::convert::{exp7, Felt};
use super::rescue;
use super::spend_air::{SpendAir, HASH_CYCLE, MERKLE_DEPTH, SPEND_TRACE_WIDTH};
use super::types::{SpendPublicInputs, SpendStarkProof, SpendWitness, StarkError};

/// First column index of the commitment register.
const REG_COL_START: usize = 26;

/// Block index of the proof_link hash.
const PROOF_LINK_BLOCK: usize = 1 + MERKLE_DEPTH;

/// Total real blocks: 1 (nullifier) + MERKLE_DEPTH (Merkle) + 1 (proof_link).
const TOTAL_REAL_BLOCKS: usize = 1 + MERKLE_DEPTH + 1;

/// Build the execution trace for a spend proof.
pub fn build_spend_trace(
    witness: &SpendWitness,
    pub_inputs: &SpendPublicInputs,
) -> Result<TraceTable<Felt>, StarkError> {
    if witness.merkle_path.len() != MERKLE_DEPTH {
        return Err(StarkError::InvalidWitness(format!(
            "expected Merkle path of depth {MERKLE_DEPTH}, got {}",
            witness.merkle_path.len()
        )));
    }

    let trace_len = super::spend_air::spend_trace_length();
    let num_blocks = trace_len / HASH_CYCLE;

    let mut columns = vec![vec![Felt::ZERO; trace_len]; SPEND_TRACE_WIDTH];

    let mds = rescue::mds();
    let ark1 = rescue::ark1();

    // Fill commitment register columns (26-29) — constant throughout entire trace
    for j in 0..4 {
        for cell in &mut columns[REG_COL_START + j] {
            *cell = witness.commitment[j];
        }
    }

    // Block 0: Nullifier hash — Rescue(spend_auth, commitment) → nullifier
    {
        let init_state = rescue::nullifier_init_state(&witness.spend_auth, &witness.commitment);
        fill_hash_block(
            &mut columns,
            0,
            &init_state,
            Felt::ZERO,
            Felt::ZERO,
            mds,
            ark1,
        );
    }

    // Block 1: First Merkle level — merge(commitment, sibling_0) or (sibling_0, commitment)
    let mut current_hash = witness.commitment;
    {
        let (sibling, is_right) = &witness.merkle_path[0];
        let init_state = if *is_right {
            rescue::merge_init_state(sibling, &current_hash)
        } else {
            rescue::merge_init_state(&current_hash, sibling)
        };
        let path_bit = if *is_right { Felt::ONE } else { Felt::ZERO };
        fill_hash_block(
            &mut columns,
            1,
            &init_state,
            path_bit,
            Felt::ZERO,
            mds,
            ark1,
        );

        let mut state = init_state;
        rescue::apply_permutation(&mut state);
        current_hash = [state[4], state[5], state[6], state[7]];
    }

    // Blocks 2..MERKLE_DEPTH: remaining Merkle levels (chained)
    for level in 1..MERKLE_DEPTH {
        let block = level + 1;
        let (sibling, is_right) = &witness.merkle_path[level];
        let init_state = if *is_right {
            rescue::merge_init_state(sibling, &current_hash)
        } else {
            rescue::merge_init_state(&current_hash, sibling)
        };
        let path_bit = if *is_right { Felt::ONE } else { Felt::ZERO };
        let chain_flag = Felt::ONE;
        fill_hash_block(
            &mut columns,
            block,
            &init_state,
            path_bit,
            chain_flag,
            mds,
            ark1,
        );

        let mut state = init_state;
        rescue::apply_permutation(&mut state);
        current_hash = [state[4], state[5], state[6], state[7]];
    }

    // Verify the final hash matches the Merkle root
    if current_hash != pub_inputs.merkle_root {
        return Err(StarkError::InvalidWitness(
            "Merkle path does not lead to expected root".into(),
        ));
    }

    // Block PROOF_LINK_BLOCK: proof_link hash — Rescue(commitment, link_nonce) → proof_link
    {
        let init_state = rescue::proof_link_init_state(&witness.commitment, &witness.link_nonce);
        fill_hash_block(
            &mut columns,
            PROOF_LINK_BLOCK,
            &init_state,
            Felt::ONE, // path_bit = 1 (irrelevant for this block, matches padding)
            Felt::ZERO,
            mds,
            ark1,
        );
    }

    // Padding blocks: all zeros, chain_flag = 0, path_bit = 1
    for block in TOTAL_REAL_BLOCKS..num_blocks {
        let init_state = [Felt::ZERO; 12];
        fill_hash_block(
            &mut columns,
            block,
            &init_state,
            Felt::ONE,
            Felt::ZERO,
            mds,
            ark1,
        );
    }

    Ok(TraceTable::init(columns))
}

/// Fill a single hash block (8 rows) in the trace.
fn fill_hash_block(
    columns: &mut [Vec<Felt>],
    block: usize,
    init_state: &[Felt; 12],
    path_bit: Felt,
    chain_flag: Felt,
    mds: &[[Felt; 12]; 12],
    ark1: &[[Felt; 12]; 7],
) {
    let start_row = block * HASH_CYCLE;
    let mut state = *init_state;

    // Rows 0 through NUM_ROUNDS-1 (rounds 0-6)
    for (round, round_constants) in ark1.iter().enumerate() {
        let row = start_row + round;
        for j in 0..12 {
            columns[j][row] = state[j];
        }

        // Compute mid-state: MDS * (state^7) + ARK1[round]
        let mut mid = [Felt::ZERO; 12];
        for j in 0..12 {
            for k in 0..12 {
                let sbox_out = exp7(state[k]);
                mid[j] += mds[j][k] * sbox_out;
            }
            mid[j] += round_constants[j];
        }
        for j in 0..12 {
            columns[12 + j][row] = mid[j];
        }

        columns[24][row] = path_bit;
        columns[25][row] = chain_flag;

        rescue::apply_round(&mut state, round);
    }

    // Boundary row (hash_flag = 0)
    let boundary_row = start_row + HASH_CYCLE - 1;
    for j in 0..12 {
        columns[j][boundary_row] = state[j];
    }
    for j in 0..12 {
        columns[12 + j][boundary_row] = Felt::ZERO;
    }
    columns[24][boundary_row] = path_bit;
    columns[25][boundary_row] = chain_flag;
}

// ── Prover implementation ──

struct SpendProver {
    options: ProofOptions,
    pub_inputs: SpendPublicInputs,
}

impl winterfell::Prover for SpendProver {
    type BaseField = Felt;
    type Air = SpendAir;
    type Trace = TraceTable<Felt>;
    type HashFn = Rp64_256;
    type VC = MerkleTree<Rp64_256>;
    type RandomCoin = DefaultRandomCoin<Rp64_256>;
    type TraceLde<E: FieldElement<BaseField = Felt>> =
        DefaultTraceLde<E, Rp64_256, MerkleTree<Rp64_256>>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Felt>> =
        DefaultConstraintEvaluator<'a, SpendAir, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = Felt>> =
        DefaultConstraintCommitment<E, Rp64_256, MerkleTree<Rp64_256>>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> SpendPublicInputs {
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

/// Generate a spend STARK proof.
pub fn prove_spend(
    witness: &SpendWitness,
    pub_inputs: &SpendPublicInputs,
    options: ProofOptions,
) -> Result<SpendStarkProof, StarkError> {
    // Validate nullifier derivation
    let expected_nullifier = rescue::hash_nullifier(&witness.spend_auth, &witness.commitment);
    if expected_nullifier != pub_inputs.nullifier {
        return Err(StarkError::InvalidWitness(
            "nullifier does not match spend_auth and commitment".into(),
        ));
    }

    // Validate first_path_bit matches witness
    let expected_first_bit = if witness.merkle_path[0].1 {
        Felt::ONE
    } else {
        Felt::ZERO
    };
    if pub_inputs.first_path_bit != expected_first_bit {
        return Err(StarkError::InvalidWitness(
            "first_path_bit does not match Merkle path".into(),
        ));
    }

    // Validate proof_link matches
    let expected_proof_link = rescue::hash_proof_link(&witness.commitment, &witness.link_nonce);
    if expected_proof_link != pub_inputs.proof_link {
        return Err(StarkError::InvalidWitness(
            "proof_link does not match commitment and link_nonce".into(),
        ));
    }

    let trace = build_spend_trace(witness, pub_inputs)?;

    let prover = SpendProver {
        options,
        pub_inputs: pub_inputs.clone(),
    };

    let proof: Proof = winterfell::Prover::prove(&prover, trace)
        .map_err(|e: ProverError| StarkError::ProvingFailed(e.to_string()))?;

    let proof_bytes = proof.to_bytes();
    let public_inputs_bytes = pub_inputs.to_bytes();

    Ok(SpendStarkProof {
        proof_bytes,
        public_inputs_bytes,
    })
}
