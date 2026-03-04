//! Validator lifecycle integration tests.
//!
//! Tests the full validator lifecycle: registration, activation delay,
//! equivocation detection, slashing, and capacity limits.

use umbra::consensus::bft::{vote_sign_data, BftState, Validator, Vote, VoteType};
use umbra::consensus::dag::VertexId;
use umbra::constants;
use umbra::crypto::keys::{KemKeypair, SigningKeypair};

// ── Helpers ──────────────────────────────────────────────────────────────

fn register_genesis_validator(
    state: &mut umbra::state::ChainState,
) -> (SigningKeypair, KemKeypair, Validator) {
    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let validator = Validator::with_kem(signing.public.clone(), kem.public.clone());
    state.register_genesis_validator(validator.clone()).unwrap();
    (signing, kem, validator)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[test]
fn test_register_genesis_validator() {
    let mut state = umbra::state::ChainState::new();
    let (_signing, _kem, validator) = register_genesis_validator(&mut state);

    assert!(state.is_active_validator(&validator.id));

    let bond = state.validator_bond(&validator.id);
    assert!(bond.is_some());
    assert!(bond.unwrap() > 0);

    let active = state.active_validators();
    assert!(active.iter().any(|v| v.id == validator.id));
}

#[test]
fn test_register_multiple_validators() {
    let mut state = umbra::state::ChainState::new();

    let mut ids = Vec::new();
    for _ in 0..4 {
        let (_s, _k, v) = register_genesis_validator(&mut state);
        ids.push(v.id);
    }

    assert_eq!(state.total_validators(), 4);
    let active = state.active_validators();
    assert_eq!(active.len(), 4);
    for id in &ids {
        assert!(state.is_active_validator(id));
    }
}

#[test]
fn test_activation_delay_enforcement() {
    let mut state = umbra::state::ChainState::new();

    // Register a genesis validator (active at epoch 0)
    let (_s0, _k0, _v0) = register_genesis_validator(&mut state);

    // Register a validator with activation delay
    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let delayed = Validator::with_activation(
        signing.public.clone(),
        kem.public.clone(),
        constants::COMMITTEE_ELIGIBILITY_DELAY_EPOCHS,
    );
    state.register_genesis_validator(delayed.clone()).unwrap();

    // At epoch 0: delayed is NOT eligible
    let eligible_0 = state.eligible_validators(0);
    assert!(eligible_0.iter().all(|v| v.id != delayed.id));

    // At epoch 1: still not eligible
    let eligible_1 = state.eligible_validators(1);
    assert!(eligible_1.iter().all(|v| v.id != delayed.id));

    // At epoch 2 (COMMITTEE_ELIGIBILITY_DELAY_EPOCHS): now eligible
    let eligible_2 = state.eligible_validators(constants::COMMITTEE_ELIGIBILITY_DELAY_EPOCHS);
    assert!(eligible_2.iter().any(|v| v.id == delayed.id));
}

#[test]
fn test_equivocation_detection_and_slashing() {
    let mut state = umbra::state::ChainState::new();

    let mut keypairs = Vec::new();
    let mut validators = Vec::new();
    for _ in 0..4 {
        let (s, _k, v) = register_genesis_validator(&mut state);
        keypairs.push(s);
        validators.push(v);
    }

    let chain_id = *state.chain_id();
    let mut bft = BftState::new(0, validators.clone(), chain_id);

    // Validator 0 votes for two different vertices in the same round
    let vertex_a = VertexId([1u8; 32]);
    let vertex_b = VertexId([2u8; 32]);
    let epoch = 0u64;
    let round = bft.round;

    let sign_a = vote_sign_data(&vertex_a, epoch, round, &VoteType::Accept, &chain_id);
    let sig_a = keypairs[0].sign(&sign_a);
    let vote_a = Vote {
        vertex_id: vertex_a,
        voter_id: validators[0].id,
        epoch,
        round,
        vote_type: VoteType::Accept,
        signature: sig_a,
        vrf_proof: None,
    };

    let sign_b = vote_sign_data(&vertex_b, epoch, round, &VoteType::Accept, &chain_id);
    let sig_b = keypairs[0].sign(&sign_b);
    let vote_b = Vote {
        vertex_id: vertex_b,
        voter_id: validators[0].id,
        epoch,
        round,
        vote_type: VoteType::Accept,
        signature: sig_b,
        vrf_proof: None,
    };

    let _ = bft.receive_vote(vote_a);
    let _ = bft.receive_vote(vote_b);

    // Equivocation detected
    assert!(
        !bft.equivocations().is_empty(),
        "equivocation evidence should be detected"
    );

    // Slash the equivocating validator
    let fees_before = state.epoch_fees();
    state.slash_validator(&validators[0].id).unwrap();

    // Bond forfeited to epoch_fees
    assert!(state.epoch_fees() > fees_before);
    assert!(state.is_slashed(&validators[0].id));
    assert!(!state.is_active_validator(&validators[0].id));
    assert_eq!(state.validator_bond(&validators[0].id), None);

    bft.clear_equivocations();
}

#[test]
fn test_slashing_permanent() {
    let mut state = umbra::state::ChainState::new();
    let (_s, _k, v) = register_genesis_validator(&mut state);

    state.slash_validator(&v.id).unwrap();
    assert!(state.is_slashed(&v.id));

    // Advance epoch — slashing persists
    state.advance_epoch();
    assert!(state.is_slashed(&v.id));
    assert!(!state.is_active_validator(&v.id));

    for _ in 0..5 {
        state.advance_epoch();
    }
    assert!(state.is_slashed(&v.id));
    assert!(state.active_validators().iter().all(|av| av.id != v.id));
}

#[test]
fn test_deregister_via_slashing_removes_from_active() {
    // Since deregistration requires a full ValidatorDeregister transaction with
    // STARK proofs, we test the state-level behavior: after slashing, a validator
    // is permanently inactive and its bond is forfeited.
    let mut state = umbra::state::ChainState::new();
    let (_s, _k, v) = register_genesis_validator(&mut state);

    let bond_before = state.validator_bond(&v.id).unwrap();
    assert!(bond_before > 0);

    state.slash_validator(&v.id).unwrap();

    // Bond forfeited (returned as None since it went to epoch_fees)
    assert_eq!(state.validator_bond(&v.id), None);
    assert!(!state.is_active_validator(&v.id));

    // Still in all_validators list (but inactive)
    let all = state.all_validators();
    assert!(all.iter().any(|av| av.id == v.id));
}

#[test]
fn test_batch_validator_registration() {
    // Verify batch registration works and count is tracked correctly.
    // MAX_VALIDATORS cap (10,000) enforcement is tested in state.rs unit tests.
    let mut state = umbra::state::ChainState::new();

    for _ in 0..10 {
        let signing = SigningKeypair::generate();
        let kem = KemKeypair::generate();
        let v = Validator::with_kem(signing.public.clone(), kem.public.clone());
        state.register_genesis_validator(v).unwrap();
    }
    assert_eq!(state.total_validators(), 10);
}
