//! Epoch transition and committee rotation integration tests.
//!
//! Tests multi-epoch advancement, fee distribution, VRF-based committee
//! selection, validator activation delays, and epoch seed determinism.

use umbra::consensus::bft::{select_committee, Validator};
use umbra::constants;
use umbra::crypto::keys::{KemKeypair, SigningKeypair};
use umbra::crypto::vrf::EpochSeed;
use umbra::state::ChainState;

// ── Helpers ──────────────────────────────────────────────────────────────

fn register_genesis_validator(state: &mut ChainState) -> (SigningKeypair, KemKeypair, Validator) {
    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let v = Validator::with_kem(signing.public.clone(), kem.public.clone());
    state.register_genesis_validator(v.clone()).unwrap();
    (signing, kem, v)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[test]
fn test_multi_epoch_advance() {
    let mut state = ChainState::new();
    register_genesis_validator(&mut state);

    let mut prev_seed = state.epoch_seed().clone();
    assert_eq!(state.epoch(), 0);

    for i in 1..=5 {
        let (_fees, new_seed) = state.advance_epoch();
        assert_eq!(state.epoch(), i);
        assert_ne!(
            new_seed.seed, prev_seed.seed,
            "seed should change each epoch"
        );
        prev_seed = new_seed;
    }
}

#[test]
fn test_fee_distribution_on_epoch_advance() {
    let mut state = ChainState::new();
    let (_s, _k, v) = register_genesis_validator(&mut state);

    // Slash a validator to generate fees (bond goes to epoch_fees)
    let (_s2, _k2, v2) = register_genesis_validator(&mut state);
    state.slash_validator(&v2.id).unwrap();
    let accumulated_fees = state.epoch_fees();
    assert!(accumulated_fees > 0, "slashing should produce fees");

    // Advance epoch — fees are returned and reset
    let (returned_fees, _seed) = state.advance_epoch();
    assert_eq!(returned_fees, accumulated_fees);
    assert_eq!(
        state.epoch_fees(),
        0,
        "fees should reset after epoch advance"
    );

    // Validator v is still active
    assert!(state.is_active_validator(&v.id));
}

#[test]
fn test_validator_activation_delay() {
    let mut state = ChainState::new();

    // Genesis validators are eligible immediately
    let (_s, _k, genesis_v) = register_genesis_validator(&mut state);
    assert!(state
        .eligible_validators(0)
        .iter()
        .any(|v| v.id == genesis_v.id));

    // Validator with activation_epoch = 2
    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let delayed = Validator::with_activation(
        signing.public.clone(),
        kem.public.clone(),
        constants::COMMITTEE_ELIGIBILITY_DELAY_EPOCHS,
    );
    state.register_genesis_validator(delayed.clone()).unwrap();

    // Epoch 0: not eligible
    assert!(state
        .eligible_validators(0)
        .iter()
        .all(|v| v.id != delayed.id));

    // Advance to epoch 1: still not eligible
    state.advance_epoch();
    assert!(state
        .eligible_validators(1)
        .iter()
        .all(|v| v.id != delayed.id));

    // Advance to epoch 2: now eligible
    state.advance_epoch();
    assert!(
        state
            .eligible_validators(2)
            .iter()
            .any(|v| v.id == delayed.id),
        "validator should be eligible at activation_epoch"
    );
}

#[test]
fn test_epoch_seed_deterministic() {
    let seed = EpochSeed::genesis();
    let state_root = [1u8; 32];
    let vrf_mix_a = [2u8; 32];
    let vrf_mix_b = [3u8; 32];

    // Same inputs → same output
    let next_a1 = seed.next(&state_root, &vrf_mix_a);
    let next_a2 = seed.next(&state_root, &vrf_mix_a);
    assert_eq!(next_a1.seed, next_a2.seed);

    // Different VRF mix → different seed
    let next_b = seed.next(&state_root, &vrf_mix_b);
    assert_ne!(next_a1.seed, next_b.seed);

    // Different state root → different seed
    let next_c = seed.next(&[99u8; 32], &vrf_mix_a);
    assert_ne!(next_a1.seed, next_c.seed);
}

#[test]
fn test_committee_fallback_small_set() {
    let mut state = ChainState::new();

    // Register strictly fewer than MIN_COMMITTEE_SIZE validators
    let count = constants::MIN_COMMITTEE_SIZE.saturating_sub(1).min(4);
    assert!(
        count < constants::MIN_COMMITTEE_SIZE,
        "test requires count < MIN_COMMITTEE_SIZE"
    );
    for _ in 0..count {
        register_genesis_validator(&mut state);
    }

    // All should be eligible (fallback: if committee too small, include everyone)
    let eligible = state.eligible_validators(0);
    assert_eq!(eligible.len(), count);
}

#[test]
fn test_epoch_advance_preserves_validator_state() {
    let mut state = ChainState::new();

    let (_s1, _k1, v1) = register_genesis_validator(&mut state);
    let (_s2, _k2, v2) = register_genesis_validator(&mut state);

    let bond1 = state.validator_bond(&v1.id).unwrap();
    state.slash_validator(&v2.id).unwrap();

    // Advance epoch
    state.advance_epoch();

    // v1's bond preserved
    assert_eq!(state.validator_bond(&v1.id), Some(bond1));
    assert!(state.is_active_validator(&v1.id));

    // v2 still slashed
    assert!(state.is_slashed(&v2.id));
    assert!(!state.is_active_validator(&v2.id));
}

#[test]
fn test_vrf_committee_selection_fairness() {
    let mut state = ChainState::new();

    // Register 10 validators, keeping keypairs for VRF evaluation
    let mut validators_with_keys: Vec<(SigningKeypair, Validator)> = Vec::new();
    for _ in 0..10 {
        let (s, _k, v) = register_genesis_validator(&mut state);
        validators_with_keys.push((s, v));
    }

    // Track how many times each validator is VRF-selected across epochs
    let mut selection_counts = [0u32; 10];
    let committee_size = constants::MIN_COMMITTEE_SIZE;
    let num_epochs = 50;

    for _ in 0..num_epochs {
        let seed = state.epoch_seed();
        let committee = select_committee(seed, &validators_with_keys, committee_size);
        for (i, (_kp, v)) in validators_with_keys.iter().enumerate() {
            if committee.iter().any(|(cv, _)| cv.id == v.id) {
                selection_counts[i] += 1;
            }
        }
        state.advance_epoch();
    }

    // Every validator should be VRF-selected at least once across 50 epochs
    for (i, count) in selection_counts.iter().enumerate() {
        assert!(
            *count > 0,
            "validator {} was never VRF-selected across {} epochs",
            i,
            num_epochs
        );
    }
}

#[test]
fn test_epoch_seed_advances_monotonically() {
    let mut state = ChainState::new();
    register_genesis_validator(&mut state);

    let mut seeds = vec![state.epoch_seed().seed];
    for _ in 0..10 {
        state.advance_epoch();
        let seed = state.epoch_seed().seed;
        // Every seed should be unique
        assert!(
            !seeds.contains(&seed),
            "epoch seed should be unique across epochs"
        );
        seeds.push(seed);
    }
}
