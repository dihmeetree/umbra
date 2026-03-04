//! Full snapshot export/import/restore integration tests.
//!
//! Tests snapshot cycles with validators, transactions, nullifiers,
//! commitment trees, and slashing state.

use umbra::consensus::bft::Validator;
use umbra::constants;
use umbra::crypto::commitment::{BlindingFactor, Commitment};
use umbra::crypto::keys::{KemKeypair, SigningKeypair};
use umbra::crypto::nullifier::Nullifier;
use umbra::hash_domain;
use umbra::node::storage::{SledStorage, Storage};
use umbra::state::{import_snapshot_to_storage, ChainState, Ledger};

// ── Helpers ──────────────────────────────────────────────────────────────

fn register_validator(state: &mut ChainState) -> Validator {
    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let v = Validator::with_kem(signing.public.clone(), kem.public.clone());
    state.register_genesis_validator(v.clone()).unwrap();
    v
}

fn add_test_nullifier(state: &mut ChainState, seed: u8) -> Nullifier {
    let n = Nullifier(hash_domain(b"test.nullifier", &[seed]));
    state.mark_nullifier(n).unwrap();
    n
}

fn add_test_commitment(state: &mut ChainState, seed: u8) -> Commitment {
    let blinding = BlindingFactor::from_bytes([seed; 32]);
    let c = Commitment::commit(1000 + seed as u64, &blinding);
    state.add_commitment(c).unwrap();
    c
}

/// Persist in-memory state to storage so snapshot export can read it.
fn persist_state_to_storage(state: &ChainState, storage: &SledStorage) {
    // Persist commitment tree levels
    let depth = constants::MERKLE_DEPTH;
    for level in 0..=depth {
        for idx in 0..state.commitment_tree_level_len(level) {
            let hash = state.commitment_tree_node(level, idx);
            storage.put_commitment_level(level, idx, &hash).unwrap();
        }
    }
}

fn persist_nullifiers_to_storage(nullifiers: &[Nullifier], storage: &SledStorage) {
    for n in nullifiers {
        storage.put_nullifier(n).unwrap();
    }
}

fn persist_validators_to_storage(
    state: &ChainState,
    validators: &[Validator],
    storage: &SledStorage,
) {
    for v in validators {
        let bond = state.validator_bond(&v.id).unwrap_or(0);
        let slashed = state.is_slashed(&v.id);
        storage.put_validator(v, bond, slashed).unwrap();
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[test]
fn test_snapshot_with_validators_and_txs() {
    let source_storage = SledStorage::open_temporary().unwrap();
    let mut state = ChainState::new();

    let v1 = register_validator(&mut state);
    let v2 = register_validator(&mut state);
    let v3 = register_validator(&mut state);

    let mut nullifiers = Vec::new();
    for i in 0..5 {
        add_test_commitment(&mut state, i);
        nullifiers.push(add_test_nullifier(&mut state, i));
    }

    // Persist to storage for snapshot export
    persist_state_to_storage(&state, &source_storage);
    persist_nullifiers_to_storage(&nullifiers, &source_storage);
    persist_validators_to_storage(&state, &[v1, v2, v3], &source_storage);

    let original_root = state.state_root();
    let original_epoch = state.epoch();

    let snapshot = state.to_snapshot_data(&source_storage, 0).unwrap();

    // Import to fresh storage
    let dest_storage = SledStorage::open_temporary().unwrap();
    let meta = import_snapshot_to_storage(&dest_storage, &snapshot).unwrap();
    let restored =
        Ledger::restore_from_storage(&dest_storage, &meta, constants::NetworkId::Mainnet).unwrap();

    assert_eq!(restored.state.epoch(), original_epoch);
    assert_eq!(restored.state.state_root(), original_root);
    assert_eq!(restored.state.total_validators(), 3);
}

#[test]
fn test_snapshot_preserves_nullifiers() {
    let source_storage = SledStorage::open_temporary().unwrap();
    let mut state = ChainState::new();
    register_validator(&mut state);

    let mut nullifiers = Vec::new();
    for i in 0..10 {
        nullifiers.push(add_test_nullifier(&mut state, i));
    }

    persist_state_to_storage(&state, &source_storage);
    persist_nullifiers_to_storage(&nullifiers, &source_storage);
    persist_validators_to_storage(
        &state,
        &state
            .active_validators()
            .iter()
            .map(|v| (*v).clone())
            .collect::<Vec<_>>(),
        &source_storage,
    );

    let snapshot = state.to_snapshot_data(&source_storage, 0).unwrap();

    let dest_storage = SledStorage::open_temporary().unwrap();
    let meta = import_snapshot_to_storage(&dest_storage, &snapshot).unwrap();
    let restored =
        Ledger::restore_from_storage(&dest_storage, &meta, constants::NetworkId::Mainnet).unwrap();

    for n in &nullifiers {
        assert!(
            restored.state.is_spent(n),
            "nullifier should be marked as spent after snapshot restore"
        );
    }
    assert_eq!(restored.state.nullifier_count(), 10);
}

#[test]
fn test_snapshot_commitment_tree_integrity() {
    let source_storage = SledStorage::open_temporary().unwrap();
    let mut state = ChainState::new();
    let v = register_validator(&mut state);

    for i in 0..8 {
        add_test_commitment(&mut state, i);
    }

    let original_root = state.commitment_root();
    let original_count = state.commitment_count();

    persist_state_to_storage(&state, &source_storage);
    persist_validators_to_storage(&state, &[v], &source_storage);

    let snapshot = state.to_snapshot_data(&source_storage, 0).unwrap();

    let dest_storage = SledStorage::open_temporary().unwrap();
    let meta = import_snapshot_to_storage(&dest_storage, &snapshot).unwrap();
    let restored =
        Ledger::restore_from_storage(&dest_storage, &meta, constants::NetworkId::Mainnet).unwrap();

    assert_eq!(restored.state.commitment_root(), original_root);
    assert_eq!(restored.state.commitment_count(), original_count);
}

#[test]
fn test_snapshot_validator_bonds_preserved() {
    let source_storage = SledStorage::open_temporary().unwrap();
    let mut state = ChainState::new();

    let v1 = register_validator(&mut state);
    let v2 = register_validator(&mut state);

    let bond1 = state.validator_bond(&v1.id).unwrap();
    let bond2 = state.validator_bond(&v2.id).unwrap();

    persist_state_to_storage(&state, &source_storage);
    persist_validators_to_storage(&state, &[v1.clone(), v2.clone()], &source_storage);

    let snapshot = state.to_snapshot_data(&source_storage, 0).unwrap();

    let dest_storage = SledStorage::open_temporary().unwrap();
    let meta = import_snapshot_to_storage(&dest_storage, &snapshot).unwrap();
    let restored =
        Ledger::restore_from_storage(&dest_storage, &meta, constants::NetworkId::Mainnet).unwrap();

    assert!(restored.state.is_active_validator(&v1.id));
    assert!(restored.state.is_active_validator(&v2.id));
    assert_eq!(restored.state.validator_bond(&v1.id), Some(bond1));
    assert_eq!(restored.state.validator_bond(&v2.id), Some(bond2));
    assert_eq!(restored.state.total_validators(), 2);
}

#[test]
fn test_snapshot_serialization_roundtrip() {
    let source_storage = SledStorage::open_temporary().unwrap();
    let mut state = ChainState::new();
    let v = register_validator(&mut state);

    let mut nullifiers = Vec::new();
    for i in 0..5 {
        add_test_commitment(&mut state, i);
        nullifiers.push(add_test_nullifier(&mut state, i));
    }

    persist_state_to_storage(&state, &source_storage);
    persist_nullifiers_to_storage(&nullifiers, &source_storage);
    persist_validators_to_storage(&state, &[v], &source_storage);

    let snapshot = state.to_snapshot_data(&source_storage, 0).unwrap();

    let bytes = umbra::serialize(&snapshot).unwrap();
    let deserialized: umbra::state::SnapshotData = umbra::deserialize_snapshot(&bytes).unwrap();

    assert_eq!(deserialized.meta.epoch, snapshot.meta.epoch);
    assert_eq!(deserialized.meta.state_root, snapshot.meta.state_root);
    assert_eq!(deserialized.nullifiers.len(), snapshot.nullifiers.len());
}
