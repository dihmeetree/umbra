//! Storage persistence and recovery integration tests.
//!
//! Tests that vertices, transactions, validators, chain state metadata,
//! peer bans, and finalization batches survive sled close/reopen cycles.

use umbra::consensus::bft::Validator;
use umbra::consensus::dag::{Vertex, VertexId};
use umbra::constants;
use umbra::crypto::keys::{KemKeypair, Signature, SigningKeypair};
use umbra::crypto::nullifier::Nullifier;
use umbra::hash_domain;
use umbra::node::storage::{ChainStateMeta, FinalizationBatch, SledStorage, Storage};

// ── Helpers ──────────────────────────────────────────────────────────────

fn make_test_vertex(round: u64, seed: u8) -> Vertex {
    let keypair = SigningKeypair::generate();
    let proposer_fp = keypair.public.fingerprint();
    let tx_root = [0u8; 32];
    let parents = vec![VertexId([seed; 32])];
    let id = Vertex::compute_id(
        &parents,
        0,
        round,
        &proposer_fp,
        &tx_root,
        None,
        &[0u8; 32],
        constants::PROTOCOL_VERSION_ID,
    );
    Vertex {
        id,
        parents,
        epoch: 0,
        round,
        proposer: keypair.public,
        transactions: vec![],
        timestamp: round * 1000,
        state_root: [0u8; 32],
        signature: Signature::empty(),
        vrf_proof: None,
        protocol_version: constants::PROTOCOL_VERSION_ID,
    }
}

fn make_test_meta() -> ChainStateMeta {
    ChainStateMeta {
        epoch: 5,
        last_finalized: Some(VertexId([42u8; 32])),
        state_root: [1u8; 32],
        commitment_root: [2u8; 32],
        commitment_count: 100,
        nullifier_count: 50,
        nullifier_hash: [3u8; 32],
        epoch_fees: 1000,
        validator_count: 4,
        epoch_seed: [4u8; 32],
        finalized_count: 200,
        total_minted: 500_000,
        last_slash_epoch: Some(3),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[test]
fn test_vertex_persist_and_restore() {
    let dir = tempfile::tempdir().unwrap();
    let vertex = make_test_vertex(1, 1);
    let vid = vertex.id;

    {
        let storage = SledStorage::open(dir.path()).unwrap();
        storage.put_vertex(&vertex).unwrap();
        // Verify immediate read
        let loaded = storage.get_vertex(&vid).unwrap();
        assert!(loaded.is_some());
    }

    // Reopen and verify persistence
    {
        let storage = SledStorage::open(dir.path()).unwrap();
        let loaded = storage.get_vertex(&vid).unwrap();
        assert!(loaded.is_some());
        let v = loaded.unwrap();
        assert_eq!(v.id, vid);
        assert_eq!(v.round, 1);
    }
}

#[test]
fn test_finalization_batch_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let vertex = make_test_vertex(1, 10);
    let vid = vertex.id;
    let nullifier = Nullifier(hash_domain(b"test.null", &[1]));

    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let validator = Validator::with_kem(signing.public.clone(), kem.public.clone());
    let val_id = validator.id;

    let batch = FinalizationBatch {
        vertices: vec![vertex],
        transactions: vec![],
        nullifiers: vec![nullifier],
        commitment_levels: vec![(0, 0, [99u8; 32])],
        finalized_indices: vec![(0, vid)],
        validators: vec![(validator, 1_000_000, false)],
        removed_validators: vec![],
        coinbase_outputs: vec![],
        chain_state_meta: Some(make_test_meta()),
    };

    {
        let storage = SledStorage::open(dir.path()).unwrap();
        storage.apply_finalization_batch(&batch).unwrap();
    }

    // Reopen and verify all components persisted
    {
        let storage = SledStorage::open(dir.path()).unwrap();

        // Vertex stored
        assert!(storage.get_vertex(&vid).unwrap().is_some());

        // Nullifier stored
        assert!(storage.has_nullifier(&nullifier).unwrap());

        // Commitment level stored
        let cl = storage.get_commitment_level(0, 0).unwrap();
        assert_eq!(cl, Some([99u8; 32]));

        // Finalized index stored (after_sequence=u64::MAX means start from 0)
        let finalized = storage.get_finalized_vertices_after(u64::MAX, 10).unwrap();
        assert!(!finalized.is_empty());

        // Validator stored
        let val_rec = storage.get_validator(&val_id).unwrap();
        assert!(val_rec.is_some());
        let rec = val_rec.unwrap();
        assert_eq!(rec.bond, 1_000_000);
        assert!(!rec.slashed);

        // Meta stored
        let meta = storage.get_chain_state_meta().unwrap();
        assert!(meta.is_some());
        assert_eq!(meta.unwrap().epoch, 5);
    }
}

#[test]
fn test_chain_state_meta_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let meta = make_test_meta();

    {
        let storage = SledStorage::open(dir.path()).unwrap();
        storage.put_chain_state_meta(&meta).unwrap();
    }

    {
        let storage = SledStorage::open(dir.path()).unwrap();
        let loaded = storage.get_chain_state_meta().unwrap().unwrap();
        assert_eq!(loaded.epoch, meta.epoch);
        assert_eq!(loaded.state_root, meta.state_root);
        assert_eq!(loaded.commitment_root, meta.commitment_root);
        assert_eq!(loaded.commitment_count, meta.commitment_count);
        assert_eq!(loaded.nullifier_count, meta.nullifier_count);
        assert_eq!(loaded.total_minted, meta.total_minted);
        assert_eq!(loaded.epoch_fees, meta.epoch_fees);
        assert_eq!(loaded.finalized_count, meta.finalized_count);
        assert_eq!(loaded.last_slash_epoch, meta.last_slash_epoch);
    }
}

#[test]
fn test_validator_storage_roundtrip() {
    let dir = tempfile::tempdir().unwrap();

    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let validator = Validator::with_kem(signing.public.clone(), kem.public.clone());
    let val_id = validator.id;

    {
        let storage = SledStorage::open(dir.path()).unwrap();
        storage.put_validator(&validator, 2_000_000, true).unwrap();
    }

    {
        let storage = SledStorage::open(dir.path()).unwrap();
        let rec = storage.get_validator(&val_id).unwrap().unwrap();
        assert_eq!(rec.bond, 2_000_000);
        assert!(rec.slashed);
        assert_eq!(rec.validator.id, val_id);
    }
}

#[test]
fn test_ledger_restore_from_storage() {
    use umbra::state::{import_snapshot_to_storage, ChainState, Ledger};

    let source_storage = SledStorage::open_temporary().unwrap();

    // Build state with a genesis validator
    let mut state = ChainState::new();
    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let validator = Validator::with_kem(signing.public.clone(), kem.public.clone());
    state.register_genesis_validator(validator.clone()).unwrap();

    // Persist commitment tree and validator to storage
    let depth = constants::MERKLE_DEPTH;
    for level in 0..=depth {
        for idx in 0..state.commitment_tree_level_len(level) {
            let hash = state.commitment_tree_node(level, idx);
            source_storage
                .put_commitment_level(level, idx, &hash)
                .unwrap();
        }
    }
    source_storage
        .put_validator(
            &validator,
            state.validator_bond(&validator.id).unwrap(),
            false,
        )
        .unwrap();

    // Export snapshot and import to new storage (ensures consistent restore)
    let snapshot = state.to_snapshot_data(&source_storage, 0).unwrap();
    let dest_storage = SledStorage::open_temporary().unwrap();
    let meta = import_snapshot_to_storage(&dest_storage, &snapshot).unwrap();

    let restored =
        Ledger::restore_from_storage(&dest_storage, &meta, constants::NetworkId::Mainnet);
    assert!(restored.is_ok());

    let ledger = restored.unwrap();
    assert_eq!(ledger.state.epoch(), meta.epoch);
    assert_eq!(ledger.state.state_root(), meta.state_root);
}

#[test]
fn test_peer_ban_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let peer_id = hash_domain(b"test.peer", &[1]);
    let banned_until = 999_999u64;

    {
        let storage = SledStorage::open(dir.path()).unwrap();
        storage.put_peer_ban(&peer_id, banned_until).unwrap();
    }

    {
        let storage = SledStorage::open(dir.path()).unwrap();
        let bans = storage.get_peer_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, peer_id);
        assert_eq!(bans[0].1, banned_until);

        // Remove ban and verify
        storage.remove_peer_ban(&peer_id).unwrap();
        let bans = storage.get_peer_bans().unwrap();
        assert!(bans.is_empty());
    }
}

#[test]
fn test_crash_recovery_markers() {
    let dir = tempfile::tempdir().unwrap();

    {
        let storage = SledStorage::open(dir.path()).unwrap();
        assert!(!storage.is_import_in_progress().unwrap());

        storage.set_import_in_progress(true).unwrap();
        assert!(storage.is_import_in_progress().unwrap());
    }

    // Reopen — marker persists (simulates crash during import)
    {
        let storage = SledStorage::open(dir.path()).unwrap();
        assert!(
            storage.is_import_in_progress().unwrap(),
            "import_in_progress should survive restart"
        );

        // Clear the marker
        storage.set_import_in_progress(false).unwrap();
        assert!(!storage.is_import_in_progress().unwrap());
    }
}
