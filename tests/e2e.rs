//! End-to-end integration tests for the Umbra cryptocurrency.
//!
//! These tests exercise the public API across multiple modules to verify
//! complete flows: transaction lifecycle, BFT certification, validator
//! management, wallet operations, snapshot sync, and more.
//!
//! Tests are organized into three groups:
//! - **Group A** (fast): No STARK proofs, test consensus/state/crypto flows
//! - **Group B** (medium): One STARK proof each, test full transaction flows
//! - **Group C** (slow, `#[ignore]`): Multiple STARK proofs, multi-step flows

use umbra::consensus::bft::{vote_sign_data, BftState, Certificate, Validator, Vote, VoteType};
use umbra::consensus::dag::{Dag, Vertex, VertexId};
use umbra::constants;
use umbra::crypto::commitment::{BlindingFactor, Commitment};
use umbra::crypto::keys::{FullKeypair, KemKeypair, Signature, SigningKeypair};
use umbra::crypto::nullifier::Nullifier;
use umbra::crypto::proof::build_merkle_tree;
use umbra::network::{decode_message, encode_message, Message};
use umbra::node::mempool::Mempool;
use umbra::node::storage::{SledStorage, Storage};
use umbra::state::{import_snapshot_to_storage, ChainState, Ledger, SnapshotData};
use umbra::transaction::builder::{InputSpec, TransactionBuilder};
use umbra::transaction::{Transaction, TxType};
use umbra::wallet::Wallet;
use umbra::{deserialize_snapshot, hash_domain, serialize};

// ── Helpers ─────────────────────────────────────────────────────────────

/// Lightweight STARK proof options for faster test execution.
fn test_proof_options() -> winterfell::ProofOptions {
    winterfell::ProofOptions::new(
        42,
        8,
        10,
        winterfell::FieldExtension::Quadratic,
        8,
        255,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}

/// Build a test vertex using only public APIs. Uses `insert_unchecked` since
/// the vertex has an empty signature (we skip signature verification in tests).
fn build_test_vertex(
    parents: Vec<VertexId>,
    round: u64,
    epoch: u64,
    proposer: &umbra::crypto::keys::SigningPublicKey,
    transactions: Vec<Transaction>,
) -> Vertex {
    let proposer_fp = proposer.fingerprint();
    let tx_root = if transactions.is_empty() {
        [0u8; 32]
    } else {
        let tx_hashes: Vec<umbra::Hash> = transactions.iter().map(|tx| tx.tx_id().0).collect();
        let (root, _) = build_merkle_tree(&tx_hashes);
        root
    };
    let id = Vertex::compute_id(
        &parents,
        epoch,
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
        epoch,
        round,
        proposer: proposer.clone(),
        transactions,
        timestamp: round * 1000,
        state_root: [0u8; 32],
        signature: Signature::empty(),
        vrf_proof: None,
        protocol_version: constants::PROTOCOL_VERSION_ID,
    }
}

/// Build a valid transfer transaction against the current state, with a real
/// STARK proof. The commitment is added to state first so the merkle root matches.
/// `value` must exceed `compute_weight_fee(1, 0)` (currently 200).
fn build_valid_transfer(state: &mut ChainState, value: u64, seed: u8) -> Transaction {
    let det_fee = constants::compute_weight_fee(1, 0);
    assert!(
        value > det_fee,
        "input value ({}) must exceed fee ({})",
        value,
        det_fee
    );

    let blinding = BlindingFactor::from_bytes([seed; 32]);
    let spend_auth = hash_domain(b"test.spend_auth", &[seed]);
    let commitment = Commitment::commit(value, &blinding);

    state.add_commitment(commitment).unwrap();
    let index = state.find_commitment(&commitment).unwrap();
    let merkle_path = state.commitment_path(index).unwrap();

    let recipient = FullKeypair::generate();
    TransactionBuilder::new()
        .add_input(InputSpec {
            value,
            blinding,
            spend_auth,
            merkle_path,
        })
        .add_output(recipient.kem.public.clone(), value - det_fee)
        .set_proof_options(test_proof_options())
        .build()
        .unwrap()
}

/// Fund a wallet via genesis coinbase and have it scan the output.
fn fund_wallet_via_genesis(state: &mut ChainState, wallet: &mut Wallet) {
    let output = state
        .create_genesis_coinbase(wallet.kem_public_key())
        .expect("genesis coinbase creation should succeed");
    wallet.scan_coinbase_output(&output, Some(state));
}

/// Generate a committee of n validators with signing keypairs.
fn setup_committee(n: usize) -> (Vec<SigningKeypair>, Vec<Validator>) {
    let mut keypairs = Vec::with_capacity(n);
    let mut validators = Vec::with_capacity(n);
    for _ in 0..n {
        let kp = SigningKeypair::generate();
        let v = Validator::new(kp.public.clone());
        keypairs.push(kp);
        validators.push(v);
    }
    (keypairs, validators)
}

/// Register a genesis validator with KEM key, returning the keypairs.
fn register_genesis_validator(state: &mut ChainState) -> (SigningKeypair, KemKeypair) {
    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let validator = Validator::with_kem(signing.public.clone(), kem.public.clone());
    state.register_genesis_validator(validator);
    (signing, kem)
}

// ── Group A: Fast tests (no STARK proofs) ───────────────────────────────

#[test]
fn test_bft_certification_flow() {
    let (keypairs, validators) = setup_committee(4);
    let chain_id = constants::chain_id();
    let mut bft = BftState::new(0, validators.clone(), chain_id);

    // Create a vertex
    let genesis_id = Dag::genesis_vertex().id;
    let vertex = build_test_vertex(vec![genesis_id], 1, 0, &keypairs[0].public, vec![]);
    let vertex_id = vertex.id;

    // Collect votes from 3 of 4 committee members (quorum for 4 = 3)
    // BftState starts at round 0, so votes must use round 0
    let mut certificate: Option<Certificate> = None;
    for (i, kp) in keypairs.iter().enumerate().take(3) {
        let sign_data = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let vote = Vote {
            vertex_id,
            voter_id: validators[i].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: kp.sign(&sign_data),
            vrf_proof: None,
        };
        certificate = bft.receive_vote(vote);
    }

    let cert = certificate.expect("quorum should produce a certificate");
    assert_eq!(cert.vertex_id, vertex_id);
    assert!(cert.verify(&validators, &chain_id));
    assert!(cert.signatures.len() >= 3);
}

#[test]
fn test_equivocation_detection() {
    let (keypairs, validators) = setup_committee(4);
    let chain_id = constants::chain_id();
    let mut bft = BftState::new(0, validators.clone(), chain_id);

    let genesis_id = Dag::genesis_vertex().id;

    // Two different vertices in the same round
    let v_a = build_test_vertex(vec![genesis_id], 1, 0, &keypairs[0].public, vec![]);
    let v_b = build_test_vertex(vec![genesis_id], 1, 0, &keypairs[1].public, vec![]);

    // Validator 0 votes for vertex A (BftState round = 0)
    let sign_data_a = vote_sign_data(&v_a.id, 0, 0, &VoteType::Accept, &chain_id);
    let vote_a = Vote {
        vertex_id: v_a.id,
        voter_id: validators[0].id,
        epoch: 0,
        round: 0,
        vote_type: VoteType::Accept,
        signature: keypairs[0].sign(&sign_data_a),
        vrf_proof: None,
    };
    bft.receive_vote(vote_a);

    // Same validator votes for vertex B (equivocation)
    let sign_data_b = vote_sign_data(&v_b.id, 0, 0, &VoteType::Accept, &chain_id);
    let vote_b = Vote {
        vertex_id: v_b.id,
        voter_id: validators[0].id,
        epoch: 0,
        round: 0,
        vote_type: VoteType::Accept,
        signature: keypairs[0].sign(&sign_data_b),
        vrf_proof: None,
    };
    bft.receive_vote(vote_b);

    // Equivocation should be detected
    let equivocations = bft.equivocations();
    assert!(
        !equivocations.is_empty(),
        "equivocation should be detected when same validator votes for two vertices in same round"
    );
    assert_eq!(equivocations[0].voter_id, validators[0].id);
}

#[test]
fn test_equivocation_slashing() {
    let mut state = ChainState::new();

    let kp = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let validator = Validator::with_kem(kp.public.clone(), kem.public.clone());
    let vid = validator.id;
    state.register_genesis_validator(validator);

    assert!(state.is_active_validator(&vid));
    assert_eq!(
        state.validator_bond(&vid),
        Some(constants::VALIDATOR_BASE_BOND)
    );

    // Slash the validator
    state.slash_validator(&vid).unwrap();

    assert!(!state.is_active_validator(&vid));
    assert!(state.is_slashed(&vid));
    // Bond should be forfeited (None after slash)
    assert_eq!(state.validator_bond(&vid), None);
    // Forfeited bond goes to epoch fees
    assert!(state.epoch_fees() >= constants::VALIDATOR_BASE_BOND);
}

#[test]
fn test_epoch_advancement() {
    let mut state = ChainState::new();
    assert_eq!(state.epoch(), 0);

    let initial_seed = state.epoch_seed().seed;

    let (fees1, seed1) = state.advance_epoch();
    assert_eq!(state.epoch(), 1);
    assert_eq!(fees1, 0); // No fees accumulated
    assert_eq!(state.epoch_fees(), 0); // Reset
    assert_ne!(seed1.seed, initial_seed, "seed should rotate each epoch");

    let (fees2, seed2) = state.advance_epoch();
    assert_eq!(state.epoch(), 2);
    assert_eq!(fees2, 0);
    assert_ne!(seed2.seed, seed1.seed, "seed should change again");
}

#[test]
fn test_epoch_fee_distribution() {
    let mut state = ChainState::new();

    // Register and slash a validator to generate fees
    let kp = SigningKeypair::generate();
    let validator = Validator::new(kp.public.clone());
    let vid = validator.id;
    state.register_genesis_validator(validator);
    state.slash_validator(&vid).unwrap();

    let fees_before = state.epoch_fees();
    assert!(
        fees_before > 0,
        "slashing should generate fees from forfeited bond"
    );

    let (distributed, _new_seed) = state.advance_epoch();
    assert_eq!(distributed, fees_before);
    assert_eq!(
        state.epoch_fees(),
        0,
        "fees should reset after epoch advance"
    );
    assert_eq!(state.epoch(), 1);
}

#[test]
fn test_snapshot_export_import() {
    let storage1 = SledStorage::open_temporary().unwrap();
    let mut state = ChainState::new();

    // Add commitments
    for i in 0..5u64 {
        let blind = BlindingFactor::from_bytes([i as u8 + 1; 32]);
        state
            .add_commitment(Commitment::commit(i * 100 + 1, &blind))
            .unwrap();
    }

    // Add nullifiers
    let n1 = Nullifier::derive(&[10u8; 32], &[20u8; 32]);
    let n2 = Nullifier::derive(&[30u8; 32], &[40u8; 32]);
    state.mark_nullifier(n1).unwrap();
    state.mark_nullifier(n2).unwrap();

    // Add a validator
    let kp = SigningKeypair::generate();
    let validator = Validator::new(kp.public.clone());
    state.register_genesis_validator(validator.clone());

    // Persist tree nodes to storage
    let depth = constants::MERKLE_DEPTH;
    for level in 0..=depth {
        for idx in 0..state.commitment_tree_level_len(level) {
            let hash = state.commitment_tree_node(level, idx);
            storage1.put_commitment_level(level, idx, &hash).unwrap();
        }
    }
    storage1.put_nullifier(&n1).unwrap();
    storage1.put_nullifier(&n2).unwrap();
    let bond = state.validator_bond(&validator.id).unwrap_or(0);
    storage1.put_validator(&validator, bond, false).unwrap();

    let original_root = state.state_root();
    let original_commitment_root = state.commitment_root();

    // Export snapshot
    let snapshot = state.to_snapshot_data(&storage1, 42).unwrap();
    assert_eq!(snapshot.meta.commitment_count, 5);
    assert_eq!(snapshot.meta.nullifier_count, 2);

    // Simulate network transfer: serialize + deserialize
    let bytes = serialize(&snapshot).unwrap();
    let received: SnapshotData = deserialize_snapshot(&bytes).unwrap();

    // Import into fresh storage
    let storage2 = SledStorage::open_temporary().unwrap();
    let meta = import_snapshot_to_storage(&storage2, &received).unwrap();

    assert_eq!(meta.state_root, original_root);
    assert_eq!(meta.commitment_root, original_commitment_root);
    assert_eq!(meta.commitment_count, 5);
    assert_eq!(meta.nullifier_count, 2);

    // Restore state and verify
    let restored = ChainState::restore_from_storage(&storage2, &meta).unwrap();
    assert_eq!(restored.commitment_root(), original_commitment_root);
    assert_eq!(restored.state_root(), original_root);
    assert_eq!(restored.nullifier_count(), 2);
    assert!(restored.is_spent(&n1));
    assert!(restored.is_spent(&n2));
    assert!(restored.is_active_validator(&validator.id));
}

#[test]
fn test_coinbase_reward_halving() {
    // Epoch 0-499: initial reward
    assert_eq!(
        constants::block_reward_for_epoch(0),
        constants::INITIAL_BLOCK_REWARD
    );
    assert_eq!(
        constants::block_reward_for_epoch(499),
        constants::INITIAL_BLOCK_REWARD
    );

    // First halving at epoch 500
    assert_eq!(
        constants::block_reward_for_epoch(500),
        constants::INITIAL_BLOCK_REWARD / 2
    );

    // Second halving at epoch 1000
    assert_eq!(
        constants::block_reward_for_epoch(1000),
        constants::INITIAL_BLOCK_REWARD / 4
    );

    // Eventually reaches zero
    assert_eq!(
        constants::block_reward_for_epoch(constants::HALVING_INTERVAL_EPOCHS * 63),
        0
    );
    assert_eq!(constants::block_reward_for_epoch(u64::MAX), 0);

    // Monotonic decrease
    let mut prev = constants::block_reward_for_epoch(0);
    for epoch in (0..5000).step_by(500) {
        let reward = constants::block_reward_for_epoch(epoch);
        assert!(reward <= prev, "reward should decrease or stay same");
        prev = reward;
    }
}

#[test]
fn test_dynamic_bond_scaling() {
    assert_eq!(
        constants::required_validator_bond(0),
        constants::VALIDATOR_BASE_BOND
    );
    assert_eq!(constants::required_validator_bond(10), 1_100_000);
    assert_eq!(constants::required_validator_bond(100), 2_000_000);
    assert_eq!(constants::required_validator_bond(500), 6_000_000);

    // Monotonic increase
    for n in 0..100 {
        assert!(constants::required_validator_bond(n) <= constants::required_validator_bond(n + 1));
    }
}

#[test]
fn test_network_message_roundtrip() {
    // GetTips
    let msg = Message::GetTips;
    let bytes = encode_message(&msg).unwrap();
    let decoded = decode_message(&bytes).unwrap();
    assert!(matches!(decoded, Message::GetTips));

    // TipsResponse
    let genesis_id = Dag::genesis_vertex().id;
    let msg = Message::TipsResponse(vec![genesis_id]);
    let bytes = encode_message(&msg).unwrap();
    let decoded = decode_message(&bytes).unwrap();
    if let Message::TipsResponse(tips) = decoded {
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0], genesis_id);
    } else {
        panic!("expected TipsResponse");
    }

    // GetPeers
    let msg = Message::GetPeers;
    let bytes = encode_message(&msg).unwrap();
    let decoded = decode_message(&bytes).unwrap();
    assert!(matches!(decoded, Message::GetPeers));

    // GetFinalizedVertices
    let msg = Message::GetFinalizedVertices {
        after_sequence: 0,
        limit: 100,
    };
    let bytes = encode_message(&msg).unwrap();
    let decoded = decode_message(&bytes).unwrap();
    if let Message::GetFinalizedVertices {
        after_sequence,
        limit,
    } = decoded
    {
        assert_eq!(after_sequence, 0);
        assert_eq!(limit, 100);
    } else {
        panic!("expected GetFinalizedVertices");
    }
}

#[test]
fn test_chain_id_consistency() {
    let cid = constants::chain_id();
    assert_ne!(cid, [0u8; 32], "chain_id should not be all zeros");
    assert_eq!(
        cid,
        constants::chain_id(),
        "chain_id should be deterministic"
    );

    let state = ChainState::new();
    assert_eq!(
        *state.chain_id(),
        cid,
        "ChainState should use the same chain_id"
    );
}

#[test]
fn test_nullifier_double_spend_direct() {
    let mut state = ChainState::new();
    let nf = Nullifier::derive(&[42u8; 32], &[43u8; 32]);

    assert!(!state.is_spent(&nf));
    state.mark_nullifier(nf).unwrap();
    assert!(state.is_spent(&nf));
    assert_eq!(state.nullifier_count(), 1);

    // Idempotent: marking again doesn't change count
    state.mark_nullifier(nf).unwrap();
    assert_eq!(state.nullifier_count(), 1);
}

#[test]
fn test_dag_vertex_insertion_finalization() {
    let genesis = Dag::genesis_vertex();
    let genesis_id = genesis.id;
    let mut dag = Dag::new(genesis);

    assert!(dag.tips().contains(&genesis_id));

    // Insert a vertex
    let proposer = SigningKeypair::generate();
    let v1 = build_test_vertex(vec![genesis_id], 1, 0, &proposer.public, vec![]);
    let v1_id = v1.id;
    dag.insert_unchecked(v1).unwrap();

    assert!(dag.tips().contains(&v1_id));
    assert!(
        !dag.tips().contains(&genesis_id),
        "genesis should no longer be a tip"
    );
    assert!(!dag.is_finalized(&v1_id));

    dag.finalize(&v1_id);
    assert!(dag.is_finalized(&v1_id));

    let order = dag.finalized_order();
    assert!(order.contains(&genesis_id));
    assert!(order.contains(&v1_id));
}

#[test]
fn test_ledger_finalize_with_certificate() {
    let mut ledger = Ledger::new();
    let chain_id = constants::chain_id();

    // Create 4 validators with KEM keys
    let mut keypairs = Vec::new();
    let mut validators = Vec::new();
    for _ in 0..4 {
        let kp = SigningKeypair::generate();
        let kem = KemKeypair::generate();
        let v = Validator::with_kem(kp.public.clone(), kem.public.clone());
        ledger.state.register_genesis_validator(v.clone());
        keypairs.push(kp);
        validators.push(v);
    }

    let mut bft = BftState::new(0, validators.clone(), chain_id);
    let genesis_id = *ledger.dag.tips().iter().next().unwrap();

    // Build and insert vertex
    let vertex = build_test_vertex(vec![genesis_id], 1, 0, &keypairs[0].public, vec![]);
    let vertex_id = vertex.id;
    ledger.dag.insert_unchecked(vertex).unwrap();

    // Collect 3 votes to form certificate (quorum for 4 = 3)
    // BftState starts at round 0
    let mut certificate: Option<Certificate> = None;
    for (i, kp) in keypairs.iter().enumerate().take(3) {
        let sign_data = vote_sign_data(&vertex_id, 0, 0, &VoteType::Accept, &chain_id);
        let vote = Vote {
            vertex_id,
            voter_id: validators[i].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: kp.sign(&sign_data),
            vrf_proof: None,
        };
        certificate = bft.receive_vote(vote);
    }

    let cert = certificate.expect("3/4 votes should produce certificate");

    // Finalize via Ledger (verifies certificate + applies state)
    let result = ledger.finalize_vertex(&vertex_id, &cert, &validators, &chain_id);
    assert!(result.is_ok(), "finalize_vertex failed: {:?}", result.err());
    assert!(ledger.dag.is_finalized(&vertex_id));
}

#[test]
fn test_wallet_creation_and_balance() {
    let w1 = Wallet::new();
    let w2 = Wallet::new();

    assert_eq!(w1.balance(), 0);
    assert!(w1.unspent_outputs().is_empty());
    assert!(w1.history().is_empty());

    // Different wallets should have different keys (with overwhelming probability)
    assert_ne!(
        w1.kem_public_key().as_bytes(),
        w2.kem_public_key().as_bytes()
    );
}

#[test]
fn test_commitment_tree_operations() {
    let mut state = ChainState::new();
    let root_before = state.commitment_root();
    assert_eq!(state.commitment_count(), 0);

    // Add 5 commitments
    for i in 0..5u64 {
        let blind = BlindingFactor::from_bytes([i as u8 + 1; 32]);
        let c = Commitment::commit(i * 100 + 1, &blind);
        state.add_commitment(c).unwrap();
        assert_eq!(
            state.find_commitment(&c),
            Some(i as usize),
            "commitment {} should be at index {}",
            i,
            i
        );
    }

    assert_eq!(state.commitment_count(), 5);
    assert_ne!(
        state.commitment_root(),
        root_before,
        "root should change after insertions"
    );

    // Merkle path should exist for valid index
    assert!(state.commitment_path(0).is_some());
    assert!(state.commitment_path(4).is_some());
    // Out-of-range index should return None
    assert!(state.commitment_path(999).is_none());
}

#[test]
fn test_privacy_commitment_properties() {
    let bf1 = BlindingFactor::from_bytes([1u8; 32]);
    let bf2 = BlindingFactor::from_bytes([2u8; 32]);

    // Hiding: same value, different blinding -> different commitment
    let c1 = Commitment::commit(100, &bf1);
    let c2 = Commitment::commit(100, &bf2);
    assert_ne!(
        c1, c2,
        "different blindings should produce different commitments"
    );

    // Binding: correct opening verifies
    assert!(c1.verify(100, &bf1));
    // Wrong value fails
    assert!(!c1.verify(99, &bf1));
    // Wrong blinding fails
    assert!(!c1.verify(100, &bf2));

    // Different values produce different commitments
    let c3 = Commitment::commit(200, &bf1);
    assert_ne!(c1, c3);

    // Nullifier determinism: same inputs -> same nullifier
    let n1 = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
    let n2 = Nullifier::derive(&[1u8; 32], &[2u8; 32]);
    assert_eq!(n1, n2, "nullifier derivation should be deterministic");

    // Different inputs -> different nullifier
    let n3 = Nullifier::derive(&[1u8; 32], &[3u8; 32]);
    assert_ne!(n1, n3);
}

// ── Group B: Medium tests (1 STARK proof each) ─────────────────────────

#[test]
fn test_transaction_lifecycle() {
    let mut state = ChainState::new();
    let (val_signing, _val_kem) = register_genesis_validator(&mut state);
    let genesis_id = Dag::genesis_vertex().id;

    let commitments_before = state.commitment_count();
    let nullifiers_before = state.nullifier_count();

    // Build a valid transfer with STARK proof
    let tx = build_valid_transfer(&mut state, 10_000, 1);
    let tx_nullifier = tx.inputs[0].nullifier;
    let det_fee = constants::compute_weight_fee(1, 0);
    assert_eq!(tx.fee, det_fee);
    assert_eq!(tx.chain_id, constants::chain_id());

    // Create vertex and apply
    let vertex = build_test_vertex(vec![genesis_id], 1, 0, &val_signing.public, vec![tx]);
    state.apply_vertex(&vertex).unwrap();

    // Verify nullifier recorded
    assert!(state.is_spent(&tx_nullifier));
    assert_eq!(state.nullifier_count(), nullifiers_before + 1);

    // Verify commitments added (1 from build_valid_transfer setup + tx output + coinbase)
    assert!(state.commitment_count() > commitments_before);

    // Verify fee accumulated
    assert_eq!(state.epoch_fees(), det_fee);
}

#[test]
fn test_double_spend_prevention() {
    let mut state = ChainState::new();
    let (val_signing, _) = register_genesis_validator(&mut state);
    let genesis_id = Dag::genesis_vertex().id;

    let tx = build_valid_transfer(&mut state, 10_000, 1);

    // First application: success
    let vertex = build_test_vertex(
        vec![genesis_id],
        1,
        0,
        &val_signing.public,
        vec![tx.clone()],
    );
    state.apply_vertex(&vertex).unwrap();

    // Second validation of same tx: double-spend
    let result = state.validate_transaction(&tx);
    assert!(
        matches!(result, Err(umbra::state::StateError::DoubleSpend(_))),
        "expected DoubleSpend, got {:?}",
        result
    );
}

#[test]
fn test_mempool_insert_drain() {
    let mut state = ChainState::new();
    let tx = build_valid_transfer(&mut state, 10_000, 1);
    let tx_id = tx.tx_id();

    let mut mempool = Mempool::with_defaults();
    mempool.insert(tx).unwrap();
    assert_eq!(mempool.len(), 1);
    assert!(!mempool.is_empty());

    let drained = mempool.drain_highest_fee(10);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].tx_id(), tx_id);
    assert!(mempool.is_empty());
}

#[test]
fn test_wallet_encrypted_message() {
    let mut state = ChainState::new();
    register_genesis_validator(&mut state);

    let mut sender = Wallet::new();
    fund_wallet_via_genesis(&mut state, &mut sender);
    sender.resolve_commitment_indices(&state);

    let mut recipient = Wallet::new();
    let msg_text = b"hello from umbra e2e test".to_vec();

    let tx = sender
        .build_transaction_with_state(
            recipient.kem_public_key(),
            1_000,
            Some(msg_text.clone()),
            Some(&state),
        )
        .unwrap();

    assert!(!tx.messages.is_empty(), "tx should contain a message");

    // Recipient scans and decrypts
    recipient.scan_transaction(&tx);
    let messages = recipient.received_messages();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].content, msg_text);
}

#[test]
fn test_validator_registration_e2e() {
    let mut state = ChainState::new();
    // Register a proposer validator for coinbase
    let (val_signing, _) = register_genesis_validator(&mut state);
    let genesis_id = Dag::genesis_vertex().id;

    // New validator to register
    let new_signing = SigningKeypair::generate();
    let new_kem = KemKeypair::generate();
    let required_bond = constants::required_validator_bond(state.total_validators());
    let total_fee = required_bond + constants::MIN_TX_FEE;
    let output_value = 10_000u64;
    let input_value = total_fee + output_value;

    // Add commitment to state for spending
    let blinding = BlindingFactor::from_bytes([77u8; 32]);
    let spend_auth = hash_domain(b"test.spend_auth", &[77u8]);
    let commitment = Commitment::commit(input_value, &blinding);
    state.add_commitment(commitment).unwrap();
    let index = state.find_commitment(&commitment).unwrap();
    let merkle_path = state.commitment_path(index).unwrap();

    let recipient = FullKeypair::generate();
    let tx = TransactionBuilder::new()
        .add_input(InputSpec {
            value: input_value,
            blinding,
            spend_auth,
            merkle_path,
        })
        .add_output(recipient.kem.public.clone(), output_value)
        .set_fee(total_fee)
        .set_tx_type(TxType::ValidatorRegister {
            signing_key: new_signing.public.clone(),
            kem_public_key: new_kem.public.clone(),
        })
        .set_proof_options(test_proof_options())
        .build()
        .unwrap();

    // Apply via vertex
    let vertex = build_test_vertex(vec![genesis_id], 1, 0, &val_signing.public, vec![tx]);
    state.apply_vertex(&vertex).unwrap();

    // Verify validator registered
    let vid = new_signing.public.fingerprint();
    assert!(
        state.is_active_validator(&vid),
        "new validator should be active after registration"
    );
    assert_eq!(
        state.get_validator(&vid).unwrap().activation_epoch,
        1,
        "activation should be next epoch (current=0, so activation=1)"
    );
    assert_eq!(
        state.validator_bond(&vid),
        Some(required_bond),
        "bond should be escrowed"
    );
}

#[test]
fn test_full_wallet_lifecycle() {
    let mut state = ChainState::new();
    let (val_signing, _) = register_genesis_validator(&mut state);
    let genesis_id = Dag::genesis_vertex().id;

    // Fund sender wallet
    let mut sender = Wallet::new();
    fund_wallet_via_genesis(&mut state, &mut sender);
    assert_eq!(sender.balance(), constants::GENESIS_MINT);
    sender.resolve_commitment_indices(&state);

    // Build transfer to recipient
    let mut recipient = Wallet::new();
    let send_amount = 50_000u64;
    let tx = sender
        .build_transaction_with_state(recipient.kem_public_key(), send_amount, None, Some(&state))
        .unwrap();

    let tx_fee = tx.fee;
    let tx_binding = tx.tx_binding;

    // Apply via vertex
    let vertex = build_test_vertex(
        vec![genesis_id],
        1,
        0,
        &val_signing.public,
        vec![tx.clone()],
    );
    state.apply_vertex(&vertex).unwrap();

    // Recipient scans and receives funds
    recipient.scan_transaction_with_state(&tx, Some(&state));
    assert_eq!(recipient.balance(), send_amount);
    assert_eq!(recipient.history().len(), 1);

    // Sender scans their own tx to detect the change output
    sender.scan_transaction_with_state(&tx, Some(&state));
    // Confirm sender's pending tx (marks original UTXO as Spent)
    sender.confirm_transaction(&tx_binding);
    // Sender should have change: GENESIS_MINT - send_amount - fee
    let expected_sender_balance = constants::GENESIS_MINT - send_amount - tx_fee;
    assert_eq!(sender.balance(), expected_sender_balance);
}

// ── Group C: Slow tests (multiple STARK proofs) ────────────────────────

#[test]
#[ignore] // Generates 2 STARK proofs -- slow in debug mode
fn test_multi_transaction_vertex() {
    let mut state = ChainState::new();
    let (val_signing, _) = register_genesis_validator(&mut state);
    let genesis_id = Dag::genesis_vertex().id;

    let det_fee = constants::compute_weight_fee(1, 0);

    // Add both source commitments to the tree FIRST so both txs see the same root
    let blinding1 = BlindingFactor::from_bytes([1u8; 32]);
    let spend_auth1 = hash_domain(b"test.spend_auth", &[1u8]);
    let commitment1 = Commitment::commit(10_000, &blinding1);
    state.add_commitment(commitment1).unwrap();

    let blinding2 = BlindingFactor::from_bytes([2u8; 32]);
    let spend_auth2 = hash_domain(b"test.spend_auth", &[2u8]);
    let commitment2 = Commitment::commit(20_000, &blinding2);
    state.add_commitment(commitment2).unwrap();

    // Now build both txs against the same merkle root
    let idx1 = state.find_commitment(&commitment1).unwrap();
    let path1 = state.commitment_path(idx1).unwrap();
    let recipient1 = FullKeypair::generate();
    let tx1 = TransactionBuilder::new()
        .add_input(InputSpec {
            value: 10_000,
            blinding: blinding1,
            spend_auth: spend_auth1,
            merkle_path: path1,
        })
        .add_output(recipient1.kem.public.clone(), 10_000 - det_fee)
        .set_proof_options(test_proof_options())
        .build()
        .unwrap();

    let idx2 = state.find_commitment(&commitment2).unwrap();
    let path2 = state.commitment_path(idx2).unwrap();
    let recipient2 = FullKeypair::generate();
    let tx2 = TransactionBuilder::new()
        .add_input(InputSpec {
            value: 20_000,
            blinding: blinding2,
            spend_auth: spend_auth2,
            merkle_path: path2,
        })
        .add_output(recipient2.kem.public.clone(), 20_000 - det_fee)
        .set_proof_options(test_proof_options())
        .build()
        .unwrap();

    let nf1 = tx1.inputs[0].nullifier;
    let nf2 = tx2.inputs[0].nullifier;

    let vertex = build_test_vertex(vec![genesis_id], 1, 0, &val_signing.public, vec![tx1, tx2]);
    state.apply_vertex(&vertex).unwrap();

    assert!(state.is_spent(&nf1));
    assert!(state.is_spent(&nf2));
    assert_eq!(state.epoch_fees(), det_fee * 2);
}

#[test]
#[ignore] // Generates 2 STARK proofs -- slow in debug mode
fn test_validator_full_lifecycle() {
    let mut state = ChainState::new();
    let (proposer_signing, _proposer_kem) = register_genesis_validator(&mut state);
    let genesis_id = Dag::genesis_vertex().id;

    // --- Phase 1: Register a new validator ---
    let new_signing = SigningKeypair::generate();
    let new_kem = KemKeypair::generate();
    let required_bond = constants::required_validator_bond(state.total_validators());
    let reg_fee = required_bond + constants::MIN_TX_FEE;
    let reg_output = 5_000u64;
    let reg_input = reg_fee + reg_output;

    let blinding1 = BlindingFactor::from_bytes([11u8; 32]);
    let spend_auth1 = hash_domain(b"test.spend_auth", &[11u8]);
    let commitment1 = Commitment::commit(reg_input, &blinding1);
    state.add_commitment(commitment1).unwrap();
    let idx1 = state.find_commitment(&commitment1).unwrap();
    let path1 = state.commitment_path(idx1).unwrap();

    let reg_recipient = FullKeypair::generate();
    let reg_tx = TransactionBuilder::new()
        .add_input(InputSpec {
            value: reg_input,
            blinding: blinding1,
            spend_auth: spend_auth1,
            merkle_path: path1,
        })
        .add_output(reg_recipient.kem.public.clone(), reg_output)
        .set_fee(reg_fee)
        .set_tx_type(TxType::ValidatorRegister {
            signing_key: new_signing.public.clone(),
            kem_public_key: new_kem.public.clone(),
        })
        .set_proof_options(test_proof_options())
        .build()
        .unwrap();

    let v1 = build_test_vertex(
        vec![genesis_id],
        1,
        0,
        &proposer_signing.public,
        vec![reg_tx],
    );
    state.apply_vertex(&v1).unwrap();

    let vid = new_signing.public.fingerprint();
    assert!(state.is_active_validator(&vid));
    assert_eq!(state.get_validator(&vid).unwrap().activation_epoch, 1);

    // --- Phase 2: Advance epoch so validator activates ---
    state.advance_epoch();
    assert_eq!(state.epoch(), 1);
    let eligible = state.eligible_validators(1);
    assert!(
        eligible.iter().any(|v| v.id == vid),
        "validator should be eligible after activation epoch"
    );

    // --- Phase 3: Deregister the validator ---
    let bond = state.validator_bond(&vid).unwrap();
    let dereg_blinding_bytes = [22u8; 32];
    let dereg_blinding = BlindingFactor::from_bytes(dereg_blinding_bytes);
    let bond_return_commitment = Commitment::commit(bond, &dereg_blinding);

    // Need an input to spend for the deregister tx
    let dereg_input_value = constants::compute_weight_fee(1, 0) + 1000;
    let dereg_blinding_in = BlindingFactor::from_bytes([33u8; 32]);
    let dereg_spend_auth = hash_domain(b"test.spend_auth", &[33u8]);
    let dereg_commitment = Commitment::commit(dereg_input_value, &dereg_blinding_in);
    state.add_commitment(dereg_commitment).unwrap();
    let dereg_idx = state.find_commitment(&dereg_commitment).unwrap();
    let dereg_path = state.commitment_path(dereg_idx).unwrap();

    let dereg_fee = constants::compute_weight_fee(1, 0);
    let dereg_change = dereg_input_value - dereg_fee;

    let stealth_result =
        umbra::crypto::stealth::StealthAddress::generate(&new_kem.public, 0).unwrap();
    let note_data = {
        let mut d = Vec::with_capacity(40);
        d.extend_from_slice(&bond.to_le_bytes());
        d.extend_from_slice(&dereg_blinding_bytes);
        d
    };
    let encrypted_note = umbra::crypto::encryption::EncryptedPayload::encrypt_with_shared_secret(
        &stealth_result.shared_secret,
        stealth_result.address.kem_ciphertext.clone(),
        &note_data,
    )
    .unwrap();

    let bond_return_output = umbra::transaction::TxOutput {
        commitment: bond_return_commitment,
        stealth_address: stealth_result.address,
        encrypted_note,
    };

    // Build deregister tx with placeholder auth signature
    let change_recipient = FullKeypair::generate();
    let mut dereg_tx = TransactionBuilder::new()
        .add_input(InputSpec {
            value: dereg_input_value,
            blinding: dereg_blinding_in,
            spend_auth: dereg_spend_auth,
            merkle_path: dereg_path,
        })
        .add_output(change_recipient.kem.public.clone(), dereg_change)
        .set_fee(dereg_fee)
        .set_tx_type(TxType::ValidatorDeregister {
            validator_id: vid,
            auth_signature: Signature::empty(),
            bond_return_output: Box::new(bond_return_output.clone()),
            bond_blinding: dereg_blinding_bytes,
        })
        .set_proof_options(test_proof_options())
        .build()
        .unwrap();

    // Now sign with the real validator key
    let tx_content_hash = dereg_tx.tx_content_hash();
    let sign_data =
        umbra::transaction::deregister_sign_data(state.chain_id(), &vid, &tx_content_hash);
    let auth_sig = new_signing.sign(&sign_data);

    // Replace the placeholder signature
    dereg_tx.tx_type = TxType::ValidatorDeregister {
        validator_id: vid,
        auth_signature: auth_sig,
        bond_return_output: Box::new(bond_return_output),
        bond_blinding: dereg_blinding_bytes,
    };

    let v2 = build_test_vertex(
        vec![genesis_id],
        2,
        1,
        &proposer_signing.public,
        vec![dereg_tx],
    );
    state.apply_vertex(&v2).unwrap();

    // Validator should now be inactive
    assert!(
        !state.is_active_validator(&vid),
        "validator should be inactive after deregistration"
    );
}

#[test]
#[ignore] // Generates 2 STARK proofs -- slow in debug mode
fn test_three_hop_transfer_chain() {
    let mut state = ChainState::new();
    let (val_signing, _) = register_genesis_validator(&mut state);
    let genesis_id = Dag::genesis_vertex().id;

    // Fund wallet A via genesis
    let mut wallet_a = Wallet::new();
    fund_wallet_via_genesis(&mut state, &mut wallet_a);
    assert_eq!(wallet_a.balance(), constants::GENESIS_MINT);
    wallet_a.resolve_commitment_indices(&state);

    // A sends 50_000 to B
    let mut wallet_b = Wallet::new();
    let tx_ab = wallet_a
        .build_transaction_with_state(wallet_b.kem_public_key(), 50_000, None, Some(&state))
        .unwrap();
    let tx_ab_binding = tx_ab.tx_binding;
    let tx_ab_fee = tx_ab.fee;

    let v1 = build_test_vertex(
        vec![genesis_id],
        1,
        0,
        &val_signing.public,
        vec![tx_ab.clone()],
    );
    state.apply_vertex(&v1).unwrap();

    wallet_b.scan_transaction_with_state(&tx_ab, Some(&state));
    assert_eq!(wallet_b.balance(), 50_000);
    // Sender scans own tx to detect change output, then confirms
    wallet_a.scan_transaction_with_state(&tx_ab, Some(&state));
    wallet_a.confirm_transaction(&tx_ab_binding);
    assert_eq!(
        wallet_a.balance(),
        constants::GENESIS_MINT - 50_000 - tx_ab_fee
    );

    // B sends 10_000 to C
    wallet_b.resolve_commitment_indices(&state);
    let mut wallet_c = Wallet::new();
    let tx_bc = wallet_b
        .build_transaction_with_state(wallet_c.kem_public_key(), 10_000, None, Some(&state))
        .unwrap();
    let tx_bc_binding = tx_bc.tx_binding;
    let tx_bc_fee = tx_bc.fee;

    let v2 = build_test_vertex(
        vec![genesis_id],
        2,
        0,
        &val_signing.public,
        vec![tx_bc.clone()],
    );
    state.apply_vertex(&v2).unwrap();

    wallet_c.scan_transaction_with_state(&tx_bc, Some(&state));
    assert_eq!(wallet_c.balance(), 10_000);
    // B scans own tx to detect change output, then confirms
    wallet_b.scan_transaction_with_state(&tx_bc, Some(&state));
    wallet_b.confirm_transaction(&tx_bc_binding);
    assert_eq!(wallet_b.balance(), 50_000 - 10_000 - tx_bc_fee);
}
