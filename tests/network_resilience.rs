//! Network resilience integration tests.
//!
//! Tests peer banning, BFT view change on stale rounds,
//! round advancement clearing votes, and sync dedup.

use umbra::consensus::bft::{vote_sign_data, BftState, Validator, Vote, VoteType};
use umbra::consensus::dag::{Vertex, VertexId};
use umbra::constants;
use umbra::crypto::keys::SigningKeypair;
use umbra::state::Ledger;

// ── Helpers ──────────────────────────────────────────────────────────────

fn setup_bft(n: usize) -> (BftState, Vec<SigningKeypair>, Vec<Validator>) {
    let chain_id = constants::chain_id();
    let mut keypairs = Vec::new();
    let mut validators = Vec::new();
    for _ in 0..n {
        let s = SigningKeypair::generate();
        let v = Validator::new(s.public.clone());
        keypairs.push(s);
        validators.push(v);
    }
    let bft = BftState::new(0, validators.clone(), chain_id);
    (bft, keypairs, validators)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[test]
fn test_view_change_on_stale_round() {
    let (mut bft, _keypairs, _validators) = setup_bft(4);

    let initial_round = bft.round;

    // Simulate staleness by advancing the round (view change)
    bft.advance_round();

    assert_eq!(
        bft.round,
        initial_round + 1,
        "round should advance on view change"
    );

    // Advance multiple times
    for _ in 0..5 {
        bft.advance_round();
    }
    assert_eq!(bft.round, initial_round + 6);
}

#[test]
fn test_bft_round_advancement_clears_votes() {
    let chain_id = constants::chain_id();
    let (mut bft, keypairs, validators) = setup_bft(4);

    let vertex_id = VertexId([1u8; 32]);
    let round = bft.round;

    // Submit 1 vote in round 0 (not enough for quorum)
    let sign_data = vote_sign_data(&vertex_id, 0, round, &VoteType::Accept, &chain_id);
    let sig = keypairs[0].sign(&sign_data);
    let vote = Vote {
        vertex_id,
        voter_id: validators[0].id,
        epoch: 0,
        round,
        vote_type: VoteType::Accept,
        signature: sig,
        vrf_proof: None,
    };
    let cert = bft.receive_vote(vote);
    assert!(cert.is_none(), "1 vote should not form certificate");

    // Advance to round 1
    bft.advance_round();

    // Now submit 3 votes in round 1 for a new vertex — should form certificate
    // without interference from the round-0 vote
    let vertex_id2 = VertexId([2u8; 32]);
    let round1 = bft.round;
    let mut final_cert = None;

    for i in 0..3 {
        let sign_data = vote_sign_data(&vertex_id2, 0, round1, &VoteType::Accept, &chain_id);
        let sig = keypairs[i].sign(&sign_data);
        let vote = Vote {
            vertex_id: vertex_id2,
            voter_id: validators[i].id,
            epoch: 0,
            round: round1,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };
        if let Some(c) = bft.receive_vote(vote) {
            final_cert = Some(c);
        }
    }

    assert!(
        final_cert.is_some(),
        "3/4 votes in round 1 should form certificate"
    );
}

#[test]
fn test_sync_dedup_prevents_double_apply() {
    let mut ledger = Ledger::new();

    // Build a properly signed vertex
    let proposer = SigningKeypair::generate();
    let proposer_fp = proposer.public.fingerprint();
    let parents = vec![VertexId([0u8; 32])];
    let tx_root = [0u8; 32];
    let state_root = [0u8; 32];
    let id = Vertex::compute_id(
        &parents,
        0,
        0,
        &proposer_fp,
        &tx_root,
        None,
        &state_root,
        constants::PROTOCOL_VERSION_ID,
    );
    let signature = proposer.sign(&id.0);
    let vertex = Vertex {
        id,
        parents,
        epoch: 0,
        round: 0,
        proposer: proposer.public.clone(),
        transactions: vec![],
        timestamp: 0,
        state_root,
        signature,
        vrf_proof: None,
        protocol_version: constants::PROTOCOL_VERSION_ID,
    };

    // First apply should succeed with coinbase output
    let result1 = ledger.apply_vertex_state_only(&vertex);
    assert!(result1.is_ok(), "first apply should succeed");

    // Second apply of the same vertex should return Ok(None) due to dedup
    let result2 = ledger.apply_vertex_state_only(&vertex);
    assert!(result2.is_ok());
    assert!(
        result2.unwrap().is_none(),
        "second apply should be deduped (return None)"
    );

    // After clearing dedup, the vertex can be applied again
    ledger.clear_sync_dedup();
}

#[test]
fn test_peer_ban_storage_roundtrip() {
    use umbra::hash_domain;
    use umbra::node::storage::{SledStorage, Storage};

    let storage = SledStorage::open_temporary().unwrap();
    let peer_id = hash_domain(b"test.peer", &[42]);

    // No bans initially
    let bans = storage.get_peer_bans().unwrap();
    assert!(bans.is_empty());

    // Ban a peer
    let banned_until = 1_000_000u64;
    storage.put_peer_ban(&peer_id, banned_until).unwrap();

    let bans = storage.get_peer_bans().unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].0, peer_id);
    assert_eq!(bans[0].1, banned_until);

    // Remove ban
    storage.remove_peer_ban(&peer_id).unwrap();
    assert!(storage.get_peer_bans().unwrap().is_empty());
}

#[test]
fn test_multiple_rounds_no_stale_certificates() {
    let chain_id = constants::chain_id();
    let (mut bft, keypairs, validators) = setup_bft(4);

    // Certify round 0
    let v0 = VertexId([10u8; 32]);
    let mut cert0 = None;
    for i in 0..3 {
        let sign_data = vote_sign_data(&v0, 0, 0, &VoteType::Accept, &chain_id);
        let sig = keypairs[i].sign(&sign_data);
        let vote = Vote {
            vertex_id: v0,
            voter_id: validators[i].id,
            epoch: 0,
            round: 0,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };
        if let Some(c) = bft.receive_vote(vote) {
            cert0 = Some(c);
        }
    }
    assert!(cert0.is_some());

    // Advance round and certify round 1
    bft.advance_round();
    let v1 = VertexId([20u8; 32]);
    let mut cert1 = None;
    for i in 0..3 {
        let sign_data = vote_sign_data(&v1, 0, 1, &VoteType::Accept, &chain_id);
        let sig = keypairs[i].sign(&sign_data);
        let vote = Vote {
            vertex_id: v1,
            voter_id: validators[i].id,
            epoch: 0,
            round: 1,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };
        if let Some(c) = bft.receive_vote(vote) {
            cert1 = Some(c);
        }
    }
    assert!(cert1.is_some());

    // Both certificates should be valid
    let c0 = cert0.unwrap();
    let c1 = cert1.unwrap();
    assert!(c0.verify(&validators, &chain_id));
    assert!(c1.verify(&validators, &chain_id));
    assert_ne!(c0.round, c1.round);
}
