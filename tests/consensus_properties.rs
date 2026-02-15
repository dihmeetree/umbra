//! Consensus property tests: simulation-based verification of BFT safety,
//! liveness, and consistency invariants.
//!
//! These tests exercise the public API of the consensus module to verify
//! critical protocol properties that underpin the security of the chain.
//! No STARK proofs are needed (these test consensus, not transactions).
//! Most tests create small committees (4-7 validators) for speed.
//!
//! Properties verified:
//! - **Safety**: No conflicting certificates, quorum intersection, epoch/chain isolation
//! - **Liveness**: Honest majority certifies, leader fairness, round advancement
//! - **Consistency**: Deterministic finalization order, symmetric verification

use std::collections::HashSet;

use umbra::consensus::bft::{
    dynamic_quorum, vote_sign_data, BftState, Certificate, Validator, Vote, VoteType,
};
use umbra::consensus::dag::{Dag, Vertex, VertexId};
use umbra::constants;
use umbra::crypto::keys::{Signature, SigningKeypair};

// ── Helpers ─────────────────────────────────────────────────────────────

/// Generate n signing keypairs and corresponding validators.
fn make_committee(n: usize) -> (Vec<SigningKeypair>, Vec<Validator>) {
    let mut keypairs = Vec::new();
    let mut validators = Vec::new();
    for _ in 0..n {
        let kp = SigningKeypair::generate();
        let v = Validator::new(kp.public.clone());
        keypairs.push(kp);
        validators.push(v);
    }
    (keypairs, validators)
}

/// Deterministic chain ID for tests.
fn test_chain_id() -> umbra::Hash {
    umbra::hash_domain(b"test.chain", &[0u8; 32])
}

/// Sign and submit a vote to a BftState, returning the certificate if quorum is reached.
fn submit_vote(
    bft: &mut BftState,
    keypair: &SigningKeypair,
    validator: &Validator,
    vertex_id: &VertexId,
    epoch: u64,
    round: u64,
    chain_id: &umbra::Hash,
) -> Option<Certificate> {
    let msg = vote_sign_data(vertex_id, epoch, round, &VoteType::Accept, chain_id);
    let sig = keypair.sign(&msg);
    bft.receive_vote(Vote {
        vertex_id: *vertex_id,
        voter_id: validator.id,
        epoch,
        round,
        vote_type: VoteType::Accept,
        signature: sig,
        vrf_proof: None,
    })
}

/// Build a test vertex using only public APIs (same pattern as e2e.rs).
fn build_test_vertex(
    parents: Vec<VertexId>,
    round: u64,
    epoch: u64,
    proposer: &umbra::crypto::keys::SigningPublicKey,
) -> Vertex {
    let proposer_fp = proposer.fingerprint();
    let tx_root = [0u8; 32];
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
        transactions: vec![],
        timestamp: round * 1000,
        state_root: [0u8; 32],
        signature: Signature::empty(),
        vrf_proof: None,
        protocol_version: constants::PROTOCOL_VERSION_ID,
    }
}

// ── Safety Properties ───────────────────────────────────────────────────

/// Verify that a single BftState cannot produce certificates for two
/// conflicting vertices in the same round. Equivocation detection must
/// prevent any voter from contributing to both quorums.
#[test]
fn test_safety_no_conflicting_certificates() {
    let (keypairs, validators) = make_committee(7);
    let chain_id = test_chain_id();
    let quorum = dynamic_quorum(7); // 5

    let vertex_a = VertexId([1u8; 32]);
    let vertex_b = VertexId([2u8; 32]);

    // Phase 1: first 5 validators vote for vertex_a -> certificate
    let mut bft = BftState::new(0, validators.clone(), chain_id);
    let mut cert_a = None;
    for i in 0..quorum {
        if let Some(c) = submit_vote(
            &mut bft,
            &keypairs[i],
            &validators[i],
            &vertex_a,
            0,
            0,
            &chain_id,
        ) {
            cert_a = Some(c);
        }
    }
    assert!(
        cert_a.is_some(),
        "quorum of 5/7 should produce certificate for vertex_a"
    );

    // Phase 2: same validators try to vote for vertex_b
    // The first `quorum` validators already voted for vertex_a, so their
    // votes for vertex_b trigger equivocation detection and are rejected.
    let mut cert_b = None;
    for i in 0..quorum {
        if let Some(c) = submit_vote(
            &mut bft,
            &keypairs[i],
            &validators[i],
            &vertex_b,
            0,
            0,
            &chain_id,
        ) {
            cert_b = Some(c);
        }
    }
    assert!(
        cert_b.is_none(),
        "must not produce certificate for conflicting vertex_b"
    );

    // Phase 3: even the remaining 2 validators voting for vertex_b cannot
    // reach quorum (they only contribute 2 votes, need 5)
    for i in quorum..7 {
        if let Some(c) = submit_vote(
            &mut bft,
            &keypairs[i],
            &validators[i],
            &vertex_b,
            0,
            0,
            &chain_id,
        ) {
            cert_b = Some(c);
        }
    }
    assert!(cert_b.is_none(), "2 fresh votes cannot reach quorum of 5");

    // Equivocation evidence should be recorded for the double-voters
    assert!(
        !bft.equivocations().is_empty(),
        "equivocation evidence must be recorded for double-voting validators"
    );
}

/// Mathematical proof that any two quorums must share at least one member.
/// This is the foundation of BFT safety: if quorum = (2n/3)+1, then
/// 2*quorum > n, guaranteeing overlap.
#[test]
fn test_safety_quorum_intersection() {
    for n in 1..=50 {
        let q = dynamic_quorum(n);

        // Quorum must be achievable
        assert!(q <= n, "quorum {q} exceeds committee size {n}");

        // Two quorums must overlap (pigeonhole principle)
        assert!(
            2 * q > n,
            "committee size {n}: 2 * quorum({q}) = {} <= {n}, no guaranteed overlap",
            2 * q
        );

        // Quorum must be strictly above 2/3
        assert!(
            q * 3 > n * 2,
            "committee size {n}: quorum {q} is not above 2/3 threshold"
        );
    }
}

/// A single BftState cannot certify two different vertices in one round.
/// After certifying vertex_a, votes for vertex_b from the same voters
/// trigger equivocation detection.
#[test]
fn test_safety_certificate_uniqueness_per_round() {
    let (keypairs, validators) = make_committee(5);
    let chain_id = test_chain_id();
    let quorum = dynamic_quorum(5); // 4

    let vertex_a = VertexId([10u8; 32]);
    let vertex_b = VertexId([20u8; 32]);

    let mut bft = BftState::new(0, validators.clone(), chain_id);

    // Certify vertex_a with first 4 validators
    let mut cert_a = None;
    for i in 0..quorum {
        if let Some(c) = submit_vote(
            &mut bft,
            &keypairs[i],
            &validators[i],
            &vertex_a,
            0,
            0,
            &chain_id,
        ) {
            cert_a = Some(c);
        }
    }
    assert!(cert_a.is_some(), "should certify vertex_a");

    // Now all 5 validators try to vote for vertex_b
    let mut cert_b = None;
    for i in 0..5 {
        if let Some(c) = submit_vote(
            &mut bft,
            &keypairs[i],
            &validators[i],
            &vertex_b,
            0,
            0,
            &chain_id,
        ) {
            cert_b = Some(c);
        }
    }
    assert!(
        cert_b.is_none(),
        "must not certify conflicting vertex_b in same round"
    );

    // Verify equivocation was detected for the 4 voters who double-voted
    let evidence = bft.equivocations();
    assert!(
        !evidence.is_empty(),
        "equivocation evidence must exist for double-voters"
    );
}

/// Votes from a previous epoch must be rejected after epoch advancement.
/// This prevents cross-epoch vote replay attacks.
#[test]
fn test_safety_cross_epoch_vote_isolation() {
    let (keypairs, validators) = make_committee(5);
    let chain_id = test_chain_id();
    let vertex = VertexId([42u8; 32]);

    // Create a valid vote for epoch 0
    let msg = vote_sign_data(&vertex, 0, 0, &VoteType::Accept, &chain_id);
    let sig = keypairs[0].sign(&msg);
    let epoch0_vote = Vote {
        vertex_id: vertex,
        voter_id: validators[0].id,
        epoch: 0,
        round: 0,
        vote_type: VoteType::Accept,
        signature: sig,
        vrf_proof: None,
    };

    // Advance to epoch 1
    let mut bft = BftState::new(0, validators.clone(), chain_id);
    bft.advance_epoch(1, validators.clone());

    // Submit the epoch-0 vote to the epoch-1 state
    let result = bft.receive_vote(epoch0_vote);
    assert!(
        result.is_none(),
        "epoch-0 vote must be rejected in epoch-1 state"
    );
}

/// Votes signed with a different chain_id must be rejected.
/// This prevents cross-chain vote replay attacks.
#[test]
fn test_safety_cross_chain_vote_isolation() {
    let (keypairs, validators) = make_committee(5);
    let chain_id_a = umbra::hash_domain(b"test.chain.a", &[0u8; 32]);
    let chain_id_b = umbra::hash_domain(b"test.chain.b", &[0u8; 32]);
    let vertex = VertexId([42u8; 32]);

    // Sign vote with chain_id_b
    let msg = vote_sign_data(&vertex, 0, 0, &VoteType::Accept, &chain_id_b);
    let sig = keypairs[0].sign(&msg);
    let cross_chain_vote = Vote {
        vertex_id: vertex,
        voter_id: validators[0].id,
        epoch: 0,
        round: 0,
        vote_type: VoteType::Accept,
        signature: sig,
        vrf_proof: None,
    };

    // BftState expects chain_id_a
    let mut bft = BftState::new(0, validators.clone(), chain_id_a);
    let result = bft.receive_vote(cross_chain_vote);
    assert!(
        result.is_none(),
        "vote signed for chain_id_b must be rejected by chain_id_a state"
    );
}

// ── Liveness Properties ─────────────────────────────────────────────────

/// With an honest majority (2f+1 out of 3f+1), certification always succeeds.
/// With fewer than quorum honest validators, certification must not occur.
#[test]
fn test_liveness_honest_majority_certifies() {
    let (keypairs, validators) = make_committee(7);
    let chain_id = test_chain_id();
    let quorum = dynamic_quorum(7); // 5
    let vertex = VertexId([77u8; 32]);

    // Case 1: exactly quorum (5) honest validators vote -> certificate
    let mut bft = BftState::new(0, validators.clone(), chain_id);
    let mut cert = None;
    for i in 0..quorum {
        if let Some(c) = submit_vote(
            &mut bft,
            &keypairs[i],
            &validators[i],
            &vertex,
            0,
            0,
            &chain_id,
        ) {
            cert = Some(c);
        }
    }
    assert!(
        cert.is_some(),
        "2f+1 honest validators must produce a certificate"
    );

    // Case 2: one fewer than quorum (4) -> no certificate
    let vertex2 = VertexId([88u8; 32]);
    let mut bft2 = BftState::new(0, validators.clone(), chain_id);
    let mut cert2 = None;
    for i in 0..(quorum - 1) {
        if let Some(c) = submit_vote(
            &mut bft2,
            &keypairs[i],
            &validators[i],
            &vertex2,
            0,
            0,
            &chain_id,
        ) {
            cert2 = Some(c);
        }
    }
    assert!(
        cert2.is_none(),
        "fewer than quorum votes must not produce a certificate"
    );
}

/// Round-robin leader selection gives every committee member exactly one
/// turn as leader across N rounds (where N = committee size).
#[test]
fn test_liveness_leader_fairness() {
    let (_, validators) = make_committee(7);
    let chain_id = test_chain_id();
    let mut bft = BftState::new(0, validators.clone(), chain_id);

    let mut leader_ids: Vec<umbra::Hash> = Vec::new();
    for _ in 0..7 {
        let leader = bft
            .leader()
            .expect("non-empty committee must have a leader");
        leader_ids.push(leader.id);
        bft.advance_round();
    }

    // Every validator should appear exactly once
    let unique: HashSet<umbra::Hash> = leader_ids.iter().copied().collect();
    assert_eq!(
        unique.len(),
        7,
        "each of 7 committee members should be leader exactly once in 7 rounds"
    );

    // Verify round-robin: leader[i] == committee[i]
    for (i, leader_id) in leader_ids.iter().enumerate() {
        assert_eq!(
            *leader_id, validators[i].id,
            "round {i}: leader should be committee member {i}"
        );
    }
}

/// After advancing the round, old votes do not block new voting.
/// A fresh set of votes in the new round can reach certification.
#[test]
fn test_liveness_round_advancement_clears_state() {
    let (keypairs, validators) = make_committee(5);
    let chain_id = test_chain_id();
    let quorum = dynamic_quorum(5); // 4

    let mut bft = BftState::new(0, validators.clone(), chain_id);

    // Round 0: certify vertex_a
    let vertex_a = VertexId([1u8; 32]);
    let mut cert0 = None;
    for i in 0..quorum {
        if let Some(c) = submit_vote(
            &mut bft,
            &keypairs[i],
            &validators[i],
            &vertex_a,
            0,
            0,
            &chain_id,
        ) {
            cert0 = Some(c);
        }
    }
    assert!(cert0.is_some(), "round 0 certification should succeed");

    // Advance to round 1
    bft.advance_round();

    // Round 1: certify vertex_b with the same validators
    let vertex_b = VertexId([2u8; 32]);
    let mut cert1 = None;
    for i in 0..quorum {
        if let Some(c) = submit_vote(
            &mut bft,
            &keypairs[i],
            &validators[i],
            &vertex_b,
            0,
            1,
            &chain_id,
        ) {
            cert1 = Some(c);
        }
    }
    assert!(
        cert1.is_some(),
        "round 1 certification must succeed after round advancement"
    );
}

/// For all committee sizes from 1 to 50, verify that the quorum is
/// achievable (quorum <= n) and strictly above 2/3 of the committee.
#[test]
fn test_liveness_quorum_reachable_all_committee_sizes() {
    for n in 1..=50 {
        let q = dynamic_quorum(n);

        // Quorum must be achievable by the committee
        assert!(q <= n, "committee {n}: quorum {q} exceeds committee size");

        // Quorum must be > 0
        assert!(q > 0, "committee {n}: quorum must be positive");

        // For n >= 2, quorum must be strictly > 2/3
        if n >= 2 {
            assert!(
                q * 3 > n * 2,
                "committee {n}: quorum {q} not above 2/3 threshold ({} / {})",
                n * 2,
                3
            );
        }
    }
}

// ── Consistency Properties ──────────────────────────────────────────────

/// Two DAGs built with identical vertices but different insertion order
/// must produce the same finalized_order(). This ensures deterministic
/// state across all honest nodes regardless of network message ordering.
#[test]
fn test_consistency_finalized_order_deterministic() {
    let kp1 = SigningKeypair::generate();
    let kp2 = SigningKeypair::generate();
    let kp3 = SigningKeypair::generate();

    let genesis = Dag::genesis_vertex();
    let gid = genesis.id;

    // Diamond DAG: genesis -> {v1, v2} -> v3
    let v1 = build_test_vertex(vec![gid], 1, 0, &kp1.public);
    let v2 = build_test_vertex(vec![gid], 1, 0, &kp2.public);
    let v3 = build_test_vertex(vec![v1.id, v2.id], 2, 0, &kp3.public);

    // DAG A: insert order v1, v2, v3
    let mut dag_a = Dag::new(genesis.clone());
    dag_a.insert_unchecked(v1.clone()).unwrap();
    dag_a.insert_unchecked(v2.clone()).unwrap();
    dag_a.insert_unchecked(v3.clone()).unwrap();
    dag_a.finalize(&v1.id);
    dag_a.finalize(&v2.id);
    dag_a.finalize(&v3.id);

    // DAG B: insert order v2, v1, v3 (reversed sibling order)
    let mut dag_b = Dag::new(genesis);
    dag_b.insert_unchecked(v2.clone()).unwrap();
    dag_b.insert_unchecked(v1.clone()).unwrap();
    dag_b.insert_unchecked(v3.clone()).unwrap();
    dag_b.finalize(&v2.id);
    dag_b.finalize(&v1.id);
    dag_b.finalize(&v3.id);

    let order_a = dag_a.finalized_order();
    let order_b = dag_b.finalized_order();

    assert_eq!(
        order_a, order_b,
        "finalized order must be deterministic regardless of insertion order"
    );

    // Both should contain exactly 3 vertices (genesis is finalized at creation)
    assert_eq!(order_a.len(), 4, "should include genesis + 3 vertices");
}

/// A certificate produced by one BftState instance is verifiable by an
/// independent BftState with the same committee and epoch. Certificate
/// verification is stateless with respect to the BftState that produced it.
#[test]
fn test_consistency_certificate_verification_symmetric() {
    let (keypairs, validators) = make_committee(7);
    let chain_id = test_chain_id();
    let quorum = dynamic_quorum(7); // 5
    let vertex = VertexId([42u8; 32]);

    // BftState A produces a certificate
    let mut bft_a = BftState::new(0, validators.clone(), chain_id);
    let mut cert = None;
    for i in 0..quorum {
        if let Some(c) = submit_vote(
            &mut bft_a,
            &keypairs[i],
            &validators[i],
            &vertex,
            0,
            0,
            &chain_id,
        ) {
            cert = Some(c);
        }
    }
    let cert = cert.expect("should produce certificate");

    // Independent BftState B (same committee/epoch) verifies the certificate
    let _bft_b = BftState::new(0, validators.clone(), chain_id);
    assert!(
        cert.verify(&validators, &chain_id),
        "certificate from BftState A must be verifiable with same committee/chain_id"
    );

    // Also verify with a wrong chain_id -> must fail
    let wrong_chain = umbra::hash_domain(b"wrong.chain", &[0u8; 32]);
    assert!(
        !cert.verify(&validators, &wrong_chain),
        "certificate must not verify with wrong chain_id"
    );
}

/// Equivocation evidence produced by one BftState is independently
/// verifiable by another BftState with the same committee and epoch.
#[test]
fn test_consistency_equivocation_evidence_verifiable() {
    let (keypairs, validators) = make_committee(5);
    let chain_id = test_chain_id();

    let vertex_a = VertexId([1u8; 32]);
    let vertex_b = VertexId([2u8; 32]);

    // BftState A: validator 0 votes for vertex_a, then vertex_b (equivocation)
    let mut bft_a = BftState::new(0, validators.clone(), chain_id);

    // First vote for vertex_a
    submit_vote(
        &mut bft_a,
        &keypairs[0],
        &validators[0],
        &vertex_a,
        0,
        0,
        &chain_id,
    );

    // Second vote for vertex_b (equivocation)
    let msg_b = vote_sign_data(&vertex_b, 0, 0, &VoteType::Accept, &chain_id);
    let sig_b = keypairs[0].sign(&msg_b);
    bft_a.receive_vote(Vote {
        vertex_id: vertex_b,
        voter_id: validators[0].id,
        epoch: 0,
        round: 0,
        vote_type: VoteType::Accept,
        signature: sig_b,
        vrf_proof: None,
    });

    // Evidence should be recorded
    let evidence_list = bft_a.equivocations();
    assert_eq!(
        evidence_list.len(),
        1,
        "exactly one equivocation should be recorded"
    );
    let evidence = evidence_list[0].clone();

    // Verify evidence fields
    assert_eq!(evidence.voter_id, validators[0].id);
    assert_eq!(evidence.first_vertex, vertex_a);
    assert_eq!(evidence.second_vertex, vertex_b);

    // Independent BftState B verifies the evidence
    let bft_b = BftState::new(0, validators.clone(), chain_id);
    assert!(
        bft_b.verify_equivocation_evidence(&evidence),
        "evidence from BftState A must be verifiable by independent BftState B"
    );
}
