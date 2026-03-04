//! Cross-chain replay prevention integration tests.
//!
//! Verifies that chain_id enforcement prevents transaction replay,
//! BFT vote forgery, and certificate transplant across networks.

use umbra::consensus::bft::{vote_sign_data, BftState, Validator, Vote, VoteType};
use umbra::consensus::dag::VertexId;
use umbra::constants;
use umbra::crypto::keys::{KemKeypair, SigningKeypair};
use umbra::network::{self, Message};

// ── Helpers ──────────────────────────────────────────────────────────────

fn setup_chain(
    network: constants::NetworkId,
    n: usize,
) -> (
    umbra::state::ChainState,
    Vec<SigningKeypair>,
    Vec<Validator>,
) {
    let mut state = umbra::state::ChainState::new_for_network(network);
    let mut keypairs = Vec::new();
    let mut validators = Vec::new();
    for _ in 0..n {
        let signing = SigningKeypair::generate();
        let kem = KemKeypair::generate();
        let v = Validator::with_kem(signing.public.clone(), kem.public.clone());
        state.register_genesis_validator(v.clone()).unwrap();
        keypairs.push(signing);
        validators.push(v);
    }
    (state, keypairs, validators)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[test]
fn test_chain_id_differs_per_network() {
    let mainnet_id = constants::chain_id_for_network(constants::NetworkId::Mainnet);
    let testnet_id = constants::chain_id_for_network(constants::NetworkId::Testnet);

    assert_ne!(mainnet_id, testnet_id);
    assert_ne!(mainnet_id, [0u8; 32]);
    assert_ne!(testnet_id, [0u8; 32]);
}

#[test]
fn test_bft_vote_wrong_chain_id() {
    let (_, mainnet_kps, mainnet_vals) = setup_chain(constants::NetworkId::Mainnet, 4);
    let testnet_chain_id = constants::chain_id_for_network(constants::NetworkId::Testnet);
    let mainnet_chain_id = constants::chain_id_for_network(constants::NetworkId::Mainnet);

    let mut mainnet_bft = BftState::new(0, mainnet_vals.clone(), mainnet_chain_id);

    let vertex_id = VertexId([42u8; 32]);
    let epoch = 0u64;
    let round = mainnet_bft.round;

    // Submit 3 votes signed with TESTNET chain_id (wrong) — enough for quorum
    // if they were accepted, proving chain_id rejection prevents certification.
    let mut cert = None;
    for i in 0..3 {
        let wrong_sign_data = vote_sign_data(
            &vertex_id,
            epoch,
            round,
            &VoteType::Accept,
            &testnet_chain_id,
        );
        let wrong_sig = mainnet_kps[i].sign(&wrong_sign_data);
        let wrong_vote = Vote {
            vertex_id,
            voter_id: mainnet_vals[i].id,
            epoch,
            round,
            vote_type: VoteType::Accept,
            signature: wrong_sig,
            vrf_proof: None,
        };
        if let Some(c) = mainnet_bft.receive_vote(wrong_vote) {
            cert = Some(c);
        }
    }
    assert!(
        cert.is_none(),
        "3 wrong-chain votes should not produce certificate"
    );

    // Same 3 validators with correct chain_id DO form a certificate
    let mut cert = None;
    for i in 0..3 {
        let sign_data = vote_sign_data(
            &vertex_id,
            epoch,
            round,
            &VoteType::Accept,
            &mainnet_chain_id,
        );
        let sig = mainnet_kps[i].sign(&sign_data);
        let vote = Vote {
            vertex_id,
            voter_id: mainnet_vals[i].id,
            epoch,
            round,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };
        if let Some(c) = mainnet_bft.receive_vote(vote) {
            cert = Some(c);
        }
    }
    assert!(
        cert.is_some(),
        "3 correct-chain votes should produce a certificate"
    );
}

#[test]
fn test_certificate_wrong_chain_id() {
    let mainnet_chain_id = constants::chain_id_for_network(constants::NetworkId::Mainnet);
    let testnet_chain_id = constants::chain_id_for_network(constants::NetworkId::Testnet);

    let (_, keypairs, validators) = setup_chain(constants::NetworkId::Mainnet, 4);
    let mut bft = BftState::new(0, validators.clone(), mainnet_chain_id);

    let vertex_id = VertexId([99u8; 32]);
    let epoch = 0u64;
    let round = bft.round;

    let mut cert = None;
    for i in 0..4 {
        let sign_data = vote_sign_data(
            &vertex_id,
            epoch,
            round,
            &VoteType::Accept,
            &mainnet_chain_id,
        );
        let sig = keypairs[i].sign(&sign_data);
        let vote = Vote {
            vertex_id,
            voter_id: validators[i].id,
            epoch,
            round,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        };
        if let Some(c) = bft.receive_vote(vote) {
            cert = Some(c);
        }
    }

    let cert = cert.expect("should form certificate with 4/4 votes");

    // Verifies on mainnet
    assert!(cert.verify(&validators, &mainnet_chain_id));

    // Does NOT verify on testnet
    assert!(
        !cert.verify(&validators, &testnet_chain_id),
        "certificate should not verify with wrong chain_id"
    );
}

#[test]
fn test_cross_epoch_vote_isolation() {
    let chain_id = constants::chain_id();
    let mut keypairs = Vec::new();
    let mut validators = Vec::new();
    for _ in 0..4 {
        let s = SigningKeypair::generate();
        let v = Validator::new(s.public.clone());
        keypairs.push(s);
        validators.push(v);
    }

    let vertex_id = VertexId([55u8; 32]);
    let round = 0u64;

    // Build 3 epoch-0 votes (enough for quorum with 4 validators)
    let mut epoch0_votes = Vec::new();
    for i in 0..3 {
        let sign_data = vote_sign_data(&vertex_id, 0, round, &VoteType::Accept, &chain_id);
        let sig = keypairs[i].sign(&sign_data);
        epoch0_votes.push(Vote {
            vertex_id,
            voter_id: validators[i].id,
            epoch: 0,
            round,
            vote_type: VoteType::Accept,
            signature: sig,
            vrf_proof: None,
        });
    }

    // Submit all 3 to epoch 1 BFT — none should be accepted
    let mut bft_epoch1 = BftState::new(1, validators.clone(), chain_id);
    let mut cert = None;
    for vote in epoch0_votes.clone() {
        if let Some(c) = bft_epoch1.receive_vote(vote) {
            cert = Some(c);
        }
    }
    assert!(
        cert.is_none(),
        "3 epoch-0 votes should not form certificate in epoch-1 BFT"
    );

    // Same 3 votes DO form a certificate in epoch-0 BFT
    let mut bft_epoch0 = BftState::new(0, validators.clone(), chain_id);
    let mut cert = None;
    for vote in epoch0_votes {
        if let Some(c) = bft_epoch0.receive_vote(vote) {
            cert = Some(c);
        }
    }
    assert!(
        cert.is_some(),
        "3 epoch-0 votes should form certificate in epoch-0 BFT"
    );
}

#[test]
fn test_hello_message_chain_id() {
    let chain_id = constants::chain_id();
    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();

    let hello = Message::Hello {
        version: network::PROTOCOL_VERSION,
        chain_id,
        peer_id: signing.public.fingerprint(),
        public_key: signing.public.clone(),
        listen_port: 9000,
        kem_public_key: kem.public.clone(),
    };

    // Verify chain_id is carried in the Hello message
    if let Message::Hello {
        chain_id: msg_chain_id,
        ..
    } = &hello
    {
        assert_eq!(*msg_chain_id, chain_id);
        assert_ne!(*msg_chain_id, [0u8; 32]);
    } else {
        panic!("expected Hello message");
    }

    // Roundtrip serialization preserves chain_id
    let encoded = network::encode_message(&hello).unwrap();
    let decoded = network::decode_message(&encoded).unwrap();
    if let Message::Hello {
        chain_id: decoded_chain_id,
        ..
    } = decoded
    {
        assert_eq!(decoded_chain_id, chain_id);
    } else {
        panic!("decoded message should be Hello");
    }
}
