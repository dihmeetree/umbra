//! Dandelion++ privacy integration tests.
//!
//! Tests the stem/fluff relay mechanism via P2P message observation.
//! Since the Dandelion++ state machine is internal to the Node event loop,
//! these tests verify observable behavior: transaction propagation patterns
//! between connected peers.

use std::time::Duration;

use tokio::time::timeout;

use umbra::constants;
use umbra::crypto::commitment::BlindingFactor;
use umbra::crypto::keys::{FullKeypair, KemKeypair, SigningKeypair};
use umbra::hash_domain;
use umbra::network::p2p::{self, P2pConfig, P2pEvent};
use umbra::network::Message;
use umbra::transaction::builder::{InputSpec, TransactionBuilder};
use umbra::transaction::Transaction;

// ── Helpers ──────────────────────────────────────────────────────────────

fn test_proof_options() -> winterfell::ProofOptions {
    winterfell::ProofOptions::new(
        42,
        8,
        10,
        winterfell::FieldExtension::Cubic,
        8,
        255,
        winterfell::BatchingMethod::Linear,
        winterfell::BatchingMethod::Linear,
    )
}

fn make_test_tx(seed: u8) -> Transaction {
    let fee = constants::compute_weight_fee(1, 0);
    let recipient = FullKeypair::generate();
    TransactionBuilder::new()
        .add_input(InputSpec {
            value: 1000,
            blinding: BlindingFactor::from_bytes([seed; 32]),
            spend_auth: hash_domain(b"test.spend_auth", &[seed]),
            merkle_path: vec![],
        })
        .add_output(recipient.kem.public.clone(), 1000 - fee)
        .set_proof_options(test_proof_options())
        .build()
        .unwrap()
}

fn make_p2p_config(chain_id: umbra::Hash) -> (P2pConfig, umbra::Hash) {
    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let peer_id = signing.public.fingerprint();
    let config = P2pConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        max_peers: 10,
        our_peer_id: peer_id,
        our_public_key: signing.public.clone(),
        listen_port: 0,
        our_kem_keypair: kem,
        our_signing_keypair: signing,
        external_addr: None,
        initial_bans: vec![],
        chain_id,
    };
    (config, peer_id)
}

async fn wait_for_peer_connected(
    events: &mut tokio::sync::mpsc::Receiver<P2pEvent>,
) -> Option<umbra::Hash> {
    timeout(Duration::from_secs(10), async {
        while let Some(event) = events.recv().await {
            if let P2pEvent::PeerConnected(peer_id) = event {
                return Some(peer_id);
            }
        }
        None
    })
    .await
    .unwrap_or(None)
}

async fn wait_for_tx_message(
    events: &mut tokio::sync::mpsc::Receiver<P2pEvent>,
    timeout_secs: u64,
) -> Option<Transaction> {
    timeout(Duration::from_secs(timeout_secs), async {
        while let Some(event) = events.recv().await {
            if let P2pEvent::MessageReceived { message, .. } = event {
                if let Message::NewTransaction(tx) = *message {
                    return Some(tx);
                }
            }
        }
        None
    })
    .await
    .unwrap_or(None)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_transaction_propagation_between_peers() {
    // Verify that a NewTransaction message sent by node A reaches node B
    // via the P2P layer (basic propagation, not Dandelion-specific).
    let chain_id = constants::chain_id();

    let (config_a, _) = make_p2p_config(chain_id);
    let (config_b, _) = make_p2p_config(chain_id);

    let result_a = p2p::start(config_a).await.unwrap();
    let result_b = p2p::start(config_b).await.unwrap();

    let mut events_a = result_a.events;
    let mut events_b = result_b.events;

    result_a.handle.connect(result_b.local_addr).await.unwrap();

    let peer_b_id = wait_for_peer_connected(&mut events_a).await.unwrap();
    wait_for_peer_connected(&mut events_b).await.unwrap();

    // Send a transaction from A to B
    let tx = make_test_tx(1);
    let tx_id = tx.tx_id();

    result_a
        .handle
        .send_to(peer_b_id, Message::NewTransaction(tx))
        .await
        .unwrap();

    // B receives the transaction
    let received = wait_for_tx_message(&mut events_b, 5).await;
    assert!(received.is_some(), "B should receive the transaction");
    assert_eq!(received.unwrap().tx_id(), tx_id);

    result_a.handle.shutdown().await.ok();
    result_b.handle.shutdown().await.ok();
}

#[tokio::test]
async fn test_broadcast_reaches_all_peers() {
    // When A broadcasts a transaction, both B and C should receive it.
    // This tests the "fluff" phase behavior (all peers get the tx).
    let chain_id = constants::chain_id();

    let (config_a, _) = make_p2p_config(chain_id);
    let (config_b, _) = make_p2p_config(chain_id);
    let (config_c, _) = make_p2p_config(chain_id);

    let result_a = p2p::start(config_a).await.unwrap();
    let result_b = p2p::start(config_b).await.unwrap();
    let result_c = p2p::start(config_c).await.unwrap();

    let mut events_a = result_a.events;
    let mut events_b = result_b.events;
    let mut events_c = result_c.events;

    result_a.handle.connect(result_b.local_addr).await.unwrap();
    result_a.handle.connect(result_c.local_addr).await.unwrap();

    wait_for_peer_connected(&mut events_a).await;
    wait_for_peer_connected(&mut events_a).await;
    wait_for_peer_connected(&mut events_b).await;
    wait_for_peer_connected(&mut events_c).await;

    // Broadcast tx from A
    let tx = make_test_tx(2);
    result_a
        .handle
        .broadcast(Message::NewTransaction(tx), None)
        .await
        .unwrap();

    let rx_b = wait_for_tx_message(&mut events_b, 5).await;
    let rx_c = wait_for_tx_message(&mut events_c, 5).await;

    assert!(rx_b.is_some(), "B should receive broadcast tx");
    assert!(rx_c.is_some(), "C should receive broadcast tx");

    result_a.handle.shutdown().await.ok();
    result_b.handle.shutdown().await.ok();
    result_c.handle.shutdown().await.ok();
}

#[tokio::test]
async fn test_unicast_reaches_only_target() {
    // When A sends to B specifically, C should NOT receive it.
    // This models stem-phase behavior (single peer relay).
    let chain_id = constants::chain_id();

    let (config_a, _) = make_p2p_config(chain_id);
    let (config_b, expected_b_id) = make_p2p_config(chain_id);
    let (config_c, _) = make_p2p_config(chain_id);

    let result_a = p2p::start(config_a).await.unwrap();
    let result_b = p2p::start(config_b).await.unwrap();
    let result_c = p2p::start(config_c).await.unwrap();

    let mut events_a = result_a.events;
    let mut events_b = result_b.events;
    let mut events_c = result_c.events;

    result_a.handle.connect(result_b.local_addr).await.unwrap();
    result_a.handle.connect(result_c.local_addr).await.unwrap();

    // Consume both PeerConnected events and deterministically identify B
    let id1 = wait_for_peer_connected(&mut events_a).await.unwrap();
    let id2 = wait_for_peer_connected(&mut events_a).await.unwrap();
    let peer_b_id = if id1 == expected_b_id { id1 } else { id2 };
    assert_eq!(peer_b_id, expected_b_id, "should identify B's peer ID");
    wait_for_peer_connected(&mut events_b).await;
    wait_for_peer_connected(&mut events_c).await;

    // Unicast to B only (stem-like)
    let tx = make_test_tx(3);
    result_a
        .handle
        .send_to(peer_b_id, Message::NewTransaction(tx))
        .await
        .unwrap();

    // B should receive it
    let rx_b = wait_for_tx_message(&mut events_b, 10).await;
    assert!(rx_b.is_some(), "B should receive unicast tx");

    // C should NOT receive it (within a short timeout)
    let rx_c = wait_for_tx_message(&mut events_c, 3).await;
    assert!(
        rx_c.is_none(),
        "C should NOT receive unicast tx meant for B"
    );

    result_a.handle.shutdown().await.ok();
    result_b.handle.shutdown().await.ok();
    result_c.handle.shutdown().await.ok();
}

#[tokio::test]
async fn test_transaction_message_integrity() {
    // Verify the encrypted P2P transport preserves transaction integrity
    let chain_id = constants::chain_id();

    let (config_a, _) = make_p2p_config(chain_id);
    let (config_b, _) = make_p2p_config(chain_id);

    let result_a = p2p::start(config_a).await.unwrap();
    let result_b = p2p::start(config_b).await.unwrap();

    let mut events_a = result_a.events;
    let mut events_b = result_b.events;

    result_a.handle.connect(result_b.local_addr).await.unwrap();

    let peer_b_id = wait_for_peer_connected(&mut events_a).await.unwrap();
    wait_for_peer_connected(&mut events_b).await;

    let tx = make_test_tx(4);
    let original_binding = tx.tx_binding;
    let original_fee = tx.fee;
    let original_inputs = tx.inputs.len();

    result_a
        .handle
        .send_to(peer_b_id, Message::NewTransaction(tx))
        .await
        .unwrap();

    let received = wait_for_tx_message(&mut events_b, 5).await.unwrap();
    assert_eq!(received.tx_binding, original_binding);
    assert_eq!(received.fee, original_fee);
    assert_eq!(received.inputs.len(), original_inputs);

    result_a.handle.shutdown().await.ok();
    result_b.handle.shutdown().await.ok();
}
