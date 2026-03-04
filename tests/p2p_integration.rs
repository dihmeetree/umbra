//! P2P handshake and transport integration tests.
//!
//! Tests real TCP connections between two P2P nodes with Kyber KEM
//! handshake, Dilithium authentication, and encrypted message exchange.

use std::time::Duration;

use tokio::time::timeout;

use umbra::constants;
use umbra::crypto::keys::{KemKeypair, SigningKeypair};
use umbra::network::p2p::{self, P2pConfig, P2pEvent};
use umbra::network::Message;

// ── Helpers ──────────────────────────────────────────────────────────────

fn make_p2p_config(chain_id: umbra::Hash) -> (P2pConfig, SigningKeypair, KemKeypair) {
    let signing = SigningKeypair::generate();
    let kem = KemKeypair::generate();
    let peer_id = signing.public.fingerprint();
    let config = P2pConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        max_peers: 10,
        our_peer_id: peer_id,
        our_public_key: signing.public.clone(),
        listen_port: 0,
        our_kem_keypair: kem.clone(),
        our_signing_keypair: signing.clone(),
        external_addr: None,
        initial_bans: vec![],
        chain_id,
    };
    (config, signing, kem)
}

/// Wait for a PeerConnected event with timeout.
async fn wait_for_peer_connected(
    events: &mut tokio::sync::mpsc::Receiver<P2pEvent>,
) -> Option<umbra::Hash> {
    let result = timeout(Duration::from_secs(10), async {
        while let Some(event) = events.recv().await {
            if let P2pEvent::PeerConnected(peer_id) = event {
                return Some(peer_id);
            }
        }
        None
    })
    .await;
    result.unwrap_or(None)
}

/// Wait for a MessageReceived event with timeout.
async fn wait_for_message(
    events: &mut tokio::sync::mpsc::Receiver<P2pEvent>,
) -> Option<Box<Message>> {
    let result = timeout(Duration::from_secs(10), async {
        while let Some(event) = events.recv().await {
            if let P2pEvent::MessageReceived { message, .. } = event {
                return Some(message);
            }
        }
        None
    })
    .await;
    result.unwrap_or(None)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_two_node_handshake() {
    let chain_id = constants::chain_id();

    let (config_a, _signing_a, _kem_a) = make_p2p_config(chain_id);
    let (config_b, _signing_b, _kem_b) = make_p2p_config(chain_id);

    let result_a = p2p::start(config_a).await.unwrap();
    let result_b = p2p::start(config_b).await.unwrap();

    let mut events_a = result_a.events;
    let mut events_b = result_b.events;

    // A connects to B
    result_a.handle.connect(result_b.local_addr).await.unwrap();

    // Both should receive PeerConnected events
    let peer_a = wait_for_peer_connected(&mut events_a).await;
    let peer_b = wait_for_peer_connected(&mut events_b).await;

    assert!(peer_a.is_some(), "A should see B connected");
    assert!(peer_b.is_some(), "B should see A connected");

    result_a.handle.shutdown().await.ok();
    result_b.handle.shutdown().await.ok();
}

#[tokio::test]
async fn test_message_exchange() {
    let chain_id = constants::chain_id();

    let (config_a, _sa, _ka) = make_p2p_config(chain_id);
    let (config_b, _sb, _kb) = make_p2p_config(chain_id);

    let result_a = p2p::start(config_a).await.unwrap();
    let result_b = p2p::start(config_b).await.unwrap();

    let mut events_a = result_a.events;
    let mut events_b = result_b.events;

    result_a.handle.connect(result_b.local_addr).await.unwrap();

    // Wait for handshake
    let peer_b_id = wait_for_peer_connected(&mut events_a).await.unwrap();
    wait_for_peer_connected(&mut events_b).await.unwrap();

    // A sends a GetTips message to B
    result_a
        .handle
        .send_to(peer_b_id, Message::GetTips)
        .await
        .unwrap();

    // B should receive it
    let msg = wait_for_message(&mut events_b).await;
    assert!(msg.is_some(), "B should receive message from A");
    assert!(
        matches!(*msg.unwrap(), Message::GetTips),
        "message should be GetTips"
    );

    result_a.handle.shutdown().await.ok();
    result_b.handle.shutdown().await.ok();
}

#[tokio::test]
async fn test_chain_id_mismatch_rejected() {
    let mainnet_id = constants::chain_id_for_network(constants::NetworkId::Mainnet);
    let testnet_id = constants::chain_id_for_network(constants::NetworkId::Testnet);

    let (config_a, _sa, _ka) = make_p2p_config(mainnet_id);
    let (config_b, _sb, _kb) = make_p2p_config(testnet_id);

    let result_a = p2p::start(config_a).await.unwrap();
    let result_b = p2p::start(config_b).await.unwrap();

    let mut events_a = result_a.events;

    // A connects to B (different chain_id)
    result_a.handle.connect(result_b.local_addr).await.unwrap();

    // Should NOT get PeerConnected (handshake should fail)
    let connected = timeout(Duration::from_secs(3), async {
        while let Some(event) = events_a.recv().await {
            if let P2pEvent::PeerConnected(_) = event {
                return true;
            }
        }
        false
    })
    .await;

    assert!(
        connected.is_err() || !connected.unwrap(),
        "connection should not succeed with mismatched chain_id"
    );

    result_a.handle.shutdown().await.ok();
    result_b.handle.shutdown().await.ok();
}

#[tokio::test]
async fn test_peer_disconnect_event() {
    let chain_id = constants::chain_id();

    let (config_a, _sa, _ka) = make_p2p_config(chain_id);
    let (config_b, _sb, _kb) = make_p2p_config(chain_id);

    let result_a = p2p::start(config_a).await.unwrap();
    let result_b = p2p::start(config_b).await.unwrap();

    let mut events_a = result_a.events;
    let mut events_b = result_b.events;

    result_a.handle.connect(result_b.local_addr).await.unwrap();

    wait_for_peer_connected(&mut events_a).await.unwrap();
    wait_for_peer_connected(&mut events_b).await.unwrap();

    // Shutdown A
    result_a.handle.shutdown().await.ok();

    // B should get PeerDisconnected
    let disconnected = timeout(Duration::from_secs(5), async {
        while let Some(event) = events_b.recv().await {
            if let P2pEvent::PeerDisconnected(_) = event {
                return true;
            }
        }
        false
    })
    .await;

    assert!(disconnected.unwrap_or(false), "B should see A disconnect");

    result_b.handle.shutdown().await.ok();
}

#[tokio::test]
async fn test_get_peers() {
    let chain_id = constants::chain_id();

    let (config_a, _sa, _ka) = make_p2p_config(chain_id);
    let (config_b, _sb, _kb) = make_p2p_config(chain_id);

    let result_a = p2p::start(config_a).await.unwrap();
    let result_b = p2p::start(config_b).await.unwrap();

    let mut events_a = result_a.events;
    let mut events_b = result_b.events;

    result_a.handle.connect(result_b.local_addr).await.unwrap();

    wait_for_peer_connected(&mut events_a).await.unwrap();
    wait_for_peer_connected(&mut events_b).await.unwrap();

    // A should report B as a peer
    let peers = result_a.handle.get_peers().await.unwrap();
    assert_eq!(peers.len(), 1, "A should have 1 peer (B)");

    result_a.handle.shutdown().await.ok();
    result_b.handle.shutdown().await.ok();
}

#[tokio::test]
async fn test_broadcast() {
    let chain_id = constants::chain_id();

    let (config_a, _sa, _ka) = make_p2p_config(chain_id);
    let (config_b, _sb, _kb) = make_p2p_config(chain_id);
    let (config_c, _sc, _kc) = make_p2p_config(chain_id);

    let result_a = p2p::start(config_a).await.unwrap();
    let result_b = p2p::start(config_b).await.unwrap();
    let result_c = p2p::start(config_c).await.unwrap();

    let mut events_a = result_a.events;
    let mut events_b = result_b.events;
    let mut events_c = result_c.events;

    // A connects to B and C
    result_a.handle.connect(result_b.local_addr).await.unwrap();
    result_a.handle.connect(result_c.local_addr).await.unwrap();

    wait_for_peer_connected(&mut events_a).await.unwrap();
    wait_for_peer_connected(&mut events_a).await.unwrap();
    wait_for_peer_connected(&mut events_b).await.unwrap();
    wait_for_peer_connected(&mut events_c).await.unwrap();

    // A broadcasts GetTips
    result_a
        .handle
        .broadcast(Message::GetTips, None)
        .await
        .unwrap();

    // Both B and C should receive GetTips
    let msg_b = wait_for_message(&mut events_b).await;
    let msg_c = wait_for_message(&mut events_c).await;

    assert!(
        matches!(msg_b.as_deref(), Some(Message::GetTips)),
        "B should receive GetTips broadcast"
    );
    assert!(
        matches!(msg_c.as_deref(), Some(Message::GetTips)),
        "C should receive GetTips broadcast"
    );

    result_a.handle.shutdown().await.ok();
    result_b.handle.shutdown().await.ok();
    result_c.handle.shutdown().await.ok();
}
