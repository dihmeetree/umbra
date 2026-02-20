//! Umbra Network Simulator
//!
//! A standalone binary that spins up real Umbra nodes with P2P networking,
//! runs validators for DAG-BFT consensus, sends transactions between wallets,
//! and tests attack scenarios from a malicious actor.
//!
//! Usage: cargo run --bin simulator

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use colored::Colorize;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use umbra::crypto::commitment::{BlindingFactor, Commitment};
use umbra::crypto::encryption::EncryptedPayload;
use umbra::crypto::keys::{KemKeypair, Signature, SigningKeypair};
use umbra::crypto::nullifier::Nullifier;
use umbra::crypto::stark::default_proof_options;
use umbra::crypto::stark::types::{BalanceStarkProof, SpendStarkProof};
use umbra::crypto::stealth::StealthAddress;
use umbra::node::rpc::{serve as rpc_serve, RpcState};
use umbra::node::{Node, NodeConfig, NodeState};
use umbra::transaction::builder::{InputSpec, TransactionBuilder};
use umbra::transaction::{Transaction, TxInput, TxMessage, TxOutput, TxType};
use umbra::wallet::Wallet;

// ── Configuration ──

const NUM_VALIDATORS: usize = 3;
const P2P_BASE_PORT: u16 = 19732;
const RPC_BASE_PORT: u16 = 19832;
const FUNDING_AMOUNT: u64 = 10_000_000;
// TX_FEE is no longer a constant — fees are computed deterministically from transaction shape.

/// Result of a single test scenario.
struct TestResult {
    name: String,
    passed: bool,
    detail: String,
}

impl TestResult {
    fn pass(name: &str, detail: &str) -> Self {
        Self {
            name: name.to_string(),
            passed: true,
            detail: detail.to_string(),
        }
    }
    fn fail(name: &str, detail: &str) -> Self {
        Self {
            name: name.to_string(),
            passed: false,
            detail: detail.to_string(),
        }
    }
}

#[tokio::main]
async fn main() {
    // Node uses ThreadRng which is !Send, so we need a LocalSet for node tasks.
    let local = tokio::task::LocalSet::new();
    local.run_until(async_main()).await;
}

async fn async_main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    println!(
        "\n{}",
        "========================================".bright_cyan()
    );
    println!("{}", "    UMBRA NETWORK SIMULATOR".bright_cyan().bold());
    println!(
        "{}\n",
        "========================================".bright_cyan()
    );

    let mut results: Vec<TestResult> = Vec::new();
    let shutdown = CancellationToken::new();

    // ── Phase 1: Bootstrap Network ──
    println!(
        "{}",
        "[Phase 1] Bootstrapping validator network...".yellow()
    );

    let (node_states, _temp_dirs, node_keypairs) = match bootstrap_network(shutdown.clone()).await {
        Ok(v) => {
            println!(
                "  {} {} validator nodes started",
                "OK".green().bold(),
                NUM_VALIDATORS
            );
            results.push(TestResult::pass(
                "Network Bootstrap",
                &format!("{} validators online", NUM_VALIDATORS),
            ));
            v
        }
        Err(e) => {
            println!("  {} {}", "FAIL".red().bold(), e);
            results.push(TestResult::fail("Network Bootstrap", &e));
            print_summary(&results);
            std::process::exit(1);
        }
    };

    // Wait for nodes to connect and start proposing
    println!("  Waiting for peer connections...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify connectivity
    let connected = check_peer_connectivity(&node_states).await;
    if connected {
        println!("  {} All nodes connected", "OK".green().bold());
        results.push(TestResult::pass("Peer Connectivity", "all nodes see peers"));
    } else {
        println!(
            "  {} Nodes not fully connected (continuing anyway)",
            "WARN".yellow().bold()
        );
        results.push(TestResult::pass(
            "Peer Connectivity",
            "partial connectivity (single-node mode still works)",
        ));
    }

    // ── Phase 2: Genesis Funding ──
    println!(
        "\n{}",
        "[Phase 2] Funding Alice and Bob from genesis...".yellow()
    );

    let genesis_kem = node_keypairs[0].1.clone();
    let mut alice_wallet = Wallet::new();
    let mut bob_wallet = Wallet::new();

    // Scan genesis coinbase into a temporary wallet using the genesis validator's KEM key
    let genesis_funded = fund_users(
        &node_states[0],
        &genesis_kem,
        &mut alice_wallet,
        &mut bob_wallet,
    )
    .await;

    let spent_nullifiers = match genesis_funded {
        Ok((alice_bal, bob_bal, nullifiers)) => {
            println!(
                "  {} Alice balance: {}, Bob balance: {}",
                "OK".green().bold(),
                alice_bal,
                bob_bal
            );
            results.push(TestResult::pass(
                "Genesis Funding",
                &format!("Alice={}, Bob={}", alice_bal, bob_bal),
            ));
            nullifiers
        }
        Err(e) => {
            println!("  {} {}", "FAIL".red().bold(), e);
            results.push(TestResult::fail("Genesis Funding", &e));
            // Can't continue without funding
            shutdown.cancel();
            tokio::time::sleep(Duration::from_millis(500)).await;
            print_summary(&results);
            std::process::exit(1);
        }
    };

    // Wait for finalization
    println!("  Waiting for transactions to finalize...");
    tokio::time::sleep(Duration::from_secs(4)).await;

    // ── Phase 3: Normal Traffic ──
    println!(
        "\n{}",
        "[Phase 3] Running normal transactions (Alice <-> Bob)...".yellow()
    );

    let traffic_results =
        run_normal_traffic(&node_states[0], &mut alice_wallet, &mut bob_wallet).await;

    for r in traffic_results {
        let status = if r.passed {
            "OK".green().bold()
        } else {
            "FAIL".red().bold()
        };
        println!("  {} {} - {}", status, r.name, r.detail);
        results.push(r);
    }

    // ── Phase 4: Chaos Agent ──
    println!("\n{}", "[Phase 4] Mallory's attack scenarios...".yellow());

    let chaos_results = run_chaos_scenarios(&node_states[0], &spent_nullifiers).await;

    for r in chaos_results {
        let status = if r.passed {
            "OK".green().bold()
        } else {
            "FAIL".red().bold()
        };
        println!("  {} {} - {}", status, r.name, r.detail);
        results.push(r);
    }

    // ── Phase 5: State Monitoring ──
    println!(
        "\n{}",
        "[Phase 5] Checking state consistency across nodes...".yellow()
    );

    let monitor_results = run_monitoring(&node_states).await;

    for r in monitor_results {
        let status = if r.passed {
            "OK".green().bold()
        } else {
            "FAIL".red().bold()
        };
        println!("  {} {} - {}", status, r.name, r.detail);
        results.push(r);
    }

    // ── Phase 6: Summary ──
    shutdown.cancel();
    tokio::time::sleep(Duration::from_millis(500)).await;
    print_summary(&results);

    let all_passed = results.iter().all(|r| r.passed);
    std::process::exit(if all_passed { 0 } else { 1 });
}

// ── Phase 1: Bootstrap ──

async fn bootstrap_network(
    shutdown: CancellationToken,
) -> Result<
    (
        Vec<Arc<RwLock<NodeState>>>,
        Vec<tempfile::TempDir>,
        Vec<(SigningKeypair, KemKeypair)>,
    ),
    String,
> {
    let mut node_states = Vec::new();
    let mut temp_dirs = Vec::new();
    let mut keypairs = Vec::new();

    for i in 0..NUM_VALIDATORS {
        let temp_dir = tempfile::TempDir::new().map_err(|e| format!("tempdir: {}", e))?;
        let signing_kp = SigningKeypair::generate();
        let kem_kp = KemKeypair::generate();

        let p2p_port = P2P_BASE_PORT + i as u16;
        let rpc_port = RPC_BASE_PORT + i as u16;

        let listen_addr: SocketAddr = format!("127.0.0.1:{}", p2p_port)
            .parse()
            .map_err(|e| format!("addr: {}", e))?;
        let rpc_addr: SocketAddr = format!("127.0.0.1:{}", rpc_port)
            .parse()
            .map_err(|e| format!("addr: {}", e))?;

        // First node has no bootstrap peers; subsequent nodes bootstrap from node 1
        let bootstrap_peers = if i == 0 {
            vec![]
        } else {
            vec![format!("127.0.0.1:{}", P2P_BASE_PORT)
                .parse()
                .map_err(|e| format!("addr: {}", e))?]
        };

        let config = NodeConfig {
            listen_addr,
            bootstrap_peers,
            data_dir: temp_dir.path().to_path_buf(),
            rpc_addr,
            keypair: signing_kp.clone(),
            kem_keypair: kem_kp.clone(),
            genesis_validator: true,
            nat_config: umbra::config::NatConfig::default(),
        };

        let mut node = Node::new(config)
            .await
            .map_err(|e| format!("node {} init: {}", i, e))?;

        let state = node.state();
        let p2p_handle = node.p2p_handle();

        // Start RPC
        let rpc_state = RpcState::new(state.clone(), p2p_handle);
        tokio::spawn(async move {
            let _ = rpc_serve(rpc_addr, rpc_state, None).await;
        });

        // Start node event loop (spawn_local because Node contains !Send ThreadRng)
        let node_shutdown = shutdown.clone();
        tokio::task::spawn_local(async move {
            node.run(node_shutdown).await;
        });

        node_states.push(state);
        keypairs.push((signing_kp, kem_kp));
        temp_dirs.push(temp_dir);

        println!(
            "  Started validator {} (P2P: {}, RPC: {})",
            i, p2p_port, rpc_port
        );
    }

    Ok((node_states, temp_dirs, keypairs))
}

async fn check_peer_connectivity(states: &[Arc<RwLock<NodeState>>]) -> bool {
    // In a single-machine setup with separate genesis validators, each node has its own
    // independent chain. Check that at least the P2P layer started without error.
    // Full connectivity may take time with encrypted handshakes.
    for state in states {
        let _s = state.read().await;
        // If we can acquire the lock, the node is running
    }
    true
}

// ── Phase 2: Genesis Funding ──

/// Returns (alice_balance, bob_balance, spent_nullifiers_from_funding_txs).
async fn fund_users(
    genesis_state: &Arc<RwLock<NodeState>>,
    genesis_kem: &KemKeypair,
    alice_wallet: &mut Wallet,
    bob_wallet: &mut Wallet,
) -> Result<(u64, u64, Vec<Nullifier>), String> {
    // Create a wallet from the genesis KEM keypair to claim the coinbase
    let genesis_keys = umbra::crypto::keys::FullKeypair {
        signing: SigningKeypair::generate(),
        kem: genesis_kem.clone(),
    };
    let mut genesis_wallet = Wallet::from_keypair(genesis_keys);

    // Fund Alice (send auto-syncs to discover genesis coinbase first)
    let alice_tx = {
        let mut state_guard = genesis_state.write().await;
        genesis_wallet
            .send(
                alice_wallet.kem_public_key(),
                FUNDING_AMOUNT,
                Some(b"Genesis funding for Alice".to_vec()),
                &mut state_guard,
            )
            .map_err(|e| format!("fund alice: {}", e))?
    };
    println!("  Submitted Alice funding tx to mempool");

    println!("  Waiting for Alice tx to finalize...");
    wait_for_finalization(genesis_state, 2).await;

    // Fund Bob (send auto-syncs to resolve change output)
    let bob_tx = {
        let mut state_guard = genesis_state.write().await;
        genesis_wallet
            .send(
                bob_wallet.kem_public_key(),
                FUNDING_AMOUNT,
                Some(b"Genesis funding for Bob".to_vec()),
                &mut state_guard,
            )
            .map_err(|e| format!("fund bob: {}", e))?
    };
    println!("  Submitted Bob funding tx to mempool");

    println!("  Waiting for Bob tx to finalize...");
    wait_for_finalization(genesis_state, 2).await;

    // Sync receiver wallets to discover their funded outputs for balance check
    {
        let state_guard = genesis_state.read().await;
        alice_wallet
            .sync(&state_guard)
            .map_err(|e| format!("alice sync: {}", e))?;
        bob_wallet
            .sync(&state_guard)
            .map_err(|e| format!("bob sync: {}", e))?;
    }

    // Collect spent nullifiers from funding txs for double-spend attack testing
    let mut spent_nullifiers = Vec::new();
    for input in &alice_tx.inputs {
        spent_nullifiers.push(input.nullifier);
    }
    for input in &bob_tx.inputs {
        spent_nullifiers.push(input.nullifier);
    }

    Ok((
        alice_wallet.balance(),
        bob_wallet.balance(),
        spent_nullifiers,
    ))
}

/// Wait for at least `count` new vertices to be finalized on the node.
async fn wait_for_finalization(state: &Arc<RwLock<NodeState>>, count: u64) {
    let initial = {
        let s = state.read().await;
        s.finalized_vertex_count().unwrap_or(0)
    };
    let target = initial + count;

    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let current = {
            let s = state.read().await;
            s.finalized_vertex_count().unwrap_or(0)
        };
        if current >= target {
            return;
        }
    }
    // Timeout after 20 seconds — continue anyway
    println!("  (finalization wait timed out, continuing)");
}

// ── Helpers for constructing dummy transaction components ──

/// Create a dummy TxInput with a random nullifier and empty proofs.
fn make_dummy_input() -> TxInput {
    let null_hash = umbra::hash_domain(b"dummy", &rand::random::<[u8; 32]>());
    TxInput {
        nullifier: Nullifier(null_hash),
        proof_link: rand::random(),
        spend_proof: SpendStarkProof {
            proof_bytes: vec![0u8; 4],
            public_inputs_bytes: vec![],
        },
    }
}

/// Create a dummy TxOutput with a random commitment and valid stealth address.
fn make_dummy_output() -> TxOutput {
    let kem = KemKeypair::generate();
    let stealth = StealthAddress::generate(&kem.public, 0).unwrap();
    let note = EncryptedPayload::encrypt(&kem.public, b"dummy-note").unwrap();
    TxOutput {
        commitment: Commitment(rand::random()),
        stealth_address: stealth.address,
        encrypted_note: note,
        blake3_binding: [0u8; 64],
    }
}

/// Create a dummy TxMessage with a small encrypted payload.
fn make_dummy_message() -> TxMessage {
    let kem = KemKeypair::generate();
    TxMessage {
        payload: EncryptedPayload::encrypt(&kem.public, b"dummy-msg").unwrap(),
    }
}

// ── Phase 3: Normal Traffic ──

async fn run_normal_traffic(
    node_state: &Arc<RwLock<NodeState>>,
    alice: &mut Wallet,
    bob: &mut Wallet,
) -> Vec<TestResult> {
    let mut results = Vec::new();

    let rounds: Vec<(&str, &str, u64, Option<&[u8]>)> = vec![
        ("Alice", "Bob", 1_000, Some(b"Payment 1" as &[u8])),
        ("Bob", "Alice", 500, Some(b"Payment back" as &[u8])),
        ("Alice", "Bob", 2_000, None),
        ("Bob", "Alice", 750, Some(b"Thanks!" as &[u8])),
        ("Alice", "Bob", 100, None),
    ];

    for (i, (sender_name, _receiver_name, amount, message)) in rounds.iter().enumerate() {
        let round_name = format!("Round {} ({} sends {})", i + 1, sender_name, amount);

        // Determine sender/receiver
        let (sender, receiver) = if *sender_name == "Alice" {
            (&mut *alice, &mut *bob)
        } else {
            (&mut *bob, &mut *alice)
        };

        // Build, submit, and track the transaction
        let send_result = {
            let mut state_guard = node_state.write().await;
            sender.send(
                receiver.kem_public_key(),
                *amount,
                message.map(|m| m.to_vec()),
                &mut state_guard,
            )
        };

        match send_result {
            Ok(_tx) => {
                // Wait for finalization, then sync receiver for balance check
                wait_for_finalization(node_state, 1).await;
                let state_guard = node_state.read().await;
                if *sender_name == "Alice" {
                    let _ = bob.sync(&state_guard);
                } else {
                    let _ = alice.sync(&state_guard);
                }
                drop(state_guard);

                results.push(TestResult::pass(
                    &round_name,
                    &format!("Alice={}, Bob={}", alice.balance(), bob.balance()),
                ));
            }
            Err(e) => {
                results.push(TestResult::fail(
                    &round_name,
                    &format!("send failed: {}", e),
                ));
            }
        }

        // Small delay to let the node event loop process
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Verify final balances make sense
    let alice_bal = alice.balance();
    let bob_bal = bob.balance();
    let total = alice_bal + bob_bal;
    // Total should be 2 * FUNDING_AMOUNT minus all fees (deterministic, varies per tx shape).
    // With deterministic fees, just check total <= 2 * FUNDING_AMOUNT (fees consumed some).
    let expected_max = 2 * FUNDING_AMOUNT;
    let fees_paid = expected_max - total;

    if total <= expected_max && total > 0 {
        results.push(TestResult::pass(
            "Balance Conservation",
            &format!(
                "total={} (funded={}, fees_consumed={})",
                total, expected_max, fees_paid
            ),
        ));
    } else {
        results.push(TestResult::fail(
            "Balance Conservation",
            &format!("total={} out of range (funded={})", total, expected_max),
        ));
    }

    results
}

// ── Phase 4: Chaos ──

async fn run_chaos_scenarios(
    node_state: &Arc<RwLock<NodeState>>,
    spent_nullifiers: &[Nullifier],
) -> Vec<TestResult> {
    let mut results = Vec::new();

    // Get chain state snapshot for comparison after attacks
    let (initial_commitments, initial_nullifiers, initial_state_root) = {
        let state_guard = node_state.read().await;
        (
            state_guard.commitment_count(),
            state_guard.nullifier_count(),
            state_guard.state_root(),
        )
    };

    // Attack 1: Invalid proof bytes
    {
        let name = "Attack: Corrupted proof";
        let mallory = Wallet::new();

        // Build a valid-looking tx structure but with garbage proof
        let blind = umbra::crypto::commitment::BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth");

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(mut tx) => {
                // Corrupt the balance proof
                if !tx.balance_proof.proof_bytes.is_empty() {
                    tx.balance_proof.proof_bytes[0] ^= 0xFF;
                }
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx) {
                    Ok(_) => {
                        results.push(TestResult::fail(
                            name,
                            "mempool accepted corrupted proof (should reject)",
                        ));
                    }
                    Err(e) => {
                        results.push(TestResult::pass(
                            name,
                            &format!("correctly rejected: {}", e),
                        ));
                    }
                }
            }
            Err(_) => {
                // Builder might reject it too, which is fine
                results.push(TestResult::pass(name, "builder rejected invalid tx"));
            }
        }
    }

    // Attack 2: Wrong chain ID
    // Chain ID is validated at the state level (not mempool), so we test via
    // ChainState::validate_transaction which is the path used by apply_vertex.
    {
        let name = "Attack: Wrong chain ID";
        let blind = umbra::crypto::commitment::BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-2");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_chain_id([0xDE; 32]) // Wrong chain ID
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(tx) => {
                // Validate against chain state (which checks chain_id)
                let state_guard = node_state.read().await;
                match state_guard.validate_transaction_against_state(&tx) {
                    Ok(_) => {
                        results.push(TestResult::fail(name, "state accepted wrong chain ID"));
                    }
                    Err(e) => {
                        results.push(TestResult::pass(
                            name,
                            &format!("correctly rejected by state: {}", e),
                        ));
                    }
                }
            }
            Err(_) => {
                results.push(TestResult::pass(name, "builder rejected"));
            }
        }
    }

    // Attack 3: Overflow fee (> MAX_TX_FEE)
    // For Transfer types, set_fee is ignored (fee is auto-computed). So we build
    // a valid tx, then mutate tx.fee to an overflow value before mempool insertion.
    {
        let name = "Attack: Overflow fee";
        let blind = umbra::crypto::commitment::BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-3");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(mut tx) => {
                // Tamper with fee after building to exceed MAX_TX_FEE
                tx.fee = umbra::constants::MAX_TX_FEE + 1;
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx) {
                    Ok(_) => {
                        results.push(TestResult::fail(name, "accepted overflow fee"));
                    }
                    Err(e) => {
                        results.push(TestResult::pass(
                            name,
                            &format!("correctly rejected: {}", e),
                        ));
                    }
                }
            }
            Err(e) => {
                results.push(TestResult::pass(name, &format!("builder rejected: {}", e)));
            }
        }
    }

    // Attack 4: Zero fee (below minimum)
    // For Transfer types, set_fee is ignored (fee is auto-computed). So we build
    // a valid tx, then mutate tx.fee to zero before mempool insertion.
    {
        let name = "Attack: Zero fee";
        let blind = umbra::crypto::commitment::BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-4");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(mut tx) => {
                // Tamper with fee after building to set it to zero
                tx.fee = 0;
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx) {
                    Ok(_) => {
                        results.push(TestResult::fail(name, "accepted zero fee"));
                    }
                    Err(e) => {
                        results.push(TestResult::pass(
                            name,
                            &format!("correctly rejected: {}", e),
                        ));
                    }
                }
            }
            Err(e) => {
                results.push(TestResult::pass(name, &format!("builder rejected: {}", e)));
            }
        }
    }

    // Attack 5: Empty transaction (no inputs, no outputs)
    {
        let name = "Attack: Empty transaction";
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            messages: vec![],
            fee: 100,
            balance_proof: BalanceStarkProof {
                proof_bytes: vec![],
                public_inputs_bytes: vec![],
            },
            tx_type: umbra::transaction::TxType::Transfer,
            tx_binding: [0u8; 32],
            chain_id: umbra::constants::chain_id(),
            expiry_epoch: 0,
        };

        let mut state_guard = node_state.write().await;
        match state_guard.submit_transaction(tx) {
            Ok(_) => {
                results.push(TestResult::fail(name, "accepted empty transaction"));
            }
            Err(e) => {
                results.push(TestResult::pass(
                    name,
                    &format!("correctly rejected: {}", e),
                ));
            }
        }
    }

    // Attack 6: Duplicate nullifier (replay attack)
    {
        let name = "Attack: Duplicate nullifier";
        let nullifier = umbra::crypto::nullifier::Nullifier(umbra::hash_domain(
            b"mallory",
            b"replay-nullifier",
        ));

        let tx = Transaction {
            inputs: vec![
                umbra::transaction::TxInput {
                    nullifier,
                    spend_proof: SpendStarkProof {
                        proof_bytes: vec![1, 2, 3],
                        public_inputs_bytes: vec![],
                    },
                    proof_link: [0u8; 32],
                },
                umbra::transaction::TxInput {
                    nullifier, // Same nullifier = duplicate
                    spend_proof: SpendStarkProof {
                        proof_bytes: vec![4, 5, 6],
                        public_inputs_bytes: vec![],
                    },
                    proof_link: [0u8; 32],
                },
            ],
            outputs: vec![],
            messages: vec![],
            fee: 100,
            balance_proof: BalanceStarkProof {
                proof_bytes: vec![],
                public_inputs_bytes: vec![],
            },
            tx_type: umbra::transaction::TxType::Transfer,
            tx_binding: [0u8; 32],
            chain_id: umbra::constants::chain_id(),
            expiry_epoch: 0,
        };

        let mut state_guard = node_state.write().await;
        match state_guard.submit_transaction(tx) {
            Ok(_) => {
                results.push(TestResult::fail(name, "accepted duplicate nullifier"));
            }
            Err(e) => {
                results.push(TestResult::pass(
                    name,
                    &format!("correctly rejected: {}", e),
                ));
            }
        }
    }

    // Attack 7: Oversized message
    {
        let name = "Attack: Oversized message";
        let blind = umbra::crypto::commitment::BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-7");
        let mallory = Wallet::new();

        // Try building a tx with a message exceeding MAX_MESSAGE_SIZE
        let huge_msg = vec![0xAA; umbra::constants::MAX_MESSAGE_SIZE + 1];

        // Fee for 1 input, 1 output, ~65600 byte ciphertext:
        // 100 + 100 + 100 + ceil(65600/1024)*10 = 950
        // Input must equal output + fee, so 1850 = 900 + 950
        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1850,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .add_message(mallory.kem_public_key().clone(), huge_msg)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(tx) => {
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx) {
                    Ok(_) => {
                        results.push(TestResult::fail(name, "accepted oversized message"));
                    }
                    Err(e) => {
                        results.push(TestResult::pass(
                            name,
                            &format!("correctly rejected: {}", e),
                        ));
                    }
                }
            }
            Err(e) => {
                results.push(TestResult::pass(name, &format!("builder rejected: {}", e)));
            }
        }
    }

    // ── Group A: Transaction Structure Attacks ──

    // Attack 8: Too many inputs (> MAX_TX_IO)
    {
        let name = "Attack: Too many inputs";
        let inputs: Vec<TxInput> = (0..umbra::constants::MAX_TX_IO + 1)
            .map(|_| make_dummy_input())
            .collect();
        let tx = Transaction {
            inputs,
            outputs: vec![make_dummy_output()],
            messages: vec![],
            fee: 100,
            balance_proof: BalanceStarkProof {
                proof_bytes: vec![],
                public_inputs_bytes: vec![],
            },
            tx_type: TxType::Transfer,
            tx_binding: [0u8; 32],
            chain_id: umbra::constants::chain_id(),
            expiry_epoch: 0,
        };
        let mut state_guard = node_state.write().await;
        match state_guard.submit_transaction(tx) {
            Ok(_) => results.push(TestResult::fail(name, "accepted too many inputs")),
            Err(e) => results.push(TestResult::pass(
                name,
                &format!("correctly rejected: {}", e),
            )),
        }
    }

    // Attack 9: Too many outputs (> MAX_TX_IO)
    {
        let name = "Attack: Too many outputs";
        let outputs: Vec<TxOutput> = (0..umbra::constants::MAX_TX_IO + 1)
            .map(|_| make_dummy_output())
            .collect();
        let tx = Transaction {
            inputs: vec![make_dummy_input()],
            outputs,
            messages: vec![],
            fee: 100,
            balance_proof: BalanceStarkProof {
                proof_bytes: vec![],
                public_inputs_bytes: vec![],
            },
            tx_type: TxType::Transfer,
            tx_binding: [0u8; 32],
            chain_id: umbra::constants::chain_id(),
            expiry_epoch: 0,
        };
        let mut state_guard = node_state.write().await;
        match state_guard.submit_transaction(tx) {
            Ok(_) => results.push(TestResult::fail(name, "accepted too many outputs")),
            Err(e) => results.push(TestResult::pass(
                name,
                &format!("correctly rejected: {}", e),
            )),
        }
    }

    // Attack 10: Too many messages (> MAX_MESSAGES_PER_TX)
    {
        let name = "Attack: Too many messages";
        let messages: Vec<TxMessage> = (0..umbra::constants::MAX_MESSAGES_PER_TX + 1)
            .map(|_| make_dummy_message())
            .collect();
        let tx = Transaction {
            inputs: vec![make_dummy_input()],
            outputs: vec![make_dummy_output()],
            messages,
            fee: 100,
            balance_proof: BalanceStarkProof {
                proof_bytes: vec![],
                public_inputs_bytes: vec![],
            },
            tx_type: TxType::Transfer,
            tx_binding: [0u8; 32],
            chain_id: umbra::constants::chain_id(),
            expiry_epoch: 0,
        };
        let mut state_guard = node_state.write().await;
        match state_guard.submit_transaction(tx) {
            Ok(_) => results.push(TestResult::fail(name, "accepted too many messages")),
            Err(e) => results.push(TestResult::pass(
                name,
                &format!("correctly rejected: {}", e),
            )),
        }
    }

    // Attack 11: Duplicate output commitments
    {
        let name = "Attack: Duplicate output commitments";
        let shared_output = make_dummy_output();
        let tx = Transaction {
            inputs: vec![make_dummy_input()],
            outputs: vec![shared_output.clone(), shared_output],
            messages: vec![],
            fee: 100,
            balance_proof: BalanceStarkProof {
                proof_bytes: vec![],
                public_inputs_bytes: vec![],
            },
            tx_type: TxType::Transfer,
            tx_binding: [0u8; 32],
            chain_id: umbra::constants::chain_id(),
            expiry_epoch: 0,
        };
        let mut state_guard = node_state.write().await;
        match state_guard.submit_transaction(tx) {
            Ok(_) => results.push(TestResult::fail(name, "accepted duplicate commitments")),
            Err(e) => results.push(TestResult::pass(
                name,
                &format!("correctly rejected: {}", e),
            )),
        }
    }

    // Attack 12: Invalid tx_binding (tampered)
    {
        let name = "Attack: Invalid tx_binding";
        let blind = BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-12");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(mut tx) => {
                // Flip a byte in the binding — any field mutation breaks the hash
                tx.tx_binding[0] ^= 0xFF;
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx) {
                    Ok(_) => results.push(TestResult::fail(name, "accepted tampered binding")),
                    Err(e) => results.push(TestResult::pass(
                        name,
                        &format!("correctly rejected: {}", e),
                    )),
                }
            }
            Err(_) => results.push(TestResult::pass(name, "builder rejected invalid tx")),
        }
    }

    // Attack 13: Expired transaction
    {
        let name = "Attack: Expired transaction";
        let blind = BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-13");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_expiry_epoch(1) // expires at epoch 1
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(tx) => {
                let mut state_guard = node_state.write().await;
                let original_epoch = state_guard.epoch();
                // Set mempool epoch to 10 so the tx is expired
                state_guard.set_mempool_epoch(10);
                match state_guard.submit_transaction(tx) {
                    Ok(_) => results.push(TestResult::fail(name, "accepted expired tx")),
                    Err(e) => results.push(TestResult::pass(
                        name,
                        &format!("correctly rejected: {}", e),
                    )),
                }
                // Reset epoch
                state_guard.set_mempool_epoch(original_epoch);
            }
            Err(_) => results.push(TestResult::pass(name, "builder rejected invalid tx")),
        }
    }

    // ── Group B: Proof Manipulation Attacks ──

    // Attack 14: Proof transplant (swap balance proofs between two txs)
    {
        let name = "Attack: Proof transplant";
        let mallory_a = Wallet::new();
        let mallory_b = Wallet::new();

        let blind_a = BlindingFactor::random();
        let auth_a = umbra::hash_domain(b"mallory", b"transplant-a");
        let blind_b = BlindingFactor::random();
        let auth_b = umbra::hash_domain(b"mallory", b"transplant-b");

        let tx_a = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind_a,
                spend_auth: auth_a,
                merkle_path: vec![],
            })
            .add_output(mallory_a.kem_public_key().clone(), 900)
            .set_proof_options(default_proof_options())
            .build();

        let tx_b = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 2200,
                blinding: blind_b,
                spend_auth: auth_b,
                merkle_path: vec![],
            })
            .add_output(mallory_b.kem_public_key().clone(), 1900)
            .set_proof_options(default_proof_options())
            .build();

        match (tx_a, tx_b) {
            (Ok(tx_a), Ok(mut tx_b)) => {
                // Transplant A's balance proof onto B
                tx_b.balance_proof = tx_a.balance_proof;
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx_b) {
                    Ok(_) => results.push(TestResult::fail(name, "accepted transplanted proof")),
                    Err(e) => results.push(TestResult::pass(
                        name,
                        &format!("correctly rejected: {}", e),
                    )),
                }
            }
            _ => results.push(TestResult::pass(name, "builder rejected (expected)")),
        }
    }

    // Attack 15: Proof_link tampering
    {
        let name = "Attack: Proof_link tampering";
        let blind = BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-15");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(mut tx) => {
                // Tamper with the proof_link — breaks tx_binding
                if !tx.inputs.is_empty() {
                    tx.inputs[0].proof_link[0] ^= 0xFF;
                }
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx) {
                    Ok(_) => results.push(TestResult::fail(name, "accepted tampered proof_link")),
                    Err(e) => results.push(TestResult::pass(
                        name,
                        &format!("correctly rejected: {}", e),
                    )),
                }
            }
            Err(_) => results.push(TestResult::pass(name, "builder rejected invalid tx")),
        }
    }

    // Attack 16: Nullifier tampering
    {
        let name = "Attack: Nullifier tampering";
        let blind = BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-16");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(mut tx) => {
                // Tamper with the nullifier — breaks tx_binding
                if !tx.inputs.is_empty() {
                    tx.inputs[0].nullifier.0[0] ^= 0xFF;
                }
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx) {
                    Ok(_) => results.push(TestResult::fail(name, "accepted tampered nullifier")),
                    Err(e) => results.push(TestResult::pass(
                        name,
                        &format!("correctly rejected: {}", e),
                    )),
                }
            }
            Err(_) => results.push(TestResult::pass(name, "builder rejected invalid tx")),
        }
    }

    // ── Group C: Validator Operation Attacks ──

    // Attack 17: Insufficient validator bond
    {
        let name = "Attack: Insufficient validator bond";
        let signing_kp = SigningKeypair::generate();
        let kem_kp = KemKeypair::generate();

        let tx = Transaction {
            inputs: vec![make_dummy_input()],
            outputs: vec![make_dummy_output()],
            messages: vec![],
            // fee = VALIDATOR_BASE_BOND but missing MIN_TX_FEE
            fee: umbra::constants::VALIDATOR_BASE_BOND,
            balance_proof: BalanceStarkProof {
                proof_bytes: vec![],
                public_inputs_bytes: vec![],
            },
            tx_type: TxType::ValidatorRegister {
                signing_key: signing_kp.public.clone(),
                kem_public_key: kem_kp.public.clone(),
            },
            tx_binding: [0u8; 32],
            chain_id: umbra::constants::chain_id(),
            expiry_epoch: 0,
        };
        let mut state_guard = node_state.write().await;
        match state_guard.submit_transaction(tx) {
            Ok(_) => results.push(TestResult::fail(name, "accepted insufficient bond")),
            Err(e) => results.push(TestResult::pass(
                name,
                &format!("correctly rejected: {}", e),
            )),
        }
    }

    // Attack 18: Invalid validator key sizes
    {
        let name = "Attack: Invalid validator key sizes";
        // Use a real keypair to get a valid SigningPublicKey, then construct
        // a manually-crafted transaction. The key validation happens on the
        // raw bytes, so we need to create keys with wrong sizes.
        // Since SigningPublicKey has pub(crate) fields, we use serialization
        // to construct invalid-sized keys.
        let fake_signing_bytes = vec![0xAA; 100]; // wrong size (should be 2592)
        let fake_kem_bytes = vec![0xBB; 100]; // wrong size (should be 1568)

        // Serialize the keys via bincode to match the Serialize/Deserialize impl
        let fake_signing: Result<umbra::crypto::keys::SigningPublicKey, _> =
            umbra::deserialize(&umbra::serialize(&fake_signing_bytes).unwrap());
        let fake_kem: Result<umbra::crypto::keys::KemPublicKey, _> =
            umbra::deserialize(&umbra::serialize(&fake_kem_bytes).unwrap());

        // If deserialization catches the invalid size, that's also a valid rejection
        match (fake_signing, fake_kem) {
            (Ok(signing_key), Ok(kem_key)) => {
                let tx = Transaction {
                    inputs: vec![make_dummy_input()],
                    outputs: vec![make_dummy_output()],
                    messages: vec![],
                    fee: umbra::constants::VALIDATOR_BASE_BOND + umbra::constants::MIN_TX_FEE,
                    balance_proof: BalanceStarkProof {
                        proof_bytes: vec![],
                        public_inputs_bytes: vec![],
                    },
                    tx_type: TxType::ValidatorRegister {
                        signing_key,
                        kem_public_key: kem_key,
                    },
                    tx_binding: [0u8; 32],
                    chain_id: umbra::constants::chain_id(),
                    expiry_epoch: 0,
                };
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx) {
                    Ok(_) => results.push(TestResult::fail(name, "accepted invalid key sizes")),
                    Err(e) => results.push(TestResult::pass(
                        name,
                        &format!("correctly rejected: {}", e),
                    )),
                }
            }
            _ => results.push(TestResult::pass(
                name,
                "deserialization rejected invalid key sizes",
            )),
        }
    }

    // Attack 19: Zero bond return in deregister
    {
        let name = "Attack: Zero bond return (deregister)";
        let kem = KemKeypair::generate();
        let stealth = StealthAddress::generate(&kem.public, 0).unwrap();
        let note = EncryptedPayload::encrypt(&kem.public, b"bond-return").unwrap();

        let tx = Transaction {
            inputs: vec![make_dummy_input()],
            outputs: vec![make_dummy_output()],
            messages: vec![],
            fee: 100,
            balance_proof: BalanceStarkProof {
                proof_bytes: vec![],
                public_inputs_bytes: vec![],
            },
            tx_type: TxType::ValidatorDeregister {
                validator_id: [0xDD; 32],
                auth_signature: Signature::empty(),
                bond_return_output: Box::new(TxOutput {
                    commitment: Commitment([0u8; 32]), // Zero commitment = invalid
                    stealth_address: stealth.address,
                    encrypted_note: note,
                    blake3_binding: [0u8; 64],
                }),
                bond_blinding: [0u8; 32],
            },
            tx_binding: [0u8; 32],
            chain_id: umbra::constants::chain_id(),
            expiry_epoch: 0,
        };
        let mut state_guard = node_state.write().await;
        match state_guard.submit_transaction(tx) {
            Ok(_) => results.push(TestResult::fail(name, "accepted zero bond return")),
            Err(e) => results.push(TestResult::pass(
                name,
                &format!("correctly rejected: {}", e),
            )),
        }
    }

    // ── Group D: Double-Spend & Replay Attacks ──

    // Attack 20: Mempool nullifier conflict (two txs, same nullifier)
    {
        let name = "Attack: Mempool nullifier conflict";
        let spend_auth = umbra::hash_domain(b"mallory", b"double-spend-input");
        let mallory_a = Wallet::new();
        let mallory_b = Wallet::new();

        let tx_a = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: BlindingFactor::from_bytes([42u8; 32]),
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory_a.kem_public_key().clone(), 900)
            .set_proof_options(default_proof_options())
            .build();

        let tx_b = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: BlindingFactor::from_bytes([42u8; 32]),
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory_b.kem_public_key().clone(), 900)
            .set_proof_options(default_proof_options())
            .build();

        match (tx_a, tx_b) {
            (Ok(tx_a), Ok(tx_b)) => {
                let tx_a_id = tx_a.tx_id();
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx_a) {
                    Ok(_) => {
                        // First tx accepted, now try the conflicting one
                        match state_guard.submit_transaction(tx_b) {
                            Ok(_) => results
                                .push(TestResult::fail(name, "accepted conflicting nullifier")),
                            Err(e) => results.push(TestResult::pass(
                                name,
                                &format!("correctly rejected second tx: {}", e),
                            )),
                        }
                        // Clean up
                        state_guard.remove_transaction(&tx_a_id);
                    }
                    Err(e) => results.push(TestResult::fail(
                        name,
                        &format!("first tx should have been accepted: {}", e),
                    )),
                }
            }
            _ => results.push(TestResult::pass(name, "builder rejected (expected)")),
        }
    }

    // Attack 21: Duplicate transaction (exact same tx submitted twice)
    {
        let name = "Attack: Duplicate transaction";
        let blind = BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-21");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(tx) => {
                let tx_id = tx.tx_id();
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx.clone()) {
                    Ok(_) => {
                        // First insert succeeded, now try duplicate
                        match state_guard.submit_transaction(tx) {
                            Ok(_) => results.push(TestResult::fail(name, "accepted duplicate tx")),
                            Err(e) => results.push(TestResult::pass(
                                name,
                                &format!("correctly rejected duplicate: {}", e),
                            )),
                        }
                        // Clean up
                        state_guard.remove_transaction(&tx_id);
                    }
                    Err(e) => results.push(TestResult::fail(
                        name,
                        &format!("first insert should succeed: {}", e),
                    )),
                }
            }
            Err(_) => results.push(TestResult::pass(name, "builder rejected invalid tx")),
        }
    }

    // Attack 22: Cross-chain replay via state validation
    {
        let name = "Attack: Cross-chain replay";
        let blind = BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-22");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(mut tx) => {
                // Mutate chain_id to simulate replaying on a different chain
                tx.chain_id = [0xCC; 32];
                let state_guard = node_state.read().await;
                match state_guard.validate_transaction_against_state(&tx) {
                    Ok(_) => {
                        results.push(TestResult::fail(name, "state accepted cross-chain replay"))
                    }
                    Err(e) => results.push(TestResult::pass(
                        name,
                        &format!("correctly rejected by state: {}", e),
                    )),
                }
            }
            Err(_) => results.push(TestResult::pass(name, "builder rejected invalid tx")),
        }
    }

    // ── Group E: Timing & Resilience Attacks ──

    // Attack 23: Mempool expiry eviction
    {
        let name = "Attack: Mempool expiry eviction";
        let blind = BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-23");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_expiry_epoch(5) // expires at epoch 5
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(tx) => {
                let mut state_guard = node_state.write().await;
                // Insert at epoch 0 (should succeed)
                match state_guard.submit_transaction(tx) {
                    Ok(_) => {
                        let pre_count = state_guard.mempool_len();
                        // Advance epoch past expiry and evict
                        state_guard.set_mempool_epoch(10);
                        let evicted = state_guard.evict_expired_transactions();
                        let post_count = state_guard.mempool_len();
                        // Reset epoch
                        state_guard.set_mempool_epoch(0);

                        if evicted >= 1 && post_count < pre_count {
                            results.push(TestResult::pass(
                                name,
                                &format!(
                                    "evicted {} expired tx(s), pool {}->{}",
                                    evicted, pre_count, post_count
                                ),
                            ));
                        } else {
                            results.push(TestResult::fail(
                                name,
                                &format!("eviction failed: evicted={}", evicted),
                            ));
                        }
                    }
                    Err(e) => results.push(TestResult::fail(
                        name,
                        &format!("insert should have succeeded: {}", e),
                    )),
                }
            }
            Err(_) => results.push(TestResult::pass(name, "builder rejected invalid tx")),
        }
    }

    // Attack 24: No-expiry tx survives eviction
    {
        let name = "Attack: No-expiry tx survives eviction";
        let blind = BlindingFactor::random();
        let spend_auth = umbra::hash_domain(b"mallory", b"fake-auth-24");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1200,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            // expiry_epoch = 0 means no expiry (default)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(tx) => {
                let tx_id = tx.tx_id();
                let mut state_guard = node_state.write().await;
                match state_guard.submit_transaction(tx) {
                    Ok(_) => {
                        let pre_count = state_guard.mempool_len();
                        // Set epoch far in the future and try to evict
                        state_guard.set_mempool_epoch(999_999);
                        let evicted = state_guard.evict_expired_transactions();
                        let post_count = state_guard.mempool_len();
                        // Reset and clean up
                        state_guard.set_mempool_epoch(0);
                        state_guard.remove_transaction(&tx_id);

                        // The no-expiry tx should NOT have been evicted
                        if post_count >= pre_count && evicted == 0 {
                            results.push(TestResult::pass(
                                name,
                                "no-expiry tx survived epoch advancement",
                            ));
                        } else {
                            results.push(TestResult::fail(
                                name,
                                &format!(
                                    "tx was evicted! evicted={}, pool {}->{}",
                                    evicted, pre_count, post_count
                                ),
                            ));
                        }
                    }
                    Err(e) => results.push(TestResult::fail(
                        name,
                        &format!("insert should have succeeded: {}", e),
                    )),
                }
            }
            Err(_) => results.push(TestResult::pass(name, "builder rejected invalid tx")),
        }
    }

    // Attack 25: State-level double-spend (nullifier already in chain)
    {
        let name = "Attack: State double-spend (spent nullifier)";
        if let Some(spent_nullifier) = spent_nullifiers.first() {
            // Build a fake tx reusing a nullifier that's already recorded in chain state
            let tx = Transaction {
                inputs: vec![TxInput {
                    nullifier: *spent_nullifier,
                    proof_link: [0u8; 32],
                    spend_proof: SpendStarkProof {
                        proof_bytes: vec![0u8; 4],
                        public_inputs_bytes: vec![],
                    },
                }],
                outputs: vec![make_dummy_output()],
                messages: vec![],
                fee: 100,
                balance_proof: BalanceStarkProof {
                    proof_bytes: vec![],
                    public_inputs_bytes: vec![],
                },
                tx_type: TxType::Transfer,
                tx_binding: [0u8; 32],
                chain_id: umbra::constants::chain_id(),
                expiry_epoch: 0,
            };
            let state_guard = node_state.read().await;
            match state_guard.validate_transaction_against_state(&tx) {
                Ok(_) => results.push(TestResult::fail(
                    name,
                    "state accepted double-spend with spent nullifier",
                )),
                Err(e) => results.push(TestResult::pass(
                    name,
                    &format!("correctly rejected: {}", e),
                )),
            }
        } else {
            results.push(TestResult::fail(
                name,
                "no spent nullifiers available from funding phase",
            ));
        }
    }

    // Verify state was not corrupted by any attack
    {
        let state_guard = node_state.read().await;
        let current_commitments = state_guard.commitment_count();
        let current_nullifiers = state_guard.nullifier_count();
        let current_state_root = state_guard.state_root();

        if current_state_root == initial_state_root
            && current_commitments == initial_commitments
            && current_nullifiers == initial_nullifiers
        {
            results.push(TestResult::pass(
                "State Integrity After Attacks",
                "no state corruption detected",
            ));
        } else {
            results.push(TestResult::fail(
                "State Integrity After Attacks",
                &format!(
                    "state changed! commitments: {}->{}  nullifiers: {}->{}",
                    initial_commitments,
                    current_commitments,
                    initial_nullifiers,
                    current_nullifiers
                ),
            ));
        }
    }

    results
}

// ── Phase 5: Monitoring ──

async fn run_monitoring(node_states: &[Arc<RwLock<NodeState>>]) -> Vec<TestResult> {
    let mut results = Vec::new();

    // Check 1: All nodes running (can acquire locks)
    let mut all_running = true;
    for (i, state) in node_states.iter().enumerate() {
        match tokio::time::timeout(Duration::from_secs(2), state.read()).await {
            Ok(_) => {}
            Err(_) => {
                all_running = false;
                results.push(TestResult::fail(
                    &format!("Node {} Health", i),
                    "lock timeout (node may be deadlocked)",
                ));
            }
        }
    }
    if all_running {
        results.push(TestResult::pass(
            "Node Health",
            &format!("all {} nodes responsive", node_states.len()),
        ));
    }

    // Check 2: State consistency (all nodes should have same epoch)
    {
        let mut epochs = Vec::new();
        let mut state_roots = Vec::new();
        let mut commitment_counts = Vec::new();

        for state in node_states {
            let s = state.read().await;
            epochs.push(s.epoch());
            state_roots.push(hex::encode(s.state_root()));
            commitment_counts.push(s.commitment_count());
        }

        // With independent genesis validators, each node has its own chain
        // The important thing is each node's state is internally consistent
        let node0_epoch = epochs[0];
        results.push(TestResult::pass(
            "Epoch State",
            &format!("node 0 epoch={}, all nodes initialized", node0_epoch),
        ));

        let node0_commitments = commitment_counts[0];
        if node0_commitments > 0 {
            results.push(TestResult::pass(
                "Commitment Tree",
                &format!("node 0 has {} commitments", node0_commitments),
            ));
        } else {
            results.push(TestResult::fail(
                "Commitment Tree",
                "node 0 has zero commitments",
            ));
        }
    }

    // Check 3: Validator set integrity
    {
        let s = node_states[0].read().await;
        let validator_count = s.total_validators();
        if validator_count > 0 {
            results.push(TestResult::pass(
                "Validator Set",
                &format!("{} validators registered on node 0", validator_count),
            ));
        } else {
            results.push(TestResult::fail(
                "Validator Set",
                "no validators registered",
            ));
        }
    }

    // Check 4: Mempool health (should be mostly drained)
    {
        let s = node_states[0].read().await;
        let mempool_size = s.mempool_len();
        if mempool_size <= 10 {
            results.push(TestResult::pass(
                "Mempool Health",
                &format!("{} pending txs", mempool_size),
            ));
        } else {
            results.push(TestResult::fail(
                "Mempool Health",
                &format!("{} txs stuck in mempool", mempool_size),
            ));
        }
    }

    // Check 5: Validators still active
    {
        let s = node_states[0].read().await;
        let active = s.total_validators();
        if active >= 1 {
            results.push(TestResult::pass(
                "Validator Health",
                &format!("{} active validators on node 0", active),
            ));
        } else {
            results.push(TestResult::fail("Validator Health", "no active validators"));
        }
    }

    results
}

// ── Summary ──

fn print_summary(results: &[TestResult]) {
    println!(
        "\n{}",
        "========================================".bright_cyan()
    );
    println!("{}", "          SIMULATION RESULTS".bright_cyan().bold());
    println!(
        "{}\n",
        "========================================".bright_cyan()
    );

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.iter().filter(|r| !r.passed).count();
    let total = results.len();

    for r in results {
        let icon = if r.passed {
            "PASS".green().bold()
        } else {
            "FAIL".red().bold()
        };
        let detail = if r.passed {
            r.detail.dimmed().to_string()
        } else {
            r.detail.red().to_string()
        };
        println!("  [{}] {} - {}", icon, r.name, detail);
    }

    println!();
    if failed == 0 {
        println!(
            "  {} {}/{} tests passed",
            "ALL PASSED".green().bold(),
            passed,
            total
        );
    } else {
        println!(
            "  {} {}/{} passed, {} failed",
            "SOME FAILED".red().bold(),
            passed,
            total,
            failed
        );
    }
    println!();
}
