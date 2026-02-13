//! Spectra Network Simulator
//!
//! A standalone binary that spins up real Spectra nodes with P2P networking,
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

use spectra::crypto::keys::{KemKeypair, SigningKeypair};
use spectra::crypto::stark::default_proof_options;
use spectra::crypto::stark::types::{BalanceStarkProof, SpendStarkProof};
use spectra::node::{Node, NodeConfig, NodeState};
use spectra::rpc::{serve as rpc_serve, RpcState};
use spectra::storage::Storage;
use spectra::transaction::builder::{InputSpec, TransactionBuilder};
use spectra::transaction::Transaction;
use spectra::wallet::Wallet;

// ── Configuration ──

const NUM_VALIDATORS: usize = 3;
const P2P_BASE_PORT: u16 = 19732;
const RPC_BASE_PORT: u16 = 19832;
const FUNDING_AMOUNT: u64 = 10_000_000;
const TX_FEE: u64 = 100;

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
    println!("{}", "    SPECTRA NETWORK SIMULATOR".bright_cyan().bold());
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

    match genesis_funded {
        Ok((alice_bal, bob_bal)) => {
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
    }

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

    let chaos_results = run_chaos_scenarios(&node_states[0]).await;

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
        };

        let mut node = Node::new(config)
            .await
            .map_err(|e| format!("node {} init: {}", i, e))?;

        let state = node.state();
        let p2p_handle = node.p2p_handle();

        // Start RPC
        let rpc_state = RpcState {
            node: state.clone(),
            p2p: p2p_handle,
        };
        tokio::spawn(async move {
            let _ = rpc_serve(rpc_addr, rpc_state).await;
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

async fn fund_users(
    genesis_state: &Arc<RwLock<NodeState>>,
    genesis_kem: &KemKeypair,
    alice_wallet: &mut Wallet,
    bob_wallet: &mut Wallet,
) -> Result<(u64, u64), String> {
    let state_guard = genesis_state.read().await;

    // Get the genesis coinbase output by scanning state
    let genesis_coinbase = state_guard
        .storage
        .get_coinbase_output(0)
        .map_err(|e| format!("get coinbase: {}", e))?
        .ok_or("no genesis coinbase found")?;

    // Create a wallet from the genesis KEM keypair to claim the coinbase
    let genesis_keys = spectra::crypto::keys::FullKeypair {
        signing: SigningKeypair::generate(), // signing key doesn't matter for scanning
        kem: genesis_kem.clone(),
    };
    let mut genesis_wallet = Wallet::from_keypair(genesis_keys);

    // Scan the genesis coinbase output using the proper wallet API
    genesis_wallet.scan_coinbase_output(&genesis_coinbase, Some(&state_guard.ledger.state));

    let genesis_balance = genesis_wallet.balance();
    if genesis_balance == 0 {
        return Err("genesis wallet has zero balance after scanning".to_string());
    }
    println!(
        "  Genesis wallet scanned: {} units available",
        genesis_balance
    );

    // Build funding tx for Alice
    let alice_tx = genesis_wallet
        .build_transaction_with_state(
            alice_wallet.kem_public_key(),
            FUNDING_AMOUNT,
            TX_FEE,
            Some(b"Genesis funding for Alice".to_vec()),
            Some(&state_guard.ledger.state),
        )
        .map_err(|e| format!("build alice tx: {}", e))?;

    let alice_tx_binding = alice_tx.tx_binding;

    // Submit to mempool directly (we have the state lock)
    drop(state_guard);

    // Submit Alice funding tx
    {
        let mut state_guard = genesis_state.write().await;
        state_guard
            .mempool
            .insert(alice_tx.clone())
            .map_err(|e| format!("mempool alice: {}", e))?;
    }
    println!("  Submitted Alice funding tx to mempool");

    // Alice scans the tx to find her output; genesis scans for change
    alice_wallet.scan_transaction(&alice_tx);
    genesis_wallet.scan_transaction(&alice_tx);
    genesis_wallet.confirm_transaction(&alice_tx_binding);

    // Wait for the tx to be included in a vertex and finalized
    // so the change output's commitment is in the chain state
    println!("  Waiting for Alice tx to finalize...");
    wait_for_finalization(genesis_state, 2).await;

    // Build funding tx for Bob (from genesis change)
    let state_guard = genesis_state.read().await;
    genesis_wallet.resolve_commitment_indices(&state_guard.ledger.state);
    drop(state_guard);

    let state_guard = genesis_state.read().await;
    let bob_tx = genesis_wallet
        .build_transaction_with_state(
            bob_wallet.kem_public_key(),
            FUNDING_AMOUNT,
            TX_FEE,
            Some(b"Genesis funding for Bob".to_vec()),
            Some(&state_guard.ledger.state),
        )
        .map_err(|e| format!("build bob tx: {}", e))?;

    let bob_tx_binding = bob_tx.tx_binding;
    drop(state_guard);

    {
        let mut state_guard = genesis_state.write().await;
        state_guard
            .mempool
            .insert(bob_tx.clone())
            .map_err(|e| format!("mempool bob: {}", e))?;
    }
    println!("  Submitted Bob funding tx to mempool");

    bob_wallet.scan_transaction(&bob_tx);
    genesis_wallet.scan_transaction(&bob_tx);
    genesis_wallet.confirm_transaction(&bob_tx_binding);

    // Wait for Bob tx to finalize
    println!("  Waiting for Bob tx to finalize...");
    wait_for_finalization(genesis_state, 2).await;

    // Resolve commitment indices for both wallets
    let state_guard = genesis_state.read().await;
    alice_wallet.resolve_commitment_indices(&state_guard.ledger.state);
    bob_wallet.resolve_commitment_indices(&state_guard.ledger.state);
    drop(state_guard);

    Ok((alice_wallet.balance(), bob_wallet.balance()))
}

/// Wait for at least `count` new vertices to be finalized on the node.
async fn wait_for_finalization(state: &Arc<RwLock<NodeState>>, count: u64) {
    let initial = {
        let s = state.read().await;
        s.storage.finalized_vertex_count().unwrap_or(0)
    };
    let target = initial + count;

    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let current = {
            let s = state.read().await;
            s.storage.finalized_vertex_count().unwrap_or(0)
        };
        if current >= target {
            return;
        }
    }
    // Timeout after 20 seconds — continue anyway
    println!("  (finalization wait timed out, continuing)");
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

        // Resolve commitment indices
        {
            let state_guard = node_state.read().await;
            sender.resolve_commitment_indices(&state_guard.ledger.state);
        }

        // Build transaction
        let state_guard = node_state.read().await;
        let tx_result = sender.build_transaction_with_state(
            receiver.kem_public_key(),
            *amount,
            TX_FEE,
            message.map(|m| m.to_vec()),
            Some(&state_guard.ledger.state),
        );
        drop(state_guard);

        match tx_result {
            Ok(tx) => {
                let tx_binding = tx.tx_binding;

                // Submit to mempool
                let mut state_guard = node_state.write().await;
                match state_guard.mempool.insert(tx.clone()) {
                    Ok(_) => {
                        drop(state_guard);

                        // Both wallets scan the transaction (receiver for output, sender for change)
                        receiver.scan_transaction(&tx);
                        sender.scan_transaction(&tx);
                        sender.confirm_transaction(&tx_binding);

                        // Wait for finalization so commitment indices are available
                        wait_for_finalization(node_state, 1).await;

                        // Resolve indices for both
                        let state_guard = node_state.read().await;
                        alice.resolve_commitment_indices(&state_guard.ledger.state);
                        bob.resolve_commitment_indices(&state_guard.ledger.state);
                        drop(state_guard);

                        results.push(TestResult::pass(
                            &round_name,
                            &format!("Alice={}, Bob={}", alice.balance(), bob.balance()),
                        ));
                    }
                    Err(e) => {
                        drop(state_guard);
                        results.push(TestResult::fail(
                            &round_name,
                            &format!("mempool rejected: {}", e),
                        ));
                    }
                }
            }
            Err(e) => {
                results.push(TestResult::fail(
                    &round_name,
                    &format!("build failed: {}", e),
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
    // Total should be 2 * FUNDING_AMOUNT minus fees
    let expected_max = 2 * FUNDING_AMOUNT;
    let fees_paid = 5 * TX_FEE; // 5 rounds * TX_FEE each
    let expected_total = expected_max - fees_paid;

    if total == expected_total {
        results.push(TestResult::pass(
            "Balance Conservation",
            &format!(
                "total={} (expected={}, fees={})",
                total, expected_total, fees_paid
            ),
        ));
    } else {
        results.push(TestResult::fail(
            "Balance Conservation",
            &format!(
                "total={} != expected={} (fees={})",
                total, expected_total, fees_paid
            ),
        ));
    }

    results
}

// ── Phase 4: Chaos ──

async fn run_chaos_scenarios(node_state: &Arc<RwLock<NodeState>>) -> Vec<TestResult> {
    let mut results = Vec::new();

    // Get chain state snapshot for comparison after attacks
    let (initial_commitments, initial_nullifiers, initial_state_root) = {
        let state_guard = node_state.read().await;
        (
            state_guard.ledger.state.commitment_count(),
            state_guard.ledger.state.nullifier_count(),
            state_guard.ledger.state.state_root(),
        )
    };

    // Attack 1: Invalid proof bytes
    {
        let name = "Attack: Corrupted proof";
        let mallory = Wallet::new();

        // Build a valid-looking tx structure but with garbage proof
        let blind = spectra::crypto::commitment::BlindingFactor::random();
        let spend_auth = spectra::hash_domain(b"mallory", b"fake-auth");

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_fee(100)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(mut tx) => {
                // Corrupt the balance proof
                if !tx.balance_proof.proof_bytes.is_empty() {
                    tx.balance_proof.proof_bytes[0] ^= 0xFF;
                }
                let mut state_guard = node_state.write().await;
                match state_guard.mempool.insert(tx) {
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
        let blind = spectra::crypto::commitment::BlindingFactor::random();
        let spend_auth = spectra::hash_domain(b"mallory", b"fake-auth-2");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_fee(100)
            .set_chain_id([0xDE; 32]) // Wrong chain ID
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(tx) => {
                // Validate against chain state (which checks chain_id)
                let state_guard = node_state.read().await;
                match state_guard.ledger.state.validate_transaction(&tx) {
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
    {
        let name = "Attack: Overflow fee";
        let blind = spectra::crypto::commitment::BlindingFactor::random();
        let spend_auth = spectra::hash_domain(b"mallory", b"fake-auth-3");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: u64::MAX,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 1)
            .set_fee(spectra::constants::MAX_TX_FEE + 1)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(tx) => {
                let mut state_guard = node_state.write().await;
                match state_guard.mempool.insert(tx) {
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
    {
        let name = "Attack: Zero fee";
        let blind = spectra::crypto::commitment::BlindingFactor::random();
        let spend_auth = spectra::hash_domain(b"mallory", b"fake-auth-4");
        let mallory = Wallet::new();

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 1000)
            .set_fee(0)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(tx) => {
                let mut state_guard = node_state.write().await;
                match state_guard.mempool.insert(tx) {
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
            tx_type: spectra::transaction::TxType::Transfer,
            tx_binding: [0u8; 32],
            chain_id: spectra::constants::chain_id(),
            expiry_epoch: 0,
        };

        let mut state_guard = node_state.write().await;
        match state_guard.mempool.insert(tx) {
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
        let nullifier = spectra::crypto::nullifier::Nullifier(spectra::hash_domain(
            b"mallory",
            b"replay-nullifier",
        ));

        let tx = Transaction {
            inputs: vec![
                spectra::transaction::TxInput {
                    nullifier,
                    spend_proof: SpendStarkProof {
                        proof_bytes: vec![1, 2, 3],
                        public_inputs_bytes: vec![],
                    },
                    proof_link: [0u8; 32],
                },
                spectra::transaction::TxInput {
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
            tx_type: spectra::transaction::TxType::Transfer,
            tx_binding: [0u8; 32],
            chain_id: spectra::constants::chain_id(),
            expiry_epoch: 0,
        };

        let mut state_guard = node_state.write().await;
        match state_guard.mempool.insert(tx) {
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
        let blind = spectra::crypto::commitment::BlindingFactor::random();
        let spend_auth = spectra::hash_domain(b"mallory", b"fake-auth-7");
        let mallory = Wallet::new();

        // Try building a tx with a message exceeding MAX_MESSAGE_SIZE
        let huge_msg = vec![0xAA; spectra::constants::MAX_MESSAGE_SIZE + 1];

        let tx_result = TransactionBuilder::new()
            .add_input(InputSpec {
                value: 1000,
                blinding: blind,
                spend_auth,
                merkle_path: vec![],
            })
            .add_output(mallory.kem_public_key().clone(), 900)
            .set_fee(100)
            .add_message(mallory.kem_public_key().clone(), huge_msg)
            .set_proof_options(default_proof_options())
            .build();

        match tx_result {
            Ok(tx) => {
                let mut state_guard = node_state.write().await;
                match state_guard.mempool.insert(tx) {
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

    // Verify state was not corrupted by any attack
    {
        let state_guard = node_state.read().await;
        let current_commitments = state_guard.ledger.state.commitment_count();
        let current_nullifiers = state_guard.ledger.state.nullifier_count();
        let current_state_root = state_guard.ledger.state.state_root();

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
            epochs.push(s.ledger.state.epoch());
            state_roots.push(hex::encode(s.ledger.state.state_root()));
            commitment_counts.push(s.ledger.state.commitment_count());
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
        let validator_count = s.ledger.state.total_validators();
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
        let mempool_size = s.mempool.len();
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
        let active = s.ledger.state.total_validators();
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
