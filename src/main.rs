//! Spectra node and wallet binary.
//!
//! Runs a full Spectra node with P2P networking, mempool, persistent storage,
//! and JSON RPC API. Also provides a wallet CLI for key management, balance
//! queries, and sending transactions.
//!
//! Usage:
//!   spectra                         # run node (default)
//!   spectra node                    # run node (explicit)
//!   spectra --demo                  # run protocol demo
//!   spectra wallet init             # create a new wallet
//!   spectra wallet balance           # scan chain + show balance
//!   spectra wallet send --to <file> --amount N --fee N
//!   spectra wallet messages          # show received messages

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Spectra post-quantum cryptocurrency node and wallet.
#[derive(Parser, Debug)]
#[command(
    name = "spectra",
    version,
    about = "Spectra post-quantum private cryptocurrency"
)]
struct Cli {
    /// Data directory for persistent storage.
    #[arg(long, default_value = "./spectra-data", global = true)]
    data_dir: PathBuf,

    /// RPC address for node/wallet communication.
    #[arg(long, default_value = "127.0.0.1:9733", global = true)]
    rpc_addr: SocketAddr,

    /// Run the demo walkthrough instead of starting a node.
    #[arg(long)]
    demo: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the Spectra node.
    Node {
        /// P2P listen address.
        #[arg(long, default_value = "0.0.0.0:9732")]
        listen_addr: SocketAddr,

        /// Bootstrap peer addresses (comma-separated).
        #[arg(long, value_delimiter = ',')]
        peers: Vec<SocketAddr>,

        /// Register as a genesis validator (for bootstrapping a new network).
        #[arg(long)]
        genesis_validator: bool,
    },

    /// Manage the Spectra wallet.
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
}

#[derive(Subcommand, Debug)]
enum WalletAction {
    /// Create a new wallet.
    Init,

    /// Show wallet address.
    Address,

    /// Scan the chain and show balance.
    Balance,

    /// Scan the chain for new outputs.
    Scan,

    /// Send a transaction.
    Send {
        /// Path to recipient's .spectra-address file.
        #[arg(long)]
        to: PathBuf,

        /// Amount to send (in base units).
        #[arg(long)]
        amount: u64,

        /// Transaction fee (in base units).
        #[arg(long)]
        fee: u64,

        /// Optional message to encrypt for the recipient.
        #[arg(long)]
        message: Option<String>,
    },

    /// Show received encrypted messages.
    Messages,

    /// Export wallet address to a file for sharing.
    Export {
        /// Output file path.
        #[arg(long)]
        file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    if cli.demo {
        run_demo();
        return Ok(());
    }

    match cli.command {
        // Default (no subcommand) → run node for backward compatibility
        None => {
            run_node(
                cli.data_dir,
                cli.rpc_addr,
                "0.0.0.0:9732".parse()?,
                vec![],
                false,
            )
            .await
        }

        Some(Command::Node {
            listen_addr,
            peers,
            genesis_validator,
        }) => {
            run_node(
                cli.data_dir,
                cli.rpc_addr,
                listen_addr,
                peers,
                genesis_validator,
            )
            .await
        }

        Some(Command::Wallet { action }) => {
            run_wallet_command(action, &cli.data_dir, cli.rpc_addr).await
        }
    }
}

async fn run_node(
    data_dir: PathBuf,
    rpc_addr: SocketAddr,
    listen_addr: SocketAddr,
    peers: Vec<SocketAddr>,
    genesis_validator: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Starting Spectra node...");
    tracing::info!("P2P: {}", listen_addr);
    tracing::info!("RPC: {}", rpc_addr);
    tracing::info!("Data: {}", data_dir.display());

    let keypair = spectra::node::load_or_generate_keypair(&data_dir)?;

    let config = spectra::node::NodeConfig {
        listen_addr,
        bootstrap_peers: peers,
        data_dir,
        rpc_addr,
        keypair,
        genesis_validator,
    };

    let rpc_addr = config.rpc_addr;
    let mut node = spectra::node::Node::new(config).await?;

    let rpc_state = spectra::rpc::RpcState {
        node: node.state(),
        p2p: node.p2p_handle(),
    };
    tokio::spawn(spectra::rpc::serve(rpc_addr, rpc_state));

    node.run().await;
    Ok(())
}

async fn run_wallet_command(
    action: WalletAction,
    data_dir: &std::path::Path,
    rpc_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    use spectra::wallet_cli;

    match action {
        WalletAction::Init => wallet_cli::cmd_init(data_dir),
        WalletAction::Address => wallet_cli::cmd_address(data_dir),
        WalletAction::Balance => wallet_cli::cmd_balance(data_dir, rpc_addr).await,
        WalletAction::Scan => wallet_cli::cmd_scan(data_dir, rpc_addr).await,
        WalletAction::Send {
            to,
            amount,
            fee,
            message,
        } => wallet_cli::cmd_send(data_dir, rpc_addr, &to, amount, fee, message).await,
        WalletAction::Messages => wallet_cli::cmd_messages(data_dir),
        WalletAction::Export { file } => wallet_cli::cmd_export(data_dir, &file),
    }
}

/// Run the original protocol demonstration.
fn run_demo() {
    use spectra::consensus::bft::{select_committee, Validator};
    use spectra::consensus::dag::{Dag, Vertex, VertexId};
    use spectra::crypto::commitment::BlindingFactor;
    use spectra::crypto::keys::{Signature, SigningKeypair};
    use spectra::crypto::vrf::EpochSeed;
    use spectra::state::ChainState;
    use spectra::transaction::builder::{InputSpec, TransactionBuilder};
    use spectra::wallet::Wallet;

    println!("=== SPECTRA: Post-Quantum Private Cryptocurrency ===\n");

    // ────────────────────────────────────────────────────────
    // 1. KEY GENERATION (Post-Quantum)
    // ────────────────────────────────────────────────────────
    println!("[1] Generating post-quantum keypairs (Dilithium5 + Kyber1024)...");

    let mut alice_wallet = Wallet::new();
    let mut bob_wallet = Wallet::new();

    let alice_addr = alice_wallet.address();
    let bob_addr = bob_wallet.address();

    println!(
        "    Alice address ID: {}",
        hex::encode(&alice_addr.address_id()[..8])
    );
    println!(
        "    Bob   address ID: {}",
        hex::encode(&bob_addr.address_id()[..8])
    );
    println!(
        "    Signing key size: {} bytes (Dilithium5)",
        alice_addr.signing.0.len()
    );
    println!(
        "    KEM key size:     {} bytes (Kyber1024)",
        alice_addr.kem.0.len()
    );

    // ────────────────────────────────────────────────────────
    // 2. FUND ALICE (Simulated coinbase)
    // ────────────────────────────────────────────────────────
    println!("\n[2] Funding Alice with 100,000 units (simulated coinbase)...");
    println!("    Generating zk-STARK proofs (balance + spend)...");

    let coinbase_blind = BlindingFactor::random();
    let coinbase_auth = spectra::hash_domain(b"coinbase", b"genesis-auth");

    let funding_tx = TransactionBuilder::new()
        .add_input(InputSpec {
            value: 100_000,
            blinding: coinbase_blind,
            spend_auth: coinbase_auth,
            merkle_path: vec![],
        })
        .add_output(alice_wallet.kem_public_key().clone(), 100_000)
        .set_fee(0)
        .build()
        .unwrap();

    alice_wallet.scan_transaction(&funding_tx);
    println!("    Alice balance: {} units", alice_wallet.balance());
    println!(
        "    Balance proof size: {} bytes (zk-STARK)",
        funding_tx.balance_proof.proof_bytes.len()
    );
    println!(
        "    Spend proof size:   {} bytes (zk-STARK)",
        funding_tx.inputs[0].spend_proof.proof_bytes.len()
    );

    // ────────────────────────────────────────────────────────
    // 3. PRIVATE TRANSACTION: Alice → Bob
    // ────────────────────────────────────────────────────────
    println!("\n[3] Alice sends 25,000 to Bob (private, with encrypted message)...");
    println!("    Generating zk-STARK proofs...");

    let tx = alice_wallet
        .build_transaction(
            bob_wallet.kem_public_key(),
            25_000,
            100,
            Some(b"Hey Bob! Payment for the quantum computer parts.".to_vec()),
        )
        .unwrap();

    let tx_id = tx.tx_id();
    println!("    Tx ID:    {}", hex::encode(&tx_id.0[..16]));
    println!(
        "    Inputs:   {} (nullifiers revealed, all else hidden by zk-STARK)",
        tx.inputs.len()
    );
    println!(
        "    Outputs:  {} (payment + change, amounts hidden)",
        tx.outputs.len()
    );
    println!(
        "    Messages: {} (encrypted to recipient only)",
        tx.messages.len()
    );
    println!("    Fee:      {} units", tx.fee);
    println!("    Chain ID: {}", hex::encode(&tx.chain_id[..8]));
    println!("    Est size: ~{} bytes", tx.estimated_size());

    // Bob scans and finds his payment + message
    bob_wallet.scan_transaction(&tx);
    alice_wallet.scan_transaction(&tx); // Alice picks up change

    println!("\n    After scanning:");
    println!(
        "    Alice balance: {} units (change returned)",
        alice_wallet.balance()
    );
    println!("    Bob balance:   {} units", bob_wallet.balance());

    let msgs = bob_wallet.received_messages();
    println!(
        "    Bob received message: {:?}",
        String::from_utf8_lossy(&msgs[0].content)
    );

    // ────────────────────────────────────────────────────────
    // 4. UNLINKABILITY DEMO
    // ────────────────────────────────────────────────────────
    println!("\n[4] Demonstrating unlinkability...");

    println!(
        "    Nullifier (input):  {}",
        hex::encode(&tx.inputs[0].nullifier.0[..16])
    );
    for (i, out) in tx.outputs.iter().enumerate() {
        println!(
            "    Output {} commitment: {}",
            i,
            hex::encode(&out.commitment.0[..16])
        );
        println!(
            "    Output {} stealth:    {}",
            i,
            hex::encode(&out.stealth_address.one_time_key[..16])
        );
    }
    println!(
        "    Input proof_link:    {}",
        hex::encode(&tx.inputs[0].proof_link[..16])
    );
    println!("    -> Nullifier cannot be linked to any output commitment");
    println!("    -> Input proof_link cannot be linked to any output commitment");
    println!("    -> Stealth addresses are unique per-transaction (unlinkable)");
    println!("    -> Amounts are hidden behind commitments");
    println!("    -> zk-STARK proofs reveal NOTHING about values or keys");

    // A bystander cannot detect anything
    let mut eve_wallet = Wallet::new();
    eve_wallet.scan_transaction(&tx);
    println!(
        "    -> Eve (bystander) found {} outputs, {} messages",
        eve_wallet.output_count(),
        eve_wallet.received_messages().len()
    );

    // ────────────────────────────────────────────────────────
    // 5. DAG-BFT CONSENSUS
    // ────────────────────────────────────────────────────────
    println!("\n[5] Demonstrating DAG-BFT consensus...");

    // Create validators
    let mut validator_pairs: Vec<(SigningKeypair, Validator)> = Vec::new();
    for i in 0..30 {
        let kp = SigningKeypair::generate();
        let v = Validator::new(kp.public.clone());
        if i < 3 {
            println!("    Validator {}: {}", i, hex::encode(&v.id[..8]));
        }
        validator_pairs.push((kp, v));
    }
    println!(
        "    ... {} total validators registered",
        validator_pairs.len()
    );

    // Committee selection via VRF
    let epoch_seed = EpochSeed::genesis();
    let committee = select_committee(
        &epoch_seed,
        &validator_pairs,
        spectra::constants::COMMITTEE_SIZE,
    );
    println!(
        "\n    Epoch 0 committee selected via VRF: {} members",
        committee.len()
    );
    for (i, (v, vrf)) in committee.iter().enumerate().take(3) {
        println!(
            "    Committee[{}]: {} (VRF sort key: {})",
            i,
            hex::encode(&v.id[..8]),
            vrf.sort_key()
        );
    }

    // Build the DAG
    let genesis = Dag::genesis_vertex();
    let genesis_id = genesis.id;
    let mut dag = Dag::new(genesis);
    println!("\n    Genesis vertex: {}", hex::encode(&genesis_id.0[..16]));

    // Add vertices with our transaction
    let v1_id = VertexId(spectra::hash_domain(b"demo.vertex", b"v1"));
    let v1 = Vertex {
        id: v1_id,
        parents: vec![genesis_id],
        epoch: 0,
        round: 1,
        proposer: committee
            .first()
            .map(|(v, _)| v.public_key.clone())
            .unwrap_or_else(|| SigningKeypair::generate().public),
        transactions: vec![tx.clone()],
        timestamp: 1000,
        state_root: [0u8; 32],
        signature: Signature(vec![]),
        vrf_proof: None,
    };
    dag.insert_unchecked(v1).unwrap();
    dag.finalize(&v1_id);

    // Parallel vertex (different validator, same parent)
    let v2_id = VertexId(spectra::hash_domain(b"demo.vertex", b"v2"));
    let v2 = Vertex {
        id: v2_id,
        parents: vec![genesis_id],
        epoch: 0,
        round: 1,
        proposer: committee
            .get(1)
            .map(|(v, _)| v.public_key.clone())
            .unwrap_or_else(|| SigningKeypair::generate().public),
        transactions: vec![],
        timestamp: 1000,
        state_root: [0u8; 32],
        signature: Signature(vec![]),
        vrf_proof: None,
    };
    dag.insert_unchecked(v2).unwrap();
    dag.finalize(&v2_id);

    // Diamond merge: v3 references both v1 and v2
    let v3_id = VertexId(spectra::hash_domain(b"demo.vertex", b"v3"));
    let v3 = Vertex {
        id: v3_id,
        parents: vec![v1_id, v2_id],
        epoch: 0,
        round: 2,
        proposer: committee
            .first()
            .map(|(v, _)| v.public_key.clone())
            .unwrap_or_else(|| SigningKeypair::generate().public),
        transactions: vec![],
        timestamp: 2000,
        state_root: [0u8; 32],
        signature: Signature(vec![]),
        vrf_proof: None,
    };
    dag.insert_unchecked(v3).unwrap();
    dag.finalize(&v3_id);

    println!(
        "    DAG vertices: {} (including parallel processing)",
        dag.len()
    );
    println!("    DAG tips: {:?}", dag.tips().len());
    println!("    Finalized vertices: {}", dag.finalized_order().len());
    println!("    -> Instant finality: vertices are final once BFT quorum reached");
    println!("    -> DAG structure: parallel vertices enable higher throughput");

    // ────────────────────────────────────────────────────────
    // 6. STATE APPLICATION
    // ────────────────────────────────────────────────────────
    println!("\n[6] Applying transactions to chain state...");

    let mut state = ChainState::new();

    // Add funding tx outputs to state (coinbase — no spend proof to verify)
    for output in &funding_tx.outputs {
        state.add_commitment(output.commitment);
    }
    println!("    After funding tx:");
    println!("    Commitments in state: {}", state.commitment_count());
    println!("    State root: {}", hex::encode(&state.state_root()[..16]));

    // Add payment tx outputs
    for output in &tx.outputs {
        state.add_commitment(output.commitment);
    }
    // Record spent nullifiers
    for input in &tx.inputs {
        state.mark_nullifier(input.nullifier);
    }
    println!("    After payment tx:");
    println!("    Commitments in state: {}", state.commitment_count());
    println!("    Nullifiers spent: {}", state.nullifier_count());
    println!("    State root: {}", hex::encode(&state.state_root()[..16]));

    // ────────────────────────────────────────────────────────
    // 7. SUMMARY
    // ────────────────────────────────────────────────────────
    println!("\n========================================");
    println!("             SPECTRA SUMMARY            ");
    println!("========================================");
    println!();
    println!("  Privacy (Full Zero-Knowledge):");
    println!("    - Stealth addresses    (receiver unlinkability)");
    println!("    - Nullifier-based      (sender unlinkability)");
    println!("    - Confidential amounts  (hidden behind commitments)");
    println!("    - Encrypted messaging  (Kyber1024 KEM + BLAKE3)");
    println!("    - zk-STARK proofs      (values hidden from ALL observers)");
    println!();
    println!("  Quantum Resistance:");
    println!("    - Signatures:  CRYSTALS-Dilithium5 (NIST PQC Level 5)");
    println!("    - Encryption:  CRYSTALS-Kyber1024  (NIST PQC Level 5)");
    println!("    - Hashing:     Rescue Prime / BLAKE3 (post-quantum secure)");
    println!("    - Proofs:      zk-STARK (~127-bit conjectured security)");
    println!("    - No trusted setup required (fully transparent)");
    println!();
    println!("  Consensus: DAG-BFT (Proof of Verifiable Participation)");
    println!("    - Not PoW (no energy waste, no mining)");
    println!("    - Not PoS (equal power, not stake-weighted)");
    println!("    - VRF committee selection (unbiased, unpredictable)");
    println!("    - Instant deterministic finality");
    println!("    - DAG enables parallel transaction processing");
    println!();
    println!("  Security Hardening:");
    println!("    - Constant-time comparisons for all cryptographic checks");
    println!("    - Epoch-bound votes prevent cross-epoch replay");
    println!("    - tx_content_hash binds proofs to specific transactions");
    println!("    - Chain ID + expiry epoch for replay protection");
    println!("    - Proof links bind spend + balance proofs (commitment hidden)");
    println!("    - Merkle tree padded to canonical depth 20");
    println!("    - Network message size limits (DoS protection)");
    println!();
    println!("=== Demo complete ===");
}
