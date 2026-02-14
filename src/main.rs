//! Umbra node and wallet binary.
//!
//! Runs a full Umbra node with P2P networking, mempool, persistent storage,
//! and JSON RPC API. Also provides a wallet CLI for key management, balance
//! queries, and sending transactions.
//!
//! Usage:
//!   umbra                         # run node (default)
//!   umbra node                    # run node (explicit)
//!   umbra --demo                  # run protocol demo
//!   umbra wallet init             # create a new wallet
//!   umbra wallet balance           # scan chain + show balance
//!   umbra wallet send --to <file> --amount N
//!   umbra wallet messages          # show received messages

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use umbra::config::{NatConfig, TlsConfig, WalletTlsConfig};

/// Umbra post-quantum cryptocurrency node and wallet.
#[derive(Parser, Debug)]
#[command(
    name = "umbra",
    version,
    about = "Umbra post-quantum private cryptocurrency"
)]
struct Cli {
    /// Data directory for persistent storage.
    #[arg(long, default_value = "./umbra-data", global = true)]
    data_dir: PathBuf,

    /// RPC host for node/wallet communication.
    #[arg(long, default_value = "127.0.0.1", global = true)]
    rpc_host: String,

    /// RPC port for node/wallet communication.
    #[arg(long, default_value = "9733", global = true)]
    rpc_port: u16,

    /// Run the demo walkthrough instead of starting a node.
    #[arg(long)]
    demo: bool,

    // ── TLS flags (server-side mTLS for RPC) ──
    /// Server TLS certificate file (PEM).
    #[arg(long, global = true)]
    tls_cert: Option<PathBuf>,

    /// Server TLS private key file (PEM).
    #[arg(long, global = true)]
    tls_key: Option<PathBuf>,

    /// CA certificate file for client verification (PEM).
    #[arg(long, global = true)]
    tls_ca_cert: Option<PathBuf>,

    // ── TLS flags (client-side mTLS for wallet) ──
    /// Wallet client TLS certificate file (PEM).
    #[arg(long, global = true)]
    tls_client_cert: Option<PathBuf>,

    /// Wallet client TLS private key file (PEM).
    #[arg(long, global = true)]
    tls_client_key: Option<PathBuf>,

    // ── NAT flags ──
    /// Manually specify external address (IP:port) for nodes behind NAT.
    #[arg(long, global = true)]
    external_addr: Option<String>,

    /// Disable UPnP port mapping.
    #[arg(long, global = true)]
    no_upnp: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the Umbra node.
    Node {
        /// P2P listen host.
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// P2P listen port.
        #[arg(long, default_value = "9732")]
        port: u16,

        /// Bootstrap peer addresses (comma-separated).
        #[arg(long, value_delimiter = ',')]
        peers: Vec<SocketAddr>,

        /// Register as a genesis validator (for bootstrapping a new network).
        #[arg(long)]
        genesis_validator: bool,
    },

    /// Manage the Umbra wallet.
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
        /// Path to recipient's .umbra-address file.
        #[arg(long)]
        to: PathBuf,

        /// Amount to send (in base units).
        #[arg(long)]
        amount: u64,

        /// Optional message to encrypt for the recipient.
        #[arg(long)]
        message: Option<String>,
    },

    /// Show received encrypted messages.
    Messages,

    /// Show transaction history.
    History,

    /// Consolidate all unspent outputs into one.
    Consolidate,

    /// Recover a wallet from a mnemonic phrase + backup file.
    Recover {
        /// 24-word recovery phrase (space-separated, in quotes).
        #[arg(long)]
        phrase: String,
    },

    /// Export wallet address to a file for sharing.
    Export {
        /// Output file path.
        #[arg(long)]
        file: PathBuf,
    },

    /// Start the wallet web UI.
    Web {
        /// Web UI listen host.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Web UI listen port.
        #[arg(long, default_value = "9734")]
        port: u16,
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

    // Load config file (umbra.toml) — CLI flags override config values
    let config = umbra::config::UmbraConfig::load(&cli.data_dir);

    let rpc_addr: SocketAddr = format!("{}:{}", cli.rpc_host, cli.rpc_port).parse()?;

    // Build server TLS config: CLI flags override config file
    let cli_ca_cert = cli.tls_ca_cert; // take ownership once
    let server_tls = if cli.tls_cert.is_some() || cli.tls_key.is_some() || cli_ca_cert.is_some() {
        let cert = cli.tls_cert.ok_or("--tls-cert required when using TLS")?;
        let key = cli.tls_key.ok_or("--tls-key required when using TLS")?;
        let ca = cli_ca_cert
            .clone()
            .ok_or("--tls-ca-cert required when using TLS")?;
        Some(TlsConfig {
            cert_file: cert,
            key_file: key,
            ca_cert_file: ca,
        })
    } else {
        config.node.tls.clone()
    };

    // Build wallet TLS config: CLI flags override config file
    let wallet_tls = if cli.tls_client_cert.is_some() || cli.tls_client_key.is_some() {
        let cert = cli
            .tls_client_cert
            .ok_or("--tls-client-cert required when using client TLS")?;
        let key = cli
            .tls_client_key
            .ok_or("--tls-client-key required when using client TLS")?;
        // CA cert: try CLI flag, then wallet config, then server TLS config
        let ca = cli_ca_cert
            .or_else(|| config.wallet.tls.as_ref().map(|t| t.ca_cert_file.clone()))
            .or_else(|| server_tls.as_ref().map(|t| t.ca_cert_file.clone()))
            .ok_or("--tls-ca-cert required for wallet TLS")?;
        Some(WalletTlsConfig {
            client_cert_file: cert,
            client_key_file: key,
            ca_cert_file: ca,
        })
    } else {
        config.wallet.tls.clone()
    };

    // Build NAT config: CLI flags override config file
    let nat_config = NatConfig {
        external_addr: cli.external_addr.or(config.node.nat.external_addr.clone()),
        upnp: if cli.no_upnp {
            false
        } else {
            config.node.nat.upnp
        },
    };

    match cli.command {
        // Default (no subcommand) → run node with config file defaults
        None => {
            let listen_addr: SocketAddr =
                format!("{}:{}", config.node.p2p_host, config.node.p2p_port).parse()?;
            let peers = if config.node.bootstrap_peers.is_empty() {
                vec![]
            } else {
                config.parse_bootstrap_peers()
            };
            run_node(
                cli.data_dir,
                rpc_addr,
                listen_addr,
                peers,
                config.node.genesis_validator,
                server_tls,
                nat_config,
            )
            .await
        }

        Some(Command::Node {
            host,
            port,
            peers,
            genesis_validator,
        }) => {
            // CLI flags override config file
            let listen_addr: SocketAddr = format!("{}:{}", host, port).parse()?;
            let all_peers = if peers.is_empty() {
                config.parse_bootstrap_peers()
            } else {
                peers
            };
            run_node(
                cli.data_dir,
                rpc_addr,
                listen_addr,
                all_peers,
                genesis_validator,
                server_tls,
                nat_config,
            )
            .await
        }

        Some(Command::Wallet { action }) => {
            run_wallet_command(action, &cli.data_dir, rpc_addr, wallet_tls).await
        }
    }
}

async fn run_node(
    data_dir: PathBuf,
    rpc_addr: SocketAddr,
    listen_addr: SocketAddr,
    peers: Vec<SocketAddr>,
    genesis_validator: bool,
    tls_config: Option<TlsConfig>,
    nat_config: NatConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!(p2p = %listen_addr, rpc = %rpc_addr, data = %data_dir.display(), "Starting Umbra node...");

    // Safety check: refuse to expose RPC on non-loopback without TLS
    let is_loopback = matches!(rpc_addr.ip(),
        std::net::IpAddr::V4(ip) if ip.is_loopback())
        || matches!(rpc_addr.ip(),
        std::net::IpAddr::V6(ip) if ip.is_loopback());
    if !is_loopback && tls_config.is_none() {
        return Err(
            "Refusing to start: RPC is bound to a non-loopback address without TLS. \
             Use --tls-cert, --tls-key, and --tls-ca-cert to enable mTLS, \
             or bind RPC to 127.0.0.1."
                .into(),
        );
    }

    // Load TLS if configured
    let loaded_tls = match &tls_config {
        Some(tls) => {
            tls.validate()
                .map_err(|e| format!("TLS config error: {}", e))?;
            let loaded =
                umbra::node::rpc::load_tls(tls).map_err(|e| -> Box<dyn std::error::Error> { e })?;
            tracing::info!(cert = %tls.cert_file.display(), "mTLS enabled for RPC");
            Some(loaded)
        }
        None => None,
    };

    let (keypair, kem_keypair) = umbra::node::load_or_generate_keypair(&data_dir)?;

    let config = umbra::node::NodeConfig {
        listen_addr,
        bootstrap_peers: peers,
        data_dir,
        rpc_addr,
        keypair,
        kem_keypair,
        genesis_validator,
        nat_config,
    };

    let rpc_addr = config.rpc_addr;
    let mut node = umbra::node::Node::new(config).await?;

    let rpc_state = umbra::node::rpc::RpcState::new(node.state(), node.p2p_handle());
    tokio::spawn(umbra::node::rpc::serve(rpc_addr, rpc_state, loaded_tls));

    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Ctrl-C received, shutting down...");
        shutdown_signal.cancel();
    });
    node.run(shutdown).await;
    Ok(())
}

async fn run_wallet_command(
    action: WalletAction,
    data_dir: &std::path::Path,
    rpc_addr: SocketAddr,
    wallet_tls: Option<WalletTlsConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    use umbra::wallet::cli as wallet_cli;

    let tls_ref = wallet_tls.as_ref();

    match action {
        WalletAction::Init => wallet_cli::cmd_init_with_recovery(data_dir),
        WalletAction::Address => wallet_cli::cmd_address(data_dir),
        WalletAction::Balance => wallet_cli::cmd_balance(data_dir, rpc_addr, tls_ref).await,
        WalletAction::Scan => wallet_cli::cmd_scan(data_dir, rpc_addr, tls_ref).await,
        WalletAction::Send {
            to,
            amount,
            message,
        } => wallet_cli::cmd_send(data_dir, rpc_addr, &to, amount, message, tls_ref).await,
        WalletAction::Messages => wallet_cli::cmd_messages(data_dir),
        WalletAction::History => wallet_cli::cmd_history(data_dir),
        WalletAction::Consolidate => wallet_cli::cmd_consolidate(data_dir, rpc_addr, tls_ref).await,
        WalletAction::Recover { phrase } => wallet_cli::cmd_recover(data_dir, &phrase),
        WalletAction::Export { file } => wallet_cli::cmd_export(data_dir, &file),
        WalletAction::Web { host, port } => {
            let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
            umbra::wallet::web::serve(addr, data_dir.to_path_buf(), rpc_addr, wallet_tls).await
        }
    }
}

/// Run the original protocol demonstration.
fn run_demo() {
    umbra::demo::run_demo();
}
