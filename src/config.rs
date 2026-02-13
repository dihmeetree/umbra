//! Configuration file support for the Spectra node.
//!
//! Loads optional `spectra.toml` from the data directory. CLI flags override
//! config file values. If no config file exists, defaults are used.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

/// Top-level configuration.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SpectraConfig {
    pub node: NodeConfig,
    pub wallet: WalletConfig,
}

/// Node configuration section.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    pub p2p_host: String,
    pub p2p_port: u16,
    pub rpc_host: String,
    pub rpc_port: u16,
    pub data_dir: String,
    pub bootstrap_peers: Vec<String>,
    pub genesis_validator: bool,
    pub max_peers: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            p2p_host: "0.0.0.0".into(),
            p2p_port: crate::constants::DEFAULT_P2P_PORT,
            rpc_host: "127.0.0.1".into(),
            rpc_port: crate::constants::DEFAULT_RPC_PORT,
            data_dir: "./spectra-data".into(),
            bootstrap_peers: vec![],
            genesis_validator: false,
            max_peers: crate::constants::MAX_PEERS,
        }
    }
}

/// Wallet configuration section.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct WalletConfig {
    pub web_host: String,
    pub web_port: u16,
}

impl Default for WalletConfig {
    fn default() -> Self {
        WalletConfig {
            web_host: "127.0.0.1".into(),
            web_port: 9734,
        }
    }
}

impl SpectraConfig {
    /// Load configuration from `spectra.toml` in the given directory.
    /// Returns `Default` if the file doesn't exist.
    pub fn load(data_dir: &Path) -> Self {
        let config_path = data_dir.join("spectra.toml");
        match std::fs::read_to_string(&config_path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(config) => {
                    tracing::info!("Loaded config from {}", config_path.display());
                    config
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse {}: {}, using defaults",
                        config_path.display(),
                        e
                    );
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Parse bootstrap peers into socket addresses.
    pub fn parse_bootstrap_peers(&self) -> Vec<SocketAddr> {
        self.node
            .bootstrap_peers
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_valid() {
        let config = SpectraConfig::default();
        assert_eq!(config.node.p2p_port, crate::constants::DEFAULT_P2P_PORT);
        assert_eq!(config.node.rpc_port, crate::constants::DEFAULT_RPC_PORT);
        assert!(!config.node.genesis_validator);
    }

    #[test]
    fn parse_toml_config() {
        let toml_str = r#"
[node]
p2p_port = 9999
rpc_host = "0.0.0.0"
bootstrap_peers = ["1.2.3.4:9732", "5.6.7.8:9732"]

[wallet]
web_port = 8080
"#;
        let config: SpectraConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.node.p2p_port, 9999);
        assert_eq!(config.node.rpc_host, "0.0.0.0");
        assert_eq!(config.node.bootstrap_peers.len(), 2);
        assert_eq!(config.wallet.web_port, 8080);
    }

    #[test]
    fn missing_config_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let config = SpectraConfig::load(dir.path());
        assert_eq!(config.node.p2p_port, crate::constants::DEFAULT_P2P_PORT);
    }

    #[test]
    fn parse_bootstrap_peers() {
        let mut config = SpectraConfig::default();
        config.node.bootstrap_peers = vec!["1.2.3.4:9732".into(), "bad-addr".into()];
        let peers = config.parse_bootstrap_peers();
        assert_eq!(peers.len(), 1);
    }
}
