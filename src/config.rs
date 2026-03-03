//! Configuration file support for the Umbra node.
//!
//! Loads optional `umbra.toml` from the data directory. CLI flags override
//! config file values. If no config file exists, defaults are used.

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

/// Top-level configuration.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct UmbraConfig {
    pub node: NodeConfig,
    pub wallet: WalletConfig,
}

/// Node configuration section.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    pub network: String,
    pub p2p_host: String,
    pub p2p_port: u16,
    pub rpc_host: String,
    pub rpc_port: u16,
    pub data_dir: String,
    pub bootstrap_peers: Vec<String>,
    pub genesis_validator: bool,
    pub max_peers: usize,
    pub tls: Option<TlsConfig>,
    pub nat: NatConfig,
}

/// NAT traversal configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct NatConfig {
    /// Manually specified external address (IP:port) for nodes behind NAT.
    pub external_addr: Option<String>,
    /// Enable UPnP port mapping (default: true).
    pub upnp: bool,
}

/// Server-side TLS configuration for mTLS on the RPC endpoint.
#[derive(Clone, Debug, Deserialize)]
pub struct TlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub ca_cert_file: PathBuf,
}

impl TlsConfig {
    /// Check that all referenced files exist.
    pub fn validate(&self) -> Result<(), String> {
        if !self.cert_file.exists() {
            return Err(format!(
                "TLS cert file not found: {}",
                self.cert_file.display()
            ));
        }
        if !self.key_file.exists() {
            return Err(format!(
                "TLS key file not found: {}",
                self.key_file.display()
            ));
        }
        if !self.ca_cert_file.exists() {
            return Err(format!(
                "TLS CA cert file not found: {}",
                self.ca_cert_file.display()
            ));
        }
        Ok(())
    }
}

impl Default for NatConfig {
    fn default() -> Self {
        NatConfig {
            external_addr: None,
            upnp: true,
        }
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            network: "mainnet".into(),
            p2p_host: "0.0.0.0".into(),
            p2p_port: crate::constants::DEFAULT_P2P_PORT,
            rpc_host: "127.0.0.1".into(),
            rpc_port: crate::constants::DEFAULT_RPC_PORT,
            data_dir: "./umbra-data".into(),
            bootstrap_peers: vec![],
            genesis_validator: false,
            max_peers: crate::constants::MAX_PEERS,
            tls: None,
            nat: NatConfig::default(),
        }
    }
}

/// Return default bootstrap peers for the given network.
pub fn default_bootstrap_peers(network: crate::constants::NetworkId) -> Vec<String> {
    match network {
        crate::constants::NetworkId::Mainnet => vec![],
        crate::constants::NetworkId::Testnet => vec![
            "testnet-1.umbra.network:9742".into(),
            "testnet-2.umbra.network:9742".into(),
            "testnet-3.umbra.network:9742".into(),
        ],
    }
}

impl NodeConfig {
    /// Returns true if the RPC host is a loopback address.
    pub fn rpc_is_loopback(&self) -> bool {
        matches!(
            self.rpc_host.as_str(),
            "127.0.0.1" | "::1" | "[::1]" | "localhost"
        )
    }
}

/// Wallet configuration section.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct WalletConfig {
    pub web_host: String,
    pub web_port: u16,
    pub tls: Option<WalletTlsConfig>,
}

/// Client-side TLS configuration for mTLS wallet connections to the RPC.
#[derive(Clone, Debug, Deserialize)]
pub struct WalletTlsConfig {
    pub client_cert_file: PathBuf,
    pub client_key_file: PathBuf,
    pub ca_cert_file: PathBuf,
}

impl WalletTlsConfig {
    /// Check that all referenced files exist.
    pub fn validate(&self) -> Result<(), String> {
        if !self.client_cert_file.exists() {
            return Err(format!(
                "TLS client cert not found: {}",
                self.client_cert_file.display()
            ));
        }
        if !self.client_key_file.exists() {
            return Err(format!(
                "TLS client key not found: {}",
                self.client_key_file.display()
            ));
        }
        if !self.ca_cert_file.exists() {
            return Err(format!(
                "TLS CA cert not found: {}",
                self.ca_cert_file.display()
            ));
        }
        Ok(())
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        WalletConfig {
            web_host: "127.0.0.1".into(),
            web_port: 9734,
            tls: None,
        }
    }
}

impl UmbraConfig {
    /// Load configuration from `umbra.toml` in the given directory.
    /// Returns `Default` if the file doesn't exist.
    pub fn load(data_dir: &Path) -> Self {
        let config_path = data_dir.join("umbra.toml");
        match std::fs::read_to_string(&config_path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(config) => {
                    tracing::info!(path = %config_path.display(), "Loaded config");
                    config
                }
                Err(e) => {
                    tracing::error!(
                        path = %config_path.display(),
                        error = %e,
                        "Failed to parse config, running with defaults"
                    );
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }
}

/// Resolve peer strings (host:port or ip:port) to socket addresses.
/// Supports DNS hostnames via `ToSocketAddrs`.
pub fn resolve_peers(peers: &[String]) -> Vec<SocketAddr> {
    use std::net::ToSocketAddrs;
    peers
        .iter()
        .filter_map(|s| match s.to_socket_addrs() {
            Ok(mut addrs) => addrs.next(),
            Err(e) => {
                tracing::warn!(peer = %s, error = %e, "Failed to resolve peer address");
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_valid() {
        let config = UmbraConfig::default();
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
        let config: UmbraConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.node.p2p_port, 9999);
        assert_eq!(config.node.rpc_host, "0.0.0.0");
        assert_eq!(config.node.bootstrap_peers.len(), 2);
        assert_eq!(config.wallet.web_port, 8080);
    }

    #[test]
    fn missing_config_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let config = UmbraConfig::load(dir.path());
        assert_eq!(config.node.p2p_port, crate::constants::DEFAULT_P2P_PORT);
    }

    #[test]
    fn resolve_bootstrap_peers() {
        let mut config = UmbraConfig::default();
        config.node.bootstrap_peers = vec!["1.2.3.4:9732".into(), "bad-addr".into()];
        let peers = resolve_peers(&config.node.bootstrap_peers);
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn rpc_is_loopback() {
        let mut config = NodeConfig::default();
        assert!(config.rpc_is_loopback()); // 127.0.0.1

        config.rpc_host = "::1".into();
        assert!(config.rpc_is_loopback());

        config.rpc_host = "localhost".into();
        assert!(config.rpc_is_loopback());

        config.rpc_host = "0.0.0.0".into();
        assert!(!config.rpc_is_loopback());

        config.rpc_host = "192.168.1.1".into();
        assert!(!config.rpc_is_loopback());
    }

    #[test]
    fn parse_toml_with_tls() {
        let toml_str = r#"
[node]
rpc_host = "0.0.0.0"

[node.tls]
cert_file = "./tls/server.crt"
key_file = "./tls/server.key"
ca_cert_file = "./tls/ca.crt"

[wallet.tls]
client_cert_file = "./tls/client.crt"
client_key_file = "./tls/client.key"
ca_cert_file = "./tls/ca.crt"
"#;
        let config: UmbraConfig = toml::from_str(toml_str).unwrap();
        let tls = config.node.tls.unwrap();
        assert_eq!(tls.cert_file.to_str().unwrap(), "./tls/server.crt");
        assert_eq!(tls.key_file.to_str().unwrap(), "./tls/server.key");
        assert_eq!(tls.ca_cert_file.to_str().unwrap(), "./tls/ca.crt");

        let wallet_tls = config.wallet.tls.unwrap();
        assert_eq!(
            wallet_tls.client_cert_file.to_str().unwrap(),
            "./tls/client.crt"
        );
        assert_eq!(wallet_tls.ca_cert_file.to_str().unwrap(), "./tls/ca.crt");
    }

    #[test]
    fn parse_toml_without_tls() {
        let toml_str = r#"
[node]
rpc_host = "127.0.0.1"
"#;
        let config: UmbraConfig = toml::from_str(toml_str).unwrap();
        assert!(config.node.tls.is_none());
        assert!(config.wallet.tls.is_none());
    }

    #[test]
    fn tls_config_validate_missing_files() {
        let tls = TlsConfig {
            cert_file: PathBuf::from("/nonexistent/cert.pem"),
            key_file: PathBuf::from("/nonexistent/key.pem"),
            ca_cert_file: PathBuf::from("/nonexistent/ca.pem"),
        };
        let err = tls.validate().unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn parse_toml_with_nat() {
        let toml_str = r#"
[node]
p2p_port = 9732

[node.nat]
external_addr = "203.0.113.5:9732"
upnp = false
"#;
        let config: UmbraConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.node.nat.external_addr.as_deref(),
            Some("203.0.113.5:9732")
        );
        assert!(!config.node.nat.upnp);
    }

    #[test]
    fn parse_toml_without_nat() {
        let toml_str = r#"
[node]
p2p_port = 9732
"#;
        let config: UmbraConfig = toml::from_str(toml_str).unwrap();
        assert!(config.node.nat.external_addr.is_none());
        assert!(config.node.nat.upnp); // default true
    }

    #[test]
    fn default_nat_config() {
        let nat = NatConfig::default();
        assert!(nat.external_addr.is_none());
        assert!(nat.upnp);
    }

    #[test]
    fn wallet_tls_config_validate_missing_files() {
        let tls = WalletTlsConfig {
            client_cert_file: PathBuf::from("/nonexistent/client.pem"),
            client_key_file: PathBuf::from("/nonexistent/client-key.pem"),
            ca_cert_file: PathBuf::from("/nonexistent/ca.pem"),
        };
        let err = tls.validate().unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn malformed_toml_returns_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("umbra.toml");
        std::fs::write(&config_path, "this is not valid toml {{{{").unwrap();
        let config = UmbraConfig::load(dir.path());
        // Should fall back to defaults
        assert_eq!(config.node.p2p_port, crate::constants::DEFAULT_P2P_PORT);
    }

    #[test]
    fn empty_toml_returns_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("umbra.toml");
        std::fs::write(&config_path, "").unwrap();
        let config = UmbraConfig::load(dir.path());
        assert_eq!(config.node.p2p_port, crate::constants::DEFAULT_P2P_PORT);
        assert_eq!(config.node.rpc_port, crate::constants::DEFAULT_RPC_PORT);
    }

    #[test]
    fn ipv6_bootstrap_peer() {
        let mut config = UmbraConfig::default();
        config.node.bootstrap_peers = vec!["[::1]:9732".into()];
        let peers = resolve_peers(&config.node.bootstrap_peers);
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn parse_toml_unknown_fields_ignored() {
        let toml_str = r#"
[node]
p2p_port = 9999
unknown_field = "ignored"

[wallet]
web_port = 8080
"#;
        // serde(default) + deny_unknown_fields is NOT set, so unknowns are OK
        let result: Result<UmbraConfig, _> = toml::from_str(toml_str);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.node.p2p_port, 9999);
    }

    #[test]
    fn rpc_is_loopback_bracket_ipv6() {
        let config = NodeConfig {
            rpc_host: "[::1]".into(),
            ..NodeConfig::default()
        };
        assert!(config.rpc_is_loopback());
    }

    #[test]
    fn default_wallet_config() {
        let config = WalletConfig::default();
        assert_eq!(config.web_host, "127.0.0.1");
        assert_eq!(config.web_port, 9734);
        assert!(config.tls.is_none());
    }

    #[test]
    fn default_node_config_max_peers() {
        let config = NodeConfig::default();
        assert_eq!(config.max_peers, crate::constants::MAX_PEERS);
        assert!(config.tls.is_none());
        assert!(config.bootstrap_peers.is_empty());
    }

    #[test]
    fn parse_toml_with_network() {
        let toml_str = r#"
[node]
network = "testnet"
p2p_port = 9742
"#;
        let config: UmbraConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.node.network, "testnet");
        assert_eq!(config.node.p2p_port, 9742);
    }

    #[test]
    fn default_config_network_is_mainnet() {
        let config = NodeConfig::default();
        assert_eq!(config.network, "mainnet");
    }

    #[test]
    fn default_bootstrap_peers_testnet() {
        let peers = super::default_bootstrap_peers(crate::constants::NetworkId::Testnet);
        assert!(!peers.is_empty());
    }

    #[test]
    fn default_bootstrap_peers_mainnet_empty() {
        let peers = super::default_bootstrap_peers(crate::constants::NetworkId::Mainnet);
        assert!(peers.is_empty());
    }

    #[test]
    fn tls_validate_cert_exists_key_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, "fake cert").unwrap();
        let tls = super::TlsConfig {
            cert_file: cert_path,
            key_file: dir.path().join("missing_key.pem"),
            ca_cert_file: dir.path().join("ca.pem"),
        };
        let result = tls.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("key"));
    }

    #[test]
    fn tls_validate_cert_key_exist_ca_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, "fake cert").unwrap();
        std::fs::write(&key_path, "fake key").unwrap();
        let tls = super::TlsConfig {
            cert_file: cert_path,
            key_file: key_path,
            ca_cert_file: dir.path().join("missing_ca.pem"),
        };
        let result = tls.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("CA"));
    }

    #[test]
    fn resolve_bootstrap_peers_all_valid() {
        let config = super::UmbraConfig {
            node: super::NodeConfig {
                bootstrap_peers: vec!["127.0.0.1:9742".to_string(), "192.168.1.1:9742".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let peers = resolve_peers(&config.node.bootstrap_peers);
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn resolve_bootstrap_peers_empty_list() {
        let config = super::UmbraConfig {
            node: super::NodeConfig {
                bootstrap_peers: vec![],
                ..Default::default()
            },
            ..Default::default()
        };
        let peers = resolve_peers(&config.node.bootstrap_peers);
        assert!(peers.is_empty());
    }

    #[test]
    fn nat_config_partial_toml() {
        let toml_str = r#"
            [node.nat]
            upnp = true
        "#;
        let config: super::UmbraConfig = toml::from_str(toml_str).unwrap();
        assert!(config.node.nat.upnp);
        assert!(config.node.nat.external_addr.is_none());
    }
}
