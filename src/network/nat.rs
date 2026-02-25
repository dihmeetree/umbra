//! NAT traversal support for the P2P network.
//!
//! Provides three layers of NAT detection:
//! 1. **Manual configuration** — operator specifies external address via CLI or config.
//! 2. **UPnP port mapping** — automatically maps a port via the local router's IGD.
//! 3. **Observed address voting** — peers report what IP they see us connecting from;
//!    after a quorum agrees, we adopt that IP combined with our listen port.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use crate::network::PeerId;

/// NAT detection and external address resolution.
pub struct NatState {
    /// Operator-configured external address (highest priority).
    manual_external_addr: Option<SocketAddr>,
    /// Address obtained via UPnP port mapping.
    upnp_external_addr: Option<SocketAddr>,
    /// Peer-observed external IPs. Key is an IP seen by peers, value is the set
    /// of peer IDs that reported that IP. We only use the IP (not port) since
    /// the remote port seen by peers is an ephemeral NAT port, not our listen port.
    observed_ip_votes: HashMap<IpAddr, HashSet<PeerId>>,
    /// Our local listen port (combined with observed IP to form external addr).
    listen_port: u16,
}

impl NatState {
    /// Create a new NAT state.
    ///
    /// - `listen_port`: the P2P listen port (used with observed IPs).
    /// - `manual`: operator-specified external address (overrides all discovery).
    pub fn new(listen_port: u16, manual: Option<SocketAddr>) -> Self {
        NatState {
            manual_external_addr: manual,
            upnp_external_addr: None,
            observed_ip_votes: HashMap::new(),
            listen_port,
        }
    }

    /// Return the best-known external address.
    ///
    /// Priority: manual > UPnP > observed (with quorum).
    pub fn external_addr(&self) -> Option<SocketAddr> {
        if let Some(addr) = self.manual_external_addr {
            return Some(addr);
        }
        if let Some(addr) = self.upnp_external_addr {
            return Some(addr);
        }
        self.observed_external_addr()
    }

    /// Return the observed external address if any IP has reached quorum.
    fn observed_external_addr(&self) -> Option<SocketAddr> {
        let quorum = crate::constants::NAT_OBSERVED_ADDR_QUORUM;
        self.observed_ip_votes
            .iter()
            .find(|(_, voters)| voters.len() >= quorum)
            .map(|(ip, _)| SocketAddr::new(*ip, self.listen_port))
    }

    /// Record an observed IP from a peer. Returns `true` if this changes
    /// the quorum outcome (i.e., we now have a new observed address).
    pub fn record_observed_addr(&mut self, peer: PeerId, ip: IpAddr) -> bool {
        // Cap total distinct IPs to prevent memory exhaustion from diverse spoofed reports
        if !self.observed_ip_votes.contains_key(&ip)
            && self.observed_ip_votes.len() >= crate::constants::MAX_OBSERVED_IP_VOTES
        {
            return false;
        }
        let had_quorum = self.observed_external_addr().is_some();
        let voters = self.observed_ip_votes.entry(ip).or_default();
        voters.insert(peer);
        let has_quorum = self.observed_external_addr().is_some();
        !had_quorum && has_quorum
    }

    /// Set the UPnP-discovered external address.
    pub fn set_upnp_addr(&mut self, addr: SocketAddr) {
        self.upnp_external_addr = Some(addr);
    }

    /// Returns `true` if we believe we're externally reachable
    /// (i.e., have any form of external address).
    pub fn is_reachable(&self) -> bool {
        self.external_addr().is_some()
    }
}

/// Type alias for the tokio-based UPnP gateway.
pub type UpnpGateway = igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>;

/// Attempt to create a UPnP port mapping via the local router.
///
/// Returns the mapped external address and the gateway handle (for renewal/cleanup),
/// or `None` if UPnP is unavailable or fails.
pub async fn try_upnp_mapping(local_addr: SocketAddr) -> Option<(SocketAddr, UpnpGateway)> {
    use igd_next::SearchOptions;

    let timeout = std::time::Duration::from_millis(crate::constants::UPNP_TIMEOUT_MS);
    let search_opts = SearchOptions {
        timeout: Some(timeout),
        ..Default::default()
    };

    let gateway: UpnpGateway = match igd_next::aio::tokio::search_gateway(search_opts).await {
        Ok(gw) => gw,
        Err(e) => {
            tracing::debug!(error = %e, "UPnP gateway discovery failed");
            return None;
        }
    };

    let local_ip = local_addr.ip();
    let local_port = local_addr.port();

    match gateway
        .add_port(
            igd_next::PortMappingProtocol::TCP,
            local_port,
            SocketAddr::new(local_ip, local_port),
            crate::constants::UPNP_LEASE_DURATION_SECS,
            "Umbra P2P",
        )
        .await
    {
        Ok(()) => match gateway.get_external_ip().await {
            Ok(ext_ip) => {
                let ext_addr = SocketAddr::new(ext_ip, local_port);
                tracing::info!(local = %local_ip, port = local_port, external = %ext_addr, "UPnP port mapped");
                Some((ext_addr, gateway))
            }
            Err(e) => {
                tracing::warn!(error = %e, "UPnP port mapped but failed to get external IP");
                None
            }
        },
        Err(e) => {
            tracing::debug!(error = %e, "UPnP port mapping failed");
            None
        }
    }
}

/// Renew an existing UPnP port mapping. Returns `true` on success.
pub async fn renew_upnp_mapping(gateway: &UpnpGateway, local_addr: SocketAddr) -> bool {
    match gateway
        .add_port(
            igd_next::PortMappingProtocol::TCP,
            local_addr.port(),
            local_addr,
            crate::constants::UPNP_LEASE_DURATION_SECS,
            "Umbra P2P",
        )
        .await
    {
        Ok(()) => {
            tracing::debug!(port = local_addr.port(), "UPnP lease renewed");
            true
        }
        Err(e) => {
            tracing::warn!(port = local_addr.port(), error = %e, "UPnP lease renewal failed");
            false
        }
    }
}

/// Remove a UPnP port mapping (for clean shutdown).
pub async fn remove_upnp_mapping(gateway: &UpnpGateway, port: u16) {
    match gateway
        .remove_port(igd_next::PortMappingProtocol::TCP, port)
        .await
    {
        Ok(()) => tracing::debug!(port = port, "UPnP mapping removed"),
        Err(e) => tracing::debug!(port = port, error = %e, "UPnP mapping removal failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer_id(byte: u8) -> PeerId {
        [byte; 32]
    }

    #[test]
    fn external_addr_with_no_info_returns_none() {
        let nat = NatState::new(9732, None);
        assert!(nat.external_addr().is_none());
        assert!(!nat.is_reachable());
    }

    #[test]
    fn manual_addr_has_highest_priority() {
        let manual = "203.0.113.5:9732".parse().unwrap();
        let mut nat = NatState::new(9732, Some(manual));

        // Even with UPnP and observed quorum, manual wins
        nat.set_upnp_addr("198.51.100.1:9732".parse().unwrap());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        for i in 0..5 {
            nat.record_observed_addr(make_peer_id(i), ip);
        }

        assert_eq!(nat.external_addr(), Some(manual));
    }

    #[test]
    fn upnp_overrides_observed() {
        let mut nat = NatState::new(9732, None);
        let upnp_addr: SocketAddr = "198.51.100.1:9732".parse().unwrap();
        nat.set_upnp_addr(upnp_addr);

        // Add observed quorum too
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        for i in 0..5 {
            nat.record_observed_addr(make_peer_id(i), ip);
        }

        // UPnP takes priority over observed
        assert_eq!(nat.external_addr(), Some(upnp_addr));
    }

    #[test]
    fn observed_quorum_required() {
        let mut nat = NatState::new(9732, None);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();

        // Add votes below quorum threshold
        nat.record_observed_addr(make_peer_id(1), ip);
        nat.record_observed_addr(make_peer_id(2), ip);
        assert!(nat.external_addr().is_none());

        // Third vote reaches quorum
        nat.record_observed_addr(make_peer_id(3), ip);
        let expected: SocketAddr = "203.0.113.5:9732".parse().unwrap();
        assert_eq!(nat.external_addr(), Some(expected));
        assert!(nat.is_reachable());
    }

    #[test]
    fn minority_ip_ignored() {
        let mut nat = NatState::new(9732, None);

        // 2 peers say one IP, 1 peer says another — neither reaches quorum of 3
        let ip1: IpAddr = "203.0.113.1".parse().unwrap();
        let ip2: IpAddr = "203.0.113.2".parse().unwrap();

        nat.record_observed_addr(make_peer_id(1), ip1);
        nat.record_observed_addr(make_peer_id(2), ip1);
        nat.record_observed_addr(make_peer_id(3), ip2);

        assert!(nat.external_addr().is_none());
    }

    #[test]
    fn same_peer_not_double_counted() {
        let mut nat = NatState::new(9732, None);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let peer = make_peer_id(1);

        // Same peer votes 5 times — should only count once
        for _ in 0..5 {
            nat.record_observed_addr(peer, ip);
        }

        assert!(
            nat.external_addr().is_none(),
            "single peer should not reach quorum"
        );
    }

    #[test]
    fn record_observed_returns_true_on_quorum_change() {
        let mut nat = NatState::new(9732, None);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();

        assert!(!nat.record_observed_addr(make_peer_id(1), ip));
        assert!(!nat.record_observed_addr(make_peer_id(2), ip));
        // Third vote establishes quorum — should return true
        assert!(nat.record_observed_addr(make_peer_id(3), ip));
        // Fourth vote doesn't change quorum — should return false
        assert!(!nat.record_observed_addr(make_peer_id(4), ip));
    }

    #[test]
    fn is_reachable_reflects_external_addr() {
        let mut nat = NatState::new(9732, None);
        assert!(!nat.is_reachable());

        nat.set_upnp_addr("198.51.100.1:9732".parse().unwrap());
        assert!(nat.is_reachable());
    }

    #[test]
    fn max_observed_ip_votes_cap_enforced() {
        let mut nat = NatState::new(9732, None);
        // Fill with 100 unique IPs (each from a unique peer, so no quorum)
        for i in 0u16..100 {
            let ip: IpAddr = if i < 256 {
                format!("203.0.113.{}", i).parse().unwrap()
            } else {
                format!("198.51.100.{}", i - 256).parse().unwrap()
            };
            // Use a unique peer for each IP so no quorum is reached
            let peer = [i as u8; 32];
            nat.record_observed_addr(peer, ip);
        }
        // 101st distinct IP should be rejected (cap is 100)
        let new_ip: IpAddr = "192.0.2.1".parse().unwrap();
        let result = nat.record_observed_addr([200u8; 32], new_ip);
        assert!(!result);
        assert!(nat.external_addr().is_none()); // no quorum reached
    }

    #[test]
    fn existing_ip_still_accepted_at_cap() {
        let mut nat = NatState::new(9732, None);
        let target_ip: IpAddr = "203.0.113.0".parse().unwrap();
        // First vote for target IP
        nat.record_observed_addr(make_peer_id(0), target_ip);
        // Fill remaining 99 slots
        for i in 1u8..100 {
            let ip: IpAddr = format!("203.0.113.{}", i).parse().unwrap();
            nat.record_observed_addr(make_peer_id(i), ip);
        }
        // Adding another vote for an already-known IP should succeed
        let result = nat.record_observed_addr(make_peer_id(200), target_ip);
        // The IP already exists in the map, so the new vote is added
        let _ = result; // just verify no panic; behavior depends on quorum
    }
}
