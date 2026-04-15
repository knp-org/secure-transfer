pub mod advertise;
pub mod browse;

use std::net::IpAddr;

/// Represents a device discovered on the local network
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub hostname: String,
    pub ip: IpAddr,
    pub port: u16,
    pub fingerprint: String,
}

impl std::fmt::Display for DiscoveredDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}:{}) [{}…]",
            self.hostname,
            self.ip,
            self.port,
            &self.fingerprint[..8]
        )
    }
}
