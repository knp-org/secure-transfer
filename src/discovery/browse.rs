use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::time::Duration;
use tracing::{debug, info};

use super::DiscoveredDevice;

const SERVICE_TYPE: &str = "_secure-transfer._tcp.local.";
const BROWSE_TIMEOUT: Duration = Duration::from_secs(3);

/// Browse the local network for devices running secure-transfer
///
/// Scans for mDNS services for the specified duration and returns
/// a list of discovered devices with their connection details.
pub fn browse_devices(timeout: Option<Duration>) -> Result<Vec<DiscoveredDevice>> {
    let timeout = timeout.unwrap_or(BROWSE_TIMEOUT);
    let mdns = ServiceDaemon::new().context("Failed to create mDNS browser")?;

    let receiver = mdns
        .browse(SERVICE_TYPE)
        .context("Failed to start mDNS browsing")?;

    let mut devices = Vec::new();

    info!("🔍 Scanning for devices ({:.0}s)…", timeout.as_secs_f64());

    let deadline = std::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let hostname = info
                    .get_property_val_str("hostname")
                    .unwrap_or("unknown")
                    .to_string();

                let fingerprint = info
                    .get_property_val_str("fingerprint")
                    .unwrap_or("")
                    .to_string();

                let port = info.get_port();

                // Get the first available IP address
                if let Some(ip) = info.get_addresses().iter().next() {
                    let device = DiscoveredDevice {
                        hostname,
                        ip: *ip,
                        port,
                        fingerprint,
                    };

                    debug!("Found device: {}", device);
                    devices.push(device);
                }
            }
            Ok(ServiceEvent::SearchStarted(_)) => {
                debug!("mDNS search started");
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    // Clean up
    mdns.stop_browse(SERVICE_TYPE).ok();
    mdns.shutdown().ok();

    info!("Found {} device(s)", devices.len());
    Ok(devices)
}
