use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use tracing::info;

use crate::config;
use crate::crypto::certs;

const SERVICE_TYPE: &str = "_secure-transfer._tcp.local.";

/// Advertise this device on the local network via mDNS
///
/// Registers a service with hostname, port, and certificate fingerprint
/// so that senders can discover and verify this receiver.
/// Uses the configured device name if set, otherwise falls back to system hostname.
pub fn advertise(port: u16) -> Result<ServiceDaemon> {
    let mdns = ServiceDaemon::new().context("Failed to create mDNS daemon")?;

    // Use configured device name, falling back to system hostname
    let display_name = config::AppConfig::load()
        .map(|c| c.effective_device_name())
        .unwrap_or_else(|_| {
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        });

    let system_hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let fingerprint = certs::local_fingerprint()?;

    let instance_name = format!("{}-{}", display_name, port);

    let properties = [
        ("hostname", display_name.as_str()),
        ("fingerprint", fingerprint.as_str()),
        ("version", env!("CARGO_PKG_VERSION")),
    ];

    let service_info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance_name,
        &format!("{}.local.", system_hostname),
        "",
        port,
        &properties[..],
    )
    .context("Failed to create mDNS service info")?
    // Let mdns-sd populate the active interface addresses for this host.
    .enable_addr_auto();

    mdns.register(service_info)
        .context("Failed to register mDNS service")?;

    info!(
        "📡 Advertising as '{}' on port {} (fingerprint: {}…)",
        display_name,
        port,
        &fingerprint[..12]
    );

    Ok(mdns)
}

/// Unregister and shut down the mDNS daemon
pub fn stop(mdns: ServiceDaemon) {
    if let Err(e) = mdns.shutdown() {
        tracing::warn!("Failed to gracefully shutdown mDNS: {:?}", e);
    }
}
