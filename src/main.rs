mod cli;
mod config;
mod crypto;
mod discovery;
mod history;
mod transfer;
mod ui;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use tracing::info;

use cli::{Cli, Commands, ConfigAction, DevicesAction};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install rustls crypto provider"))?;

    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        "secure_transfer=debug"
    } else {
        "secure_transfer=info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Ensure TLS certificates exist
    crypto::certs::ensure_certs()?;

    match cli.command {
        Commands::Listen {
            port,
            save_dir,
            share,
            unrestricted,
        } => {
            let save_dir = save_dir
                .or_else(|| {
                    config::AppConfig::load()
                        .ok()
                        .map(|c| c.default_save_dir)
                })
                .unwrap_or_else(|| std::path::PathBuf::from("./received"));

            // Start mDNS advertisement
            let mdns = discovery::advertise::advertise(port)?;

            // Start listening for transfers and browse requests
            let result = transfer::receiver::listen(port, save_dir, share, unrestricted).await;

            // Clean up mDNS on exit
            discovery::advertise::stop(mdns);

            result
        }

        Commands::Send { paths, to } => {
            // Validate all paths exist
            for path in &paths {
                if !path.exists() {
                    anyhow::bail!("Path does not exist: {}", path.display());
                }
            }

            let (addr, expected_fingerprint, peer_name) = if let Some(ref target) = to {
                let addr: SocketAddr = target
                    .parse()
                    .map_err(|_| {
                        anyhow::anyhow!("Invalid address '{}'. Use format: ip:port", target)
                    })?;
                // Manual address — no mDNS fingerprint; TOFU prompt handled in send_files
                (addr, None, None)
            } else {
                let scan_sp = ui::show_scanning_spinner();
                let devices = discovery::browse::browse_devices(None)?;
                ui::finish_spinner_success(&scan_sp, &format!("Found {} device(s)", devices.len()));

                let selected = ui::select_device(&devices);
                match selected {
                    Some(idx) => {
                        let device = &devices[idx];
                        let fp = if device.fingerprint.is_empty() { None } else { Some(device.fingerprint.clone()) };
                        (SocketAddr::new(device.ip, device.port), fp, Some(device.hostname.clone()))
                    }
                    None => {
                        info!("No device selected, exiting.");
                        return Ok(());
                    }
                }
            };

            transfer::sender::send_files(&paths, addr, expected_fingerprint, peer_name).await
        }

        Commands::Download {
            from,
            remote_path,
            save_dir,
        } => {
            let save_dir = save_dir
                .or_else(|| {
                    config::AppConfig::load()
                        .ok()
                        .map(|c| c.default_save_dir)
                })
                .unwrap_or_else(|| std::path::PathBuf::from("./downloaded"));

            let (addr, expected_fingerprint, peer_name) = if let Some(ref target) = from {
                let addr: SocketAddr = target
                    .parse()
                    .map_err(|_| {
                        anyhow::anyhow!("Invalid address '{}'. Use format: ip:port", target)
                    })?;
                // Manual address — no mDNS fingerprint; TOFU prompt handled in download_files
                (addr, None, None)
            } else {
                let scan_sp = ui::show_scanning_spinner();
                let devices = discovery::browse::browse_devices(None)?;
                ui::finish_spinner_success(&scan_sp, &format!("Found {} device(s)", devices.len()));

                let selected = ui::select_device(&devices);
                match selected {
                    Some(idx) => {
                        let device = &devices[idx];
                        let fp = if device.fingerprint.is_empty() { None } else { Some(device.fingerprint.clone()) };
                        (SocketAddr::new(device.ip, device.port), fp, Some(device.hostname.clone()))
                    }
                    None => {
                        info!("No device selected, exiting.");
                        return Ok(());
                    }
                }
            };

            transfer::downloader::download_files(addr, remote_path, save_dir, expected_fingerprint, peer_name).await
        }

        Commands::Config { action } => {
            match action {
                ConfigAction::SetName { name } => {
                    let mut cfg = config::AppConfig::load()?;
                    cfg.device_name = Some(name.clone());
                    cfg.save()?;
                    println!("  [ok] Device name set to: {}", name);
                }
                ConfigAction::Show => {
                    let cfg = config::AppConfig::load()?;
                    let fp = crypto::certs::local_fingerprint()?;
                    println!();
                    println!("  +--------------------------------------------------+");
                    println!("  |  Device Configuration                             |");
                    println!("  |--------------------------------------------------|");
                    println!("  |  Name:        {:<36} |", cfg.effective_device_name());
                    println!("  |  Fingerprint: {}...  |", &fp[..36]);
                    println!("  |  Port:        {:<36} |", cfg.default_port);
                    println!("  |  Save Dir:    {:<36} |", cfg.default_save_dir.display());
                    println!("  |  Peers:       {:<36} |", format!("{} trusted device(s)", cfg.trusted_peers.len()));
                    println!("  +--------------------------------------------------+");
                    println!();
                }
            }
            Ok(())
        }

        Commands::Devices { action } => {
            match action {
                DevicesAction::List => {
                    let cfg = config::AppConfig::load()?;
                    let peers: Vec<(String, config::TrustedPeer)> = cfg
                        .trusted_peers
                        .into_iter()
                        .collect();
                    ui::print_trusted_devices(&peers);
                }
                DevicesAction::Revoke { identifier } => {
                    let mut cfg = config::AppConfig::load()?;
                    if let Some(identifier) = identifier {
                        if identifier.eq_ignore_ascii_case("all") {
                            let removed = cfg.clear_trusted_peers()?;
                            println!("  [ok] Revoked access for {} device(s)", removed);
                        } else if cfg.remove_trusted_peer(&identifier)? {
                            println!("  [ok] Device '{}' has been revoked", identifier);
                        } else {
                            println!("  [err] No device found matching '{}'", identifier);
                        }
                    } else {
                        let peers: Vec<(String, config::TrustedPeer)> = cfg
                            .trusted_peers
                            .iter()
                            .map(|(fp, peer)| (fp.clone(), peer.clone()))
                            .collect();

                        ui::print_trusted_devices(&peers);

                        match ui::select_device_to_revoke(&peers)? {
                            ui::RevokeSelection::Device(fingerprint) => {
                                if cfg.remove_trusted_peer(&fingerprint)? {
                                    println!("  [ok] Device access revoked");
                                }
                            }
                            ui::RevokeSelection::All => {
                                let removed = cfg.clear_trusted_peers()?;
                                println!("  [ok] Revoked access for {} device(s)", removed);
                            }
                            ui::RevokeSelection::Cancel => {
                                info!("No device selected for revocation, exiting.");
                            }
                        }
                    }
                }
            }
            Ok(())
        }

        Commands::History { limit } => {
            let records = history::load_records()?;
            ui::print_history(&records, limit);
            Ok(())
        }
    }
}
