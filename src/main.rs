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

            let addr: SocketAddr = if let Some(ref target) = to {
                target
                    .parse()
                    .map_err(|_| {
                        anyhow::anyhow!("Invalid address '{}'. Use format: ip:port", target)
                    })?
            } else {
                let scan_sp = ui::show_scanning_spinner();
                let devices = discovery::browse::browse_devices(None)?;
                ui::finish_spinner_success(&scan_sp, &format!("Found {} device(s)", devices.len()));

                let selected = ui::select_device(&devices);
                match selected {
                    Some(idx) => {
                        let device = &devices[idx];
                        SocketAddr::new(device.ip, device.port)
                    }
                    None => {
                        info!("No device selected, exiting.");
                        return Ok(());
                    }
                }
            };

            transfer::sender::send_files(&paths, addr).await
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

            let addr: SocketAddr = if let Some(ref target) = from {
                target
                    .parse()
                    .map_err(|_| {
                        anyhow::anyhow!("Invalid address '{}'. Use format: ip:port", target)
                    })?
            } else {
                let scan_sp = ui::show_scanning_spinner();
                let devices = discovery::browse::browse_devices(None)?;
                ui::finish_spinner_success(&scan_sp, &format!("Found {} device(s)", devices.len()));

                let selected = ui::select_device(&devices);
                match selected {
                    Some(idx) => {
                        let device = &devices[idx];
                        SocketAddr::new(device.ip, device.port)
                    }
                    None => {
                        info!("No device selected, exiting.");
                        return Ok(());
                    }
                }
            };

            transfer::downloader::download_files(addr, remote_path, save_dir).await
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
                    if cfg.remove_trusted_peer(&identifier)? {
                        println!("  [ok] Device '{}' has been revoked", identifier);
                    } else {
                        println!("  [err] No device found matching '{}'", identifier);
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
