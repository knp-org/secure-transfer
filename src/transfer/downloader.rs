use anyhow::{Context, Result};
use sha2::Digest;
use std::net::SocketAddr;
use std::path::{Component, PathBuf};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::config::{self, AccessDuration, AccessScope, TrustedPeer};
use crate::crypto::certs;
use crate::history::{self, TransactionRecord};
use crate::transfer::protocol::{
    self, Ack, AckStatus, BrowseRequest, BrowseResponse, CHUNK_SIZE, ConnectionRequest,
    DownloadRequest, FileHeader, RequestType, TransferManifest,
};
use crate::ui;

/// Browse files on a remote device and download selected ones.
///
/// `expected_fingerprint`: the receiver's certificate fingerprint from mDNS
/// discovery. `Some` → TLS enforces an exact match; `None` → TOFU prompt
/// after handshake for manual `--from` connections.
///
/// `peer_name`: display name used in UI prompts.
pub async fn download_files(
    addr: SocketAddr,
    remote_path: Option<String>,
    save_dir: PathBuf,
    expected_fingerprint: Option<String>,
    peer_name: Option<String>,
) -> Result<()> {
    // Ensure save directory exists
    tokio::fs::create_dir_all(&save_dir).await?;

    // Connect via TLS — enforce fingerprint when available from mDNS.
    let tls_config = certs::build_client_config(expected_fingerprint.clone())?;
    let connector = TlsConnector::from(tls_config);
    let tcp_stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("Failed to connect to {}", addr))?;

    let server_name = rustls::pki_types::ServerName::try_from("secure-transfer.local")
        .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;

    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .context("TLS handshake failed")?;

    info!("Quantum-safe TLS connection established to {}", addr);

    // TOFU for manual connections: verify and optionally persist the receiver's
    // fingerprint before we send any data.
    let verified_fingerprint: String = if expected_fingerprint.is_none() {
        let server_fp = {
            let (_, rustls_conn) = tls_stream.get_ref();
            rustls_conn
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert| certs::cert_fingerprint(cert.as_ref()))
        };

        // Fail closed: if we cannot extract the server certificate we must not
        // proceed — silently skipping would allow a connection with no trust anchor.
        let server_fp =
            server_fp.context("Could not extract server certificate after TLS handshake")?;

        let app_config = config::AppConfig::load().unwrap_or_default();
        if !app_config.is_trusted(&server_fp) {
            let addr_str = addr.to_string();
            let display_name = peer_name.as_deref().unwrap_or(&addr_str);
            if !ui::prompt_verify_fingerprint(&server_fp, display_name)? {
                anyhow::bail!("Connection aborted — receiver fingerprint rejected");
            }
            // Persist so the next connection is silent
            let mut cfg = config::AppConfig::load().unwrap_or_default();
            cfg.add_trusted_peer(
                server_fp.clone(),
                TrustedPeer {
                    name: display_name.to_string(),
                    fingerprint: server_fp.clone(),
                    scope: AccessScope::FullAccess,
                    duration: AccessDuration::Persistent,
                    last_seen: history::now_timestamp(),
                },
            )?;
        }
        server_fp
    } else {
        // Fingerprint was enforced by TLS; use what we expected.
        expected_fingerprint.clone().unwrap_or_default()
    };

    // Phase 1: Browse — let user navigate and select files
    let hostname = config::AppConfig::load()
        .map(|c| c.effective_device_name())
        .unwrap_or_else(|_| {
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        });

    let local_fingerprint = certs::local_fingerprint().unwrap_or_default();

    // Send browse request with fingerprint
    let conn_req = ConnectionRequest {
        request_type: RequestType::Browse,
        hostname: hostname.clone(),
        fingerprint: local_fingerprint.clone(),
    };
    protocol::write_frame(&mut tls_stream, &conn_req).await?;

    // Interactive browsing loop
    let mut current_path = remote_path.unwrap_or_default();
    let mut selected_paths: Vec<String> = Vec::new();

    loop {
        // Request directory listing
        let browse_req = BrowseRequest {
            path: current_path.clone(),
        };
        protocol::write_frame(&mut tls_stream, &browse_req).await?;

        // Get response
        let response: BrowseResponse = protocol::read_frame(&mut tls_stream).await?;

        if response.entries.is_empty() {
            println!("  📂 No files found at this location.");
            if current_path.is_empty() {
                println!("  The remote device may not have any shared directories configured.");
                tls_stream.shutdown().await?;
                return Ok(());
            }
        }

        // Show files and let user choose action
        let action = ui::browse_remote_files(&response, &selected_paths)?;

        match action {
            ui::BrowseAction::EnterDirectory(path) => {
                current_path = path;
            }
            ui::BrowseAction::SelectFiles(paths) => {
                selected_paths.extend(paths);
                println!("  [ok] {} item(s) selected", selected_paths.len());
            }
            ui::BrowseAction::GoBack => {
                // Go up one directory
                if let Some(parent) = PathBuf::from(&current_path).parent() {
                    current_path = parent.display().to_string();
                } else {
                    current_path = String::new();
                }
            }
            ui::BrowseAction::Download => {
                break;
            }
            ui::BrowseAction::Quit => {
                info!("Browse cancelled");
                tls_stream.shutdown().await?;
                return Ok(());
            }
        }
    }

    // Close the browse connection
    tls_stream.shutdown().await?;

    if selected_paths.is_empty() {
        println!("  No files selected for download.");
        return Ok(());
    }

    // Phase 2: Download — open new connection to download selected files.
    // We already verified the fingerprint above; enforce it strictly here so
    // a MITM can't swap the cert between the Browse and Download phases.
    info!(
        "Downloading {} item(s) to {}",
        selected_paths.len(),
        save_dir.display()
    );

    let tcp_stream = TcpStream::connect(addr).await?;
    let server_name = rustls::pki_types::ServerName::try_from("secure-transfer.local")
        .map_err(|e| anyhow::anyhow!("Invalid server name: {}", e))?;

    let pinned_fp = if verified_fingerprint.is_empty() {
        None
    } else {
        Some(verified_fingerprint)
    };
    let connector = TlsConnector::from(certs::build_client_config(pinned_fp)?);
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;

    // Send download request with fingerprint
    let conn_req = ConnectionRequest {
        request_type: RequestType::Download,
        hostname,
        fingerprint: local_fingerprint,
    };
    protocol::write_frame(&mut tls_stream, &conn_req).await?;

    let download_req = DownloadRequest {
        paths: selected_paths.clone(),
    };
    protocol::write_frame(&mut tls_stream, &download_req).await?;

    // Receive manifest
    let manifest: TransferManifest = protocol::read_frame(&mut tls_stream).await?;

    println!();
    println!(
        "  📦 Downloading {} file(s), {} total",
        manifest.total_files,
        ui::format_size_pub(manifest.total_size)
    );

    let accepted = ui::confirm_download(&manifest)?;

    let ack = Ack {
        status: if accepted {
            AckStatus::Ok
        } else {
            AckStatus::Rejected
        },
        checksum: String::new(),
        message: if accepted {
            "Accepted".to_string()
        } else {
            "Download cancelled by user".to_string()
        },
    };
    protocol::write_frame(&mut tls_stream, &ack).await?;

    if !accepted {
        info!("Download cancelled by user");
        tls_stream.shutdown().await?;
        return Ok(());
    }

    // Create progress bar
    let (overall_pb, _) = ui::create_transfer_progress(manifest.total_size, manifest.total_files);

    let mut files_received: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut downloaded_paths: Vec<String> = Vec::new();

    // Receive files
    for _ in 0..manifest.total_entries {
        let header: FileHeader = protocol::read_frame(&mut tls_stream).await?;

        // Reject paths that could escape the save directory (e.g. "../../etc/passwd")
        if !is_safe_relative_path(&header.relative_path) {
            warn!(
                "Rejecting unsafe path from server: '{}'",
                header.relative_path
            );
            // Send an error ack so the server doesn't hang waiting for a response
            let ack = Ack {
                status: AckStatus::Error,
                checksum: String::new(),
                message: format!("Unsafe path rejected: {}", header.relative_path),
            };
            protocol::write_frame(&mut tls_stream, &ack).await?;
            continue;
        }

        let dest_path = save_dir.join(&header.relative_path);

        if header.is_dir {
            tokio::fs::create_dir_all(&dest_path).await?;
            debug!("Created directory: {}", header.relative_path);
            continue;
        }

        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut file = tokio::fs::File::create(&dest_path).await?;
        let mut remaining = header.size;
        let mut hasher = protocol::checksum_hasher();
        let mut buf = vec![0u8; CHUNK_SIZE];

        while remaining > 0 {
            let to_read = std::cmp::min(remaining as usize, CHUNK_SIZE);
            let n = tokio::io::AsyncReadExt::read(&mut tls_stream, &mut buf[..to_read]).await?;
            if n == 0 {
                anyhow::bail!(
                    "Connection closed during download of '{}'",
                    header.relative_path
                );
            }
            tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n]).await?;
            hasher.update(&buf[..n]);
            remaining -= n as u64;
            total_bytes += n as u64;
            overall_pb.set_position(total_bytes);
        }

        file.flush().await?;

        let computed = protocol::finalize_checksum(hasher);
        let ok = header.checksum.is_empty() || computed == header.checksum;

        let file_ack = Ack {
            status: if ok { AckStatus::Ok } else { AckStatus::Error },
            checksum: computed,
            message: if ok {
                "OK".to_string()
            } else {
                "Checksum mismatch".to_string()
            },
        };

        protocol::write_frame(&mut tls_stream, &file_ack).await?;

        if ok {
            files_received += 1;
            downloaded_paths.push(header.relative_path.clone());
            overall_pb.set_message(format!(
                "[{}/{}] {}",
                files_received, manifest.total_files, header.relative_path
            ));
        }
    }

    overall_pb.finish_with_message("[ok] Download complete");

    // Log successful download
    let _ = history::append_record(&TransactionRecord {
        timestamp: history::now_timestamp(),
        peer_name: addr.to_string(),
        peer_fingerprint: String::new(),
        action: "Download".to_string(),
        target_paths: downloaded_paths,
        bytes_transferred: total_bytes,
        status: "Success".to_string(),
    });

    info!(
        "[ok] Downloaded {} file(s), {} bytes to {}",
        files_received,
        total_bytes,
        save_dir.display()
    );

    tls_stream.shutdown().await?;
    Ok(())
}

/// Reject any relative path that could escape the destination directory.
///
/// Blocks absolute paths, `..` components, and Windows-style prefixes so that
/// `save_dir.join(relative_path)` can never land outside `save_dir`.
fn is_safe_relative_path(path: &str) -> bool {
    let p = std::path::Path::new(path);
    if p.is_absolute() {
        return false;
    }
    p.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}
