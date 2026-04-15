use anyhow::{Context, Result};
use sha2::Digest;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::config::{self, AccessDuration, TrustedPeer};
use crate::crypto::certs;
use crate::history::{self, TransactionRecord};
use crate::transfer::protocol::{
    self, Ack, AckStatus, BrowseEntry, BrowseRequest, BrowseResponse, ConnectionRequest,
    DownloadRequest, FileHeader, RequestType, TransferManifest, TransferSummary, CHUNK_SIZE,
};
use crate::ui;

/// Start the receiver, listening for incoming file transfers and browse requests
pub async fn listen(port: u16, save_dir: PathBuf, share_dirs: Vec<PathBuf>, unrestricted: bool) -> Result<()> {
    // Ensure save directory exists
    tokio::fs::create_dir_all(&save_dir).await.with_context(|| {
        format!(
            "Failed to create save directory: {}",
            save_dir.display()
        )
    })?;

    // Determine shared directories
    let share_dirs = if share_dirs.is_empty() {
        vec![dirs_home()]
    } else {
        share_dirs
    };

    // Validate shared dirs exist
    for dir in &share_dirs {
        if !dir.exists() {
            anyhow::bail!("Shared directory does not exist: {}", dir.display());
        }
    }

    // Build TLS server config
    let tls_config = certs::build_server_config()?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    // Bind TCP listener
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .with_context(|| format!("Failed to bind to port {}", port))?;

    let local_fp = certs::local_fingerprint()?;

    // Load device name for display
    let device_name = config::AppConfig::load()
        .map(|c| c.effective_device_name())
        .unwrap_or_else(|_| "unknown".to_string());

    info!("Quantum-safe receiver ready on port {}", port);
    info!("Certificate fingerprint: {}", local_fp);
    info!("Save directory: {}", save_dir.display());
    info!("Waiting for incoming transfers... (Ctrl+C to stop)");

    let share_display: Vec<String> = share_dirs.iter().map(|d| d.display().to_string()).collect();

    println!();
    println!("  +--------------------------------------------------+");
    println!("  |  secure-transfer -- Quantum-Safe Receiver         |");
    println!("  |--------------------------------------------------|");
    println!("  |  Name: {:<43} |", device_name);
    println!("  |  Port: {:<42} |", port);
    println!(
        "  |  Fingerprint: {}...  |",
        &local_fp[..36]
    );
    println!("  |  Save to: {:<39} |", truncate_path(&save_dir, 39));
    println!("  |  Sharing: {:<39} |", if unrestricted { "[!!] ALL directories".to_string() } else { truncate_str(&share_display.join(", "), 39) });
    println!("  |  Encryption: X25519MLKEM768 + AES-256-GCM       |");
    println!("  +--------------------------------------------------+");
    println!();

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        info!("Incoming connection from {}", peer_addr);

        let acceptor = acceptor.clone();
        let save_dir = save_dir.clone();
        let share_dirs = share_dirs.clone();

        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = handle_connection(tls_stream, &save_dir, &share_dirs, unrestricted).await {
                        warn!("Connection from {} failed: {}", peer_addr, e);
                    }
                }
                Err(e) => {
                    warn!("TLS handshake with {} failed: {}", peer_addr, e);
                }
            }
        });
    }
}

/// Route a connection based on the initial request type, enforcing access control
async fn handle_connection(
    mut tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    save_dir: &Path,
    share_dirs: &[PathBuf],
    unrestricted: bool,
) -> Result<()> {
    // Read the connection request to determine what the client wants
    let conn_req: ConnectionRequest = protocol::read_frame(&mut tls_stream).await?;

    let request_type_str = match &conn_req.request_type {
        RequestType::Send => "Send",
        RequestType::Browse => "Browse",
        RequestType::Download => "Download",
    };

    info!(
        "Request from '{}' (fp: {}): {:?}",
        conn_req.hostname,
        if conn_req.fingerprint.len() > 12 { &conn_req.fingerprint[..12] } else { &conn_req.fingerprint },
        conn_req.request_type
    );

    // ── Access Control Gate ──
    let mut config = config::AppConfig::load().unwrap_or_default();
    let peer_fingerprint = conn_req.fingerprint.clone();
    let peer_name = conn_req.hostname.clone();

    // Check if peer is authorized for this request type
    let authorized = if peer_fingerprint.is_empty() {
        // Legacy client without fingerprint — always prompt
        false
    } else {
        config.is_authorized(&peer_fingerprint, request_type_str)
    };

    if !authorized {
        // Unknown peer or scope exceeded — prompt user
        let decision = ui::prompt_access_grant(
            &peer_name,
            &peer_fingerprint,
            request_type_str,
        )?;

        if !decision.granted {
            // Log the denied connection
            let _ = history::append_record(&TransactionRecord {
                timestamp: history::now_timestamp(),
                peer_name: peer_name.clone(),
                peer_fingerprint: peer_fingerprint.clone(),
                action: request_type_str.to_string(),
                target_paths: vec![],
                bytes_transferred: 0,
                status: "Denied".to_string(),
            });

            // Send rejection
            let ack = Ack {
                status: AckStatus::Rejected,
                checksum: String::new(),
                message: "Access denied by receiver".to_string(),
            };
            protocol::write_frame(&mut tls_stream, &ack).await?;
            info!("Access denied for '{}' ({:?})", peer_name, conn_req.request_type);
            tls_stream.shutdown().await?;
            return Ok(());
        }

        // If granted persistently, store the trust record
        if decision.duration == AccessDuration::Persistent && !peer_fingerprint.is_empty() {
            let trusted_peer = TrustedPeer {
                name: peer_name.clone(),
                fingerprint: peer_fingerprint.clone(),
                scope: decision.scope,
                duration: decision.duration,
                last_seen: history::now_timestamp(),
            };
            config.add_trusted_peer(peer_fingerprint.clone(), trusted_peer)?;
            info!("Peer '{}' added to trusted devices", peer_name);
        }
    } else {
        // Update last_seen for trusted peers
        if let Some(peer) = config.trusted_peers.get_mut(&peer_fingerprint) {
            peer.last_seen = history::now_timestamp();
            let _ = config.save();
        }
        info!("Peer '{}' authorized via trusted device list", peer_name);
    }

    // Determine effective unrestricted mode: if the peer has FullAccess, treat as unrestricted
    let effective_unrestricted = if let Some(peer) = config.get_trusted_peer(&peer_fingerprint) {
        unrestricted || matches!(peer.scope, config::AccessScope::FullAccess)
    } else {
        unrestricted
    };

    match conn_req.request_type {
        RequestType::Send => handle_send(tls_stream, save_dir, &peer_name, &peer_fingerprint).await,
        RequestType::Browse => handle_browse(tls_stream, share_dirs, effective_unrestricted).await,
        RequestType::Download => handle_download(tls_stream, share_dirs, effective_unrestricted, &peer_name, &peer_fingerprint).await,
    }
}

/// Handle a send (incoming file transfer) — original flow
async fn handle_send(
    mut tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    save_dir: &Path,
    peer_name: &str,
    peer_fingerprint: &str,
) -> Result<()> {
    // Read manifest
    let manifest: TransferManifest = protocol::read_frame(&mut tls_stream).await?;

    info!(
        "Incoming transfer from '{}': {} files, {} entries, {} bytes",
        manifest.sender_hostname,
        manifest.total_files,
        manifest.total_entries,
        manifest.total_size
    );

    // For trusted persistent peers, skip the transfer confirmation prompt
    let config = config::AppConfig::load().unwrap_or_default();
    let auto_accept = if !peer_fingerprint.is_empty() {
        config.is_authorized(peer_fingerprint, "Send")
    } else {
        false
    };

    let accepted = if auto_accept {
        info!("Auto-accepting transfer from trusted peer '{}'", peer_name);
        true
    } else {
        ui::confirm_transfer(&manifest)?
    };

    let ack = if accepted {
        Ack {
            status: AckStatus::Ok,
            checksum: String::new(),
            message: "Transfer accepted".to_string(),
        }
    } else {
        Ack {
            status: AckStatus::Rejected,
            checksum: String::new(),
            message: "Transfer rejected by user".to_string(),
        }
    };

    protocol::write_frame(&mut tls_stream, &ack).await?;

    if !accepted {
        info!("Transfer rejected by user");
        // Log denied transfer
        let _ = history::append_record(&TransactionRecord {
            timestamp: history::now_timestamp(),
            peer_name: peer_name.to_string(),
            peer_fingerprint: peer_fingerprint.to_string(),
            action: "Send".to_string(),
            target_paths: vec![],
            bytes_transferred: 0,
            status: "Denied".to_string(),
        });
        return Ok(());
    }

    // Create progress bar
    let (overall_pb, _file_pb) =
        ui::create_transfer_progress(manifest.total_size, manifest.total_files);

    let mut files_received: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut received_paths: Vec<String> = Vec::new();

    // Receive each entry
    for _ in 0..manifest.total_entries {
        let header: FileHeader = protocol::read_frame(&mut tls_stream).await?;
        let dest_path = save_dir.join(&header.relative_path);

        if header.is_dir {
            tokio::fs::create_dir_all(&dest_path).await.with_context(|| {
                format!("Failed to create directory: {}", dest_path.display())
            })?;
            debug!("Created directory: {}", header.relative_path);
            continue;
        }

        // Ensure parent directory exists
        if let Some(parent) = dest_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Receive file data
        let mut file = tokio::fs::File::create(&dest_path).await.with_context(|| {
            format!("Failed to create file: {}", dest_path.display())
        })?;

        let mut remaining = header.size;
        let mut hasher = protocol::checksum_hasher();
        let mut buf = vec![0u8; CHUNK_SIZE];

        while remaining > 0 {
            let to_read = std::cmp::min(remaining as usize, CHUNK_SIZE);
            let n = tokio::io::AsyncReadExt::read(&mut tls_stream, &mut buf[..to_read]).await?;
            if n == 0 {
                anyhow::bail!("Connection closed during transfer of '{}'", header.relative_path);
            }
            tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n]).await?;
            hasher.update(&buf[..n]);
            remaining -= n as u64;
            total_bytes += n as u64;
            overall_pb.set_position(total_bytes);
        }

        file.flush().await?;

        // Verify checksum
        let computed_checksum = protocol::finalize_checksum(hasher);
        let checksum_ok = header.checksum.is_empty() || computed_checksum == header.checksum;

        let file_ack = if checksum_ok {
            files_received += 1;
            received_paths.push(header.relative_path.clone());
            overall_pb.set_message(format!(
                "[{}/{}] {}",
                files_received, manifest.total_files, header.relative_path
            ));
            debug!(
                "[ok] Received: {} ({} bytes)",
                header.relative_path, header.size
            );
            Ack {
                status: AckStatus::Ok,
                checksum: computed_checksum,
                message: "OK".to_string(),
            }
        } else {
            warn!(
                "[err] Checksum mismatch for '{}': expected {}, got {}",
                header.relative_path, header.checksum, computed_checksum
            );
            Ack {
                status: AckStatus::Error,
                checksum: computed_checksum,
                message: "Checksum mismatch".to_string(),
            }
        };

        protocol::write_frame(&mut tls_stream, &file_ack).await?;
    }

    overall_pb.finish_with_message("[ok] Transfer complete");

    // Send final summary
    let summary = TransferSummary {
        status: AckStatus::Ok,
        files_received,
        total_bytes,
        message: format!(
            "Successfully received {} file(s), {} bytes",
            files_received, total_bytes
        ),
    };

    protocol::write_frame(&mut tls_stream, &summary).await?;

    // Log successful transfer
    let _ = history::append_record(&TransactionRecord {
        timestamp: history::now_timestamp(),
        peer_name: peer_name.to_string(),
        peer_fingerprint: peer_fingerprint.to_string(),
        action: "Send".to_string(),
        target_paths: received_paths,
        bytes_transferred: total_bytes,
        status: "Success".to_string(),
    });

    info!(
        "[ok] Transfer complete: {} file(s), {} bytes saved to {}",
        files_received,
        total_bytes,
        save_dir.display()
    );

    tls_stream.shutdown().await?;
    Ok(())
}

/// Handle a browse request — list files in the shared directory
async fn handle_browse(
    mut tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    share_dirs: &[PathBuf],
    unrestricted: bool,
) -> Result<()> {
    loop {
        // Read browse request (or detect disconnect)
        let browse_req: BrowseRequest = match protocol::read_frame(&mut tls_stream).await {
            Ok(req) => req,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("Browse session ended (client disconnected)");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        info!("Browse request for: '{}'", browse_req.path);

        let entries = if browse_req.path.is_empty() || browse_req.path == "/" {
            if unrestricted {
                // Show filesystem root
                list_directory(Path::new("/"))?
            } else {
                // Show shared directory roots
                share_dirs
                    .iter()
                    .map(|d| {
                        let name = d
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| d.display().to_string());
                        BrowseEntry {
                            name,
                            relative_path: d.display().to_string(),
                            is_dir: true,
                            size: 0,
                        }
                    })
                    .collect()
            }
        } else {
            let req_path = PathBuf::from(&browse_req.path);

            // Security: validate path is within shared dirs (unless unrestricted)
            if !unrestricted {
                let is_allowed = share_dirs.iter().any(|sd| req_path.starts_with(sd));
                if !is_allowed {
                    let response = BrowseResponse {
                        current_path: browse_req.path,
                        entries: vec![],
                    };
                    protocol::write_frame(&mut tls_stream, &response).await?;
                    continue;
                }
            }

            list_directory(&req_path)?
        };

        let response = BrowseResponse {
            current_path: browse_req.path,
            entries,
        };

        protocol::write_frame(&mut tls_stream, &response).await?;
    }
}

/// Handle a download request — send requested files to the client
async fn handle_download(
    mut tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    share_dirs: &[PathBuf],
    unrestricted: bool,
    peer_name: &str,
    peer_fingerprint: &str,
) -> Result<()> {
    // Read the download request
    let download_req: DownloadRequest = protocol::read_frame(&mut tls_stream).await?;

    info!("📥 Download request for {} path(s)", download_req.paths.len());

    // Validate and collect entries
    let mut entries = Vec::new();
    for req_path in &download_req.paths {
        let path = PathBuf::from(req_path);

        // Security: validate path is within shared dirs (unless unrestricted)
        if !unrestricted {
            let is_allowed = share_dirs.iter().any(|sd| path.starts_with(sd));
            if !is_allowed {
                warn!("Download request denied for path outside share: {}", req_path);
                continue;
            }
        }

        if path.is_file() {
            let size = std::fs::metadata(&path)?.len();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            entries.push((path, name, size, false));
        } else if path.is_dir() {
            for entry in WalkDir::new(&path).sort_by_file_name() {
                let entry = entry?;
                let entry_path = entry.path().to_path_buf();
                let relative = entry_path
                    .strip_prefix(path.parent().unwrap_or(&path))
                    .unwrap_or(&entry_path)
                    .to_string_lossy()
                    .to_string();
                let is_dir = entry_path.is_dir();
                let size = if is_dir { 0 } else { entry.metadata()?.len() };
                entries.push((entry_path, relative, size, is_dir));
            }
        }
    }

    let total_files = entries.iter().filter(|(_, _, _, is_dir)| !is_dir).count() as u64;
    let total_size: u64 = entries.iter().map(|(_, _, s, _)| s).sum();

    let hostname = config::AppConfig::load()
        .map(|c| c.effective_device_name())
        .unwrap_or_else(|_| {
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        });

    // Send manifest
    let manifest = TransferManifest {
        sender_hostname: hostname,
        total_entries: entries.len() as u64,
        total_files,
        total_size,
        quantum_safe: true,
    };

    protocol::write_frame(&mut tls_stream, &manifest).await?;

    // Wait for client acceptance
    let ack: Ack = protocol::read_frame(&mut tls_stream).await?;
    if ack.status == AckStatus::Rejected {
        info!("Download rejected by client");
        return Ok(());
    }

    let mut sent_paths: Vec<String> = Vec::new();

    // Send each file
    for (abs_path, rel_path, size, is_dir) in &entries {
        let checksum = if *is_dir {
            String::new()
        } else {
            protocol::compute_file_checksum(abs_path).await?
        };

        let header = FileHeader {
            relative_path: rel_path.clone(),
            size: *size,
            is_dir: *is_dir,
            checksum: checksum.clone(),
        };

        protocol::write_frame(&mut tls_stream, &header).await?;

        if !is_dir {
            let mut file = tokio::fs::File::open(abs_path).await?;
            let mut remaining = *size;
            let mut buf = vec![0u8; CHUNK_SIZE];

            while remaining > 0 {
                let to_read = std::cmp::min(remaining as usize, CHUNK_SIZE);
                let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf[..to_read]).await?;
                if n == 0 {
                    break;
                }
                tls_stream.write_all(&buf[..n]).await?;
                remaining -= n as u64;
            }

            // Wait for per-file ack
            let _file_ack: Ack = protocol::read_frame(&mut tls_stream).await?;
            sent_paths.push(rel_path.clone());
        }
    }

    // Log successful download
    let _ = history::append_record(&TransactionRecord {
        timestamp: history::now_timestamp(),
        peer_name: peer_name.to_string(),
        peer_fingerprint: peer_fingerprint.to_string(),
        action: "Download".to_string(),
        target_paths: sent_paths,
        bytes_transferred: total_size,
        status: "Success".to_string(),
    });

    info!("[ok] Download complete: {} files, {} bytes", total_files, total_size);
    tls_stream.shutdown().await?;
    Ok(())
}

/// List files in a directory, returning BrowseEntry items
fn list_directory(path: &Path) -> Result<Vec<BrowseEntry>> {
    let mut entries = Vec::new();

    let read_dir = std::fs::read_dir(path)
        .with_context(|| format!("Failed to read directory: {}", path.display()))?;

    for entry in read_dir {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip hidden files
        if name.starts_with('.') {
            continue;
        }

        entries.push(BrowseEntry {
            name,
            relative_path: entry.path().display().to_string(),
            is_dir: metadata.is_dir(),
            size: if metadata.is_dir() { 0 } else { metadata.len() },
        });
    }

    // Sort: directories first, then alphabetically
    entries.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name))
    });

    Ok(entries)
}

/// Truncate a path display to fit a given width
fn truncate_path(path: &Path, max_len: usize) -> String {
    let s = path.display().to_string();
    truncate_str(&s, max_len)
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("…{}", &s[s.len() - (max_len - 1)..])
    }
}

fn dirs_home() -> PathBuf {
    directories::UserDirs::new()
        .map(|u| u.home_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}
