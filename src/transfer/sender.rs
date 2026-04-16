use anyhow::{Context, Result};

use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};
use walkdir::WalkDir;

use crate::config::{self, AccessDuration, AccessScope, TrustedPeer};
use crate::crypto::certs;
use crate::history::{self, TransactionRecord};
use crate::transfer::protocol::{
    self, Ack, AckStatus, CHUNK_SIZE, ConnectionRequest, FileHeader, RequestType, TransferManifest,
    TransferSummary, TextMessage,
};
use crate::ui;

/// Entry to be transferred — pre-computed from input paths
#[derive(Debug, Clone)]
struct TransferEntry {
    /// Absolute path on the local filesystem
    absolute_path: PathBuf,
    /// Relative path to send (preserves directory structure)
    relative_path: String,
    /// Whether this entry is a directory
    is_dir: bool,
    /// File size in bytes (0 for directories)
    size: u64,
}

/// Resolve all input paths into a flat list of transfer entries
///
/// Handles both files and directories recursively, computing
/// relative paths to preserve directory structure.
fn collect_entries(paths: &[PathBuf]) -> Result<Vec<TransferEntry>> {
    let mut entries = Vec::new();

    for path in paths {
        let path = path
            .canonicalize()
            .with_context(|| format!("Path not found: {}", path.display()))?;

        if path.is_file() {
            let filename = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unnamed".to_string());
            let size = std::fs::metadata(&path)?.len();

            entries.push(TransferEntry {
                absolute_path: path,
                relative_path: filename,
                is_dir: false,
                size,
            });
        } else if path.is_dir() {
            let base_parent = path.parent().unwrap_or(&path);

            for entry in WalkDir::new(&path).sort_by_file_name() {
                let entry = entry.with_context(|| "Failed to walk directory")?;
                let entry_path = entry.path();
                let relative = entry_path
                    .strip_prefix(base_parent)
                    .unwrap_or(entry_path)
                    .to_string_lossy()
                    .to_string();

                let is_dir = entry_path.is_dir();
                let size = if is_dir { 0 } else { entry.metadata()?.len() };

                entries.push(TransferEntry {
                    absolute_path: entry_path.to_path_buf(),
                    relative_path: relative,
                    is_dir,
                    size,
                });
            }
        } else {
            anyhow::bail!("Path is neither file nor directory: {}", path.display());
        }
    }

    Ok(entries)
}

/// Send files/directories to a remote receiver.
///
/// `expected_fingerprint`: the receiver's certificate fingerprint obtained
/// from mDNS discovery. When `Some`, TLS will reject a mismatched cert
/// outright (MITM protection). When `None` (manual `--to` connection), the
/// fingerprint is verified interactively after the handshake.
///
/// `peer_name`: display name for UI prompts; falls back to the socket address.
pub async fn send_files(
    paths: &[PathBuf],
    addr: SocketAddr,
    expected_fingerprint: Option<String>,
    peer_name: Option<String>,
) -> Result<()> {
    // Collect all entries
    let entries = collect_entries(paths)?;
    let total_files = entries.iter().filter(|e| !e.is_dir).count() as u64;
    let total_entries = entries.len() as u64;
    let total_size: u64 = entries.iter().map(|e| e.size).sum();

    // Show preparing animation
    let prep_sp = ui::show_preparing_spinner(total_files, total_size);
    std::thread::sleep(std::time::Duration::from_millis(300));
    ui::finish_spinner_success(&prep_sp, &format!("{} file(s) ready to send", total_files));

    // Show connecting animation
    let conn_sp = ui::show_connecting_spinner(&addr.to_string());

    // Connect via TLS — pass expected fingerprint so the verifier can enforce
    // an exact match when we have one from mDNS discovery.
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

    ui::finish_spinner_success(&conn_sp, "Quantum-safe TLS 1.3 connection established");

    // TOFU for manual connections: when we had no mDNS fingerprint we must
    // verify the receiver's cert fingerprint interactively before proceeding.
    if expected_fingerprint.is_none() {
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
            // Persist the receiver's fingerprint so future connections are silent
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
    }
    info!("Quantum-safe TLS connection established to {}", addr);

    // Get our identity
    let hostname = config::AppConfig::load()
        .map(|c| c.effective_device_name())
        .unwrap_or_else(|_| {
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        });

    let local_fingerprint = certs::local_fingerprint().unwrap_or_default();

    // Send connection handshake with fingerprint
    let conn_req = ConnectionRequest {
        request_type: RequestType::Send,
        hostname: hostname.clone(),
        fingerprint: local_fingerprint.clone(),
    };
    protocol::write_frame(&mut tls_stream, &conn_req).await?;

    // Send manifest
    let manifest = TransferManifest {
        sender_hostname: hostname.clone(),
        total_entries,
        total_files,
        total_size,
        quantum_safe: true,
    };

    protocol::write_frame(&mut tls_stream, &manifest).await?;
    debug!("Manifest sent");

    // Wait for receiver acceptance
    let ack: Ack = protocol::read_frame(&mut tls_stream).await?;
    if ack.status == AckStatus::Rejected {
        // Log denied send
        let _ = history::append_record(&TransactionRecord {
            timestamp: history::now_timestamp(),
            peer_name: addr.to_string(),
            peer_fingerprint: String::new(),
            action: "Send".to_string(),
            target_paths: entries.iter().map(|e| e.relative_path.clone()).collect(),
            bytes_transferred: 0,
            status: "Denied".to_string(),
        });
        anyhow::bail!("Transfer rejected by receiver: {}", ack.message);
    }

    // Create animated transfer progress
    let progress = ui::TransferProgress::new(total_size, total_files);
    let start_time = std::time::Instant::now();

    let mut files_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let mut sent_paths: Vec<String> = Vec::new();

    // Send each entry
    for entry in &entries {
        // Compute checksum for files; show hashing indicator so the UI doesn't freeze
        let checksum = if entry.is_dir {
            String::new()
        } else {
            progress.start_hashing(&entry.relative_path, files_sent + 1, entry.size);
            protocol::compute_file_checksum(&entry.absolute_path).await?
        };

        // Send file header
        let header = FileHeader {
            relative_path: entry.relative_path.clone(),
            size: entry.size,
            is_dir: entry.is_dir,
            checksum: checksum.clone(),
        };

        protocol::write_frame(&mut tls_stream, &header).await?;

        // Send file data in chunks
        if !entry.is_dir {
            progress.start_file(&entry.relative_path, files_sent + 1, entry.size);

            let mut file = tokio::fs::File::open(&entry.absolute_path).await?;
            let mut remaining = entry.size;
            let mut buf = vec![0u8; CHUNK_SIZE];

            while remaining > 0 {
                let to_read = std::cmp::min(remaining as usize, CHUNK_SIZE);
                let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf[..to_read]).await?;
                if n == 0 {
                    break;
                }
                tls_stream.write_all(&buf[..n]).await?;
                remaining -= n as u64;
                bytes_sent += n as u64;
                progress.set_bytes(bytes_sent);
            }

            // Wait for per-file ack
            let file_ack: Ack = protocol::read_frame(&mut tls_stream).await?;
            if file_ack.status != AckStatus::Ok {
                anyhow::bail!(
                    "Receiver rejected file '{}': {}",
                    entry.relative_path,
                    file_ack.message
                );
            }

            files_sent += 1;
            sent_paths.push(entry.relative_path.clone());
            progress.finish_file(&entry.relative_path, files_sent);
        }
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    progress.finish(files_sent, bytes_sent, elapsed);

    // Wait for final summary
    let summary: TransferSummary = protocol::read_frame(&mut tls_stream).await?;
    info!(
        "Transfer summary: {} files, {} bytes — {}",
        summary.files_received, summary.total_bytes, summary.message
    );

    // Log successful send
    let _ = history::append_record(&TransactionRecord {
        timestamp: history::now_timestamp(),
        peer_name: addr.to_string(),
        peer_fingerprint: String::new(),
        action: "Send".to_string(),
        target_paths: sent_paths,
        bytes_transferred: bytes_sent,
        status: "Success".to_string(),
    });

    // Show transfer summary
    ui::print_transfer_summary("Send", files_sent, bytes_sent, elapsed, &addr.to_string());

    tls_stream.shutdown().await?;
    Ok(())
}

/// Truncate a string to at most `max_chars` characters (safe for multi-byte UTF-8).
fn truncate_text(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

/// Send a short text message to a remote receiver.
pub async fn send_text(
    message: String,
    addr: SocketAddr,
    expected_fingerprint: Option<String>,
    peer_name: Option<String>,
) -> Result<()> {
    // Show connecting animation
    let conn_sp = ui::show_connecting_spinner(&addr.to_string());

    // Connect via TLS
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

    ui::finish_spinner_success(&conn_sp, "Quantum-safe TLS 1.3 connection established");

    // TOFU for manual connections
    if expected_fingerprint.is_none() {
        let server_fp = {
            let (_, rustls_conn) = tls_stream.get_ref();
            rustls_conn
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert| certs::cert_fingerprint(cert.as_ref()))
        };

        let server_fp =
            server_fp.context("Could not extract server certificate after TLS handshake")?;

        let app_config = config::AppConfig::load().unwrap_or_default();
        if !app_config.is_trusted(&server_fp) {
            let addr_str = addr.to_string();
            let display_name = peer_name.as_deref().unwrap_or(&addr_str);
            if !ui::prompt_verify_fingerprint(&server_fp, display_name)? {
                anyhow::bail!("Connection aborted — receiver fingerprint rejected");
            }
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
    }

    // Get our identity
    let hostname = config::AppConfig::load()
        .map(|c| c.effective_device_name())
        .unwrap_or_else(|_| {
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        });

    let local_fingerprint = certs::local_fingerprint().unwrap_or_default();

    // Send connection handshake
    let conn_req = ConnectionRequest {
        request_type: RequestType::Text,
        hostname: hostname.clone(),
        fingerprint: local_fingerprint,
    };
    protocol::write_frame(&mut tls_stream, &conn_req).await?;

    // Send text message
    let text_msg = TextMessage {
        sender_hostname: hostname,
        content: message.clone(),
    };
    protocol::write_frame(&mut tls_stream, &text_msg).await?;

    // Wait for acknowledgment
    let ack: Ack = protocol::read_frame(&mut tls_stream).await?;
    if ack.status == AckStatus::Rejected {
        // Log denied send
        let _ = history::append_record(&TransactionRecord {
            timestamp: history::now_timestamp(),
            peer_name: addr.to_string(),
            peer_fingerprint: String::new(),
            action: "Text".to_string(),
            target_paths: vec!["<text message>".to_string()],
            bytes_transferred: 0,
            status: "Denied".to_string(),
        });
        anyhow::bail!("Text message rejected by receiver: {}", ack.message);
    }

    // Show summary
    println!("  {}  Text message sent successfully!", console::style("[ok]").green().bold());

    // Log successful send
    let _ = history::append_record(&TransactionRecord {
        timestamp: history::now_timestamp(),
        peer_name: addr.to_string(),
        peer_fingerprint: String::new(),
        action: "Text".to_string(),
        target_paths: vec![format!("Text: {}...", truncate_text(&message, 20))],
        bytes_transferred: message.len() as u64,
        status: "Success".to_string(),
    });

    tls_stream.shutdown().await?;
    Ok(())
}
