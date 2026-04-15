use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum size for a single protocol frame header (1MB)
const MAX_FRAME_SIZE: u32 = 1_048_576;

/// Chunk size for file data transfer (64KB)
pub const CHUNK_SIZE: usize = 65_536;

// --- Protocol Frame Types ---

/// Transfer manifest — sent first to describe the entire transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferManifest {
    /// Name of the sending device
    pub sender_hostname: String,
    /// Total number of entries (files + directories)
    pub total_entries: u64,
    /// Total number of files (excluding directories)
    pub total_files: u64,
    /// Total size of all files in bytes
    pub total_size: u64,
    /// Whether this connection uses quantum-safe key exchange
    pub quantum_safe: bool,
}

/// File entry header — sent before each file's data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHeader {
    /// Relative path (preserving directory structure)
    pub relative_path: String,
    /// File size in bytes (0 for directories)
    pub size: u64,
    /// Whether this entry is a directory
    pub is_dir: bool,
    /// SHA-256 checksum of file content (empty for directories)
    pub checksum: String,
}

/// Acknowledgment frame — sent by receiver
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ack {
    pub status: AckStatus,
    /// Receiver-computed checksum for verification
    pub checksum: String,
    /// Optional message (e.g., error details)
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AckStatus {
    Ok,
    Error,
    Rejected,
}

/// Transfer summary — sent as the final ack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferSummary {
    pub status: AckStatus,
    pub files_received: u64,
    pub total_bytes: u64,
    pub message: String,
}

// --- Browse/Pull Protocol Types ---

/// The type of request being made on a connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestType {
    /// Send files to this device (original send flow)
    Send,
    /// Browse remote files
    Browse,
    /// Download specific files from remote
    Download,
}

impl RequestType {
    /// Human-readable label used for logging and history records.
    ///
    /// **Not** intended for access-control logic — use the enum variants directly.
    pub fn as_str(&self) -> &'static str {
        match self {
            RequestType::Send => "Send",
            RequestType::Browse => "Browse",
            RequestType::Download => "Download",
        }
    }
}

/// Initial handshake frame — sent first on every connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRequest {
    pub request_type: RequestType,
    pub hostname: String,
    /// Certificate fingerprint of the connecting peer
    #[serde(default)]
    pub fingerprint: String,
}

/// Browse request — ask the remote to list files in a directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowseRequest {
    /// Directory to list (empty = shared root)
    pub path: String,
}

/// A single entry in a browse listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowseEntry {
    pub name: String,
    pub relative_path: String,
    pub is_dir: bool,
    pub size: u64,
}

impl std::fmt::Display for BrowseEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_dir {
            write!(f, "[dir] {}/", self.name)
        } else {
            write!(f, "      {} ({})", self.name, format_size(self.size))
        }
    }
}

/// Browse response — list of files/dirs at the requested path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowseResponse {
    pub current_path: String,
    pub entries: Vec<BrowseEntry>,
}

/// Pull request — ask remote to send specific files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadRequest {
    /// List of relative paths to download
    pub paths: Vec<String>,
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// --- Wire Protocol Helpers ---

/// Write a JSON frame to the stream: [4-byte length BE][JSON bytes]
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> io::Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let json = serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = json.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&json).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a JSON frame from the stream: [4-byte length BE][JSON bytes]
pub async fn read_frame<R, T>(reader: &mut R) -> io::Result<T>
where
    R: AsyncReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);

    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Frame too large: {} bytes (max {})", len, MAX_FRAME_SIZE),
        ));
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;

    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Compute SHA-256 checksum of a file
pub async fn compute_file_checksum(path: &std::path::Path) -> io::Result<String> {
    let data = tokio::fs::read(path).await?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}

/// Compute SHA-256 checksum incrementally from chunks
pub fn checksum_hasher() -> Sha256 {
    Sha256::new()
}

/// Finalize a hasher into a hex string
pub fn finalize_checksum(hasher: Sha256) -> String {
    hex::encode(hasher.finalize())
}
