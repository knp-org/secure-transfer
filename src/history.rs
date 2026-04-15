use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Mutex;

use crate::config;

/// Process-level lock that serialises all history read-modify-write operations.
///
/// Without this, concurrent connections race: both read the file, both append
/// in memory, and the second write silently overwrites the first write's record.
static HISTORY_LOCK: Mutex<()> = Mutex::new(());

/// A single transaction log record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub timestamp: String,
    pub peer_name: String,
    pub peer_fingerprint: String,
    /// "Send", "Download", "Browse", "Connect"
    pub action: String,
    pub target_paths: Vec<String>,
    pub bytes_transferred: u64,
    /// "Success", "Denied", "Error"
    pub status: String,
}

/// Append a transaction record to the history file.
///
/// Holds `HISTORY_LOCK` for the duration of the read-modify-write so that
/// concurrent connections cannot interleave their writes and lose records.
pub fn append_record(record: &TransactionRecord) -> Result<()> {
    let _guard = HISTORY_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let path = config::history_path()?;
    let mut records = load_records().unwrap_or_default();
    records.push(record.clone());
    let data = serde_json::to_string_pretty(&records)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create history dir: {}", parent.display()))?;
    }
    fs::write(&path, data)
        .with_context(|| format!("Failed to write history: {}", path.display()))?;
    Ok(())
}

/// Load all transaction records from disk
pub fn load_records() -> Result<Vec<TransactionRecord>> {
    let path = config::history_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read history: {}", path.display()))?;
    let records: Vec<TransactionRecord> =
        serde_json::from_str(&data).with_context(|| "Failed to parse history file")?;
    Ok(records)
}

/// Get the current timestamp as an ISO 8601 string
pub fn now_timestamp() -> String {
    // Use a simple format from std — no chrono dependency needed
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Simple UTC timestamp calculation
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Calculate year/month/day from days since epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day)
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Simplified calendar calculation
    let mut y = 1970;
    let mut remaining = days;

    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }

    let months = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0;
    for days_in_month in &months {
        if remaining < *days_in_month {
            break;
        }
        remaining -= days_in_month;
        m += 1;
    }

    (y, m + 1, remaining + 1)
}

fn is_leap_year(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}
