use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::transfer::protocol::RequestType;

const DEFAULT_PORT: u16 = 9876;

/// Process-level lock serialising all config read-modify-write operations.
/// Without this, concurrent incoming connections (each with their own task) can
/// race: both read config, both modify, and the last write silently drops the
/// other's change — e.g. two simultaneous trust-grants lose one peer record.
static CONFIG_LOCK: Mutex<()> = Mutex::new(());

/// Access scope for a trusted peer — what operations they can perform
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccessScope {
    /// Authorized to only send files (drops if they attempt to Browse/Download)
    SendOnly,
    /// Authorized to Download from explicit `share` dirs
    SharedReadOnly,
    /// Authorized for Send/Browse/Download across unconstrained file trees
    FullAccess,
}

impl std::fmt::Display for AccessScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessScope::SendOnly => write!(f, "Send Only"),
            AccessScope::SharedReadOnly => write!(f, "Shared Read-Only"),
            AccessScope::FullAccess => write!(f, "Full Access"),
        }
    }
}

/// Access duration for a trusted peer — how long the trust lasts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccessDuration {
    /// Must be re-prompted on next connection
    OneTime,
    /// Bypasses prompt entirely up to designated scope limit
    Persistent,
}

impl std::fmt::Display for AccessDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessDuration::OneTime => write!(f, "One-Time"),
            AccessDuration::Persistent => write!(f, "Persistent"),
        }
    }
}

/// Known peer with its certificate fingerprint and access rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeer {
    pub name: String,
    pub fingerprint: String,
    pub scope: AccessScope,
    pub duration: AccessDuration,
    pub last_seen: String,
}

/// Persistent application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Custom device display name (replaces hostname in broadcasts)
    #[serde(default)]
    pub device_name: Option<String>,
    pub default_save_dir: PathBuf,
    pub default_port: u16,
    pub trusted_peers: HashMap<String, TrustedPeer>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            device_name: None,
            default_save_dir: default_save_dir(),
            default_port: DEFAULT_PORT,
            trusted_peers: HashMap::new(),
        }
    }
}

impl AppConfig {
    /// Load config from disk, or create default if missing
    pub fn load() -> Result<Self> {
        let path = config_file_path()?;
        if path.exists() {
            let data = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read config: {}", path.display()))?;
            let config: AppConfig =
                serde_json::from_str(&data).with_context(|| "Failed to parse config file")?;
            Ok(config)
        } else {
            let config = AppConfig::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Persist config to disk atomically.
    ///
    /// Holds `CONFIG_LOCK` for the duration of the read-modify-write so that
    /// concurrent connection tasks cannot interleave their writes and lose records.
    /// Writes to a `.tmp` file then renames so a crash mid-write never leaves a
    /// partially-written config.
    pub fn save(&self) -> Result<()> {
        let _guard = CONFIG_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let path = config_file_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config dir: {}", parent.display()))?;
        }
        let data = serde_json::to_string_pretty(self)?;
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, &data)
            .with_context(|| format!("Failed to write temp config: {}", tmp_path.display()))?;
        fs::rename(&tmp_path, &path)
            .with_context(|| format!("Failed to commit config: {}", path.display()))?;
        Ok(())
    }

    /// Add a trusted peer
    pub fn add_trusted_peer(&mut self, fingerprint: String, peer: TrustedPeer) -> Result<()> {
        self.trusted_peers.insert(fingerprint, peer);
        self.save()
    }

    /// Remove a trusted peer by fingerprint or name
    /// Returns true if a peer was removed
    pub fn remove_trusted_peer(&mut self, identifier: &str) -> Result<bool> {
        // Try by fingerprint first
        if self.trusted_peers.contains_key(identifier) {
            self.trusted_peers.remove(identifier);
            self.save()?;
            return Ok(true);
        }

        // Try by name (case-insensitive partial match)
        let key = self
            .trusted_peers
            .iter()
            .find(|(_, peer)| peer.name.to_lowercase() == identifier.to_lowercase())
            .map(|(k, _)| k.clone());

        if let Some(key) = key {
            self.trusted_peers.remove(&key);
            self.save()?;
            return Ok(true);
        }

        // Try by fingerprint prefix
        let key = self
            .trusted_peers
            .keys()
            .find(|k| k.starts_with(identifier))
            .cloned();

        if let Some(key) = key {
            self.trusted_peers.remove(&key);
            self.save()?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Remove all trusted peers
    /// Returns the number of peers removed
    pub fn clear_trusted_peers(&mut self) -> Result<usize> {
        let count = self.trusted_peers.len();
        self.trusted_peers.clear();
        self.save()?;
        Ok(count)
    }

    /// Check if a fingerprint is trusted
    pub fn is_trusted(&self, fingerprint: &str) -> bool {
        self.trusted_peers.contains_key(fingerprint)
    }

    /// Get a trusted peer by fingerprint
    pub fn get_trusted_peer(&self, fingerprint: &str) -> Option<&TrustedPeer> {
        self.trusted_peers.get(fingerprint)
    }

    /// Check if a given scope covers a request type.
    ///
    /// Scope matrix:
    /// - `SendOnly`       → Send only; Browse and Download are rejected.
    /// - `SharedReadOnly` → Browse and Download only; Send is rejected.
    ///   (A read-only peer should not be able to push files.)
    /// - `FullAccess`     → All request types.
    ///
    /// Used for both persistent-config and session-level checks.
    pub fn scope_covers(scope: &AccessScope, request_type: &RequestType) -> bool {
        matches!(
            (scope, request_type),
            (AccessScope::FullAccess, _)
                | (AccessScope::SendOnly, RequestType::Send)
                | (AccessScope::SharedReadOnly, RequestType::Browse)
                | (AccessScope::SharedReadOnly, RequestType::Download)
        )
    }

    /// Check if a peer is authorized for a given request type.
    ///
    /// Returns `false` for OneTime peers (they are never auto-authorized on
    /// subsequent connections) and for fingerprints not in the trusted list.
    pub fn is_authorized(&self, fingerprint: &str, request_type: &RequestType) -> bool {
        if let Some(peer) = self.trusted_peers.get(fingerprint) {
            // OneTime peers are never auto-authorized on subsequent connections
            if peer.duration == AccessDuration::OneTime {
                return false;
            }
            Self::scope_covers(&peer.scope, request_type)
        } else {
            false
        }
    }

    /// Get the effective device name (custom name or system hostname)
    pub fn effective_device_name(&self) -> String {
        self.device_name.clone().unwrap_or_else(|| {
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        })
    }
}

/// Get the config directory path
pub fn config_dir() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("", "", "secure-transfer")
        .context("Failed to determine config directory")?;
    Ok(proj_dirs.config_dir().to_path_buf())
}

/// Get the config file path
fn config_file_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.json"))
}

/// Get the path to the TLS certificate
pub fn cert_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("cert.pem"))
}

/// Get the path to the TLS private key
pub fn key_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("key.pem"))
}

/// Get the path to the transaction history file
pub fn history_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("history.json"))
}

/// Default directory for received files
fn default_save_dir() -> PathBuf {
    dirs_default_download().unwrap_or_else(|| PathBuf::from("./received"))
}

fn dirs_default_download() -> Option<PathBuf> {
    directories::UserDirs::new().map(|u| {
        u.download_dir()
            .unwrap_or(u.home_dir())
            .join("secure-transfer")
    })
}
