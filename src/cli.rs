use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Quantum-safe secure file transfer over LAN
#[derive(Parser, Debug)]
#[command(name = "secure-transfer", version, about, long_about = None)]
pub struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start listening for incoming file transfers and browse requests
    Listen {
        /// Port to listen on
        #[arg(short, long, default_value = "9876")]
        port: u16,

        /// Directory to save received files
        #[arg(short, long)]
        save_dir: Option<PathBuf>,

        /// Directories to share for remote browsing (defaults to home dir)
        #[arg(long)]
        share: Vec<PathBuf>,

        /// Allow browsing ALL directories (WARNING: use with caution on trusted networks)
        #[arg(long, default_value = "false")]
        unrestricted: bool,
    },

    /// Send files or directories to a device on the network
    Send {
        /// Files or directories to send (supports multiple)
        #[arg(required = true, num_args = 1..)]
        paths: Vec<PathBuf>,

        /// Send directly to a specific address (ip:port)
        #[arg(short, long)]
        to: Option<String>,
    },

    /// Browse and download files from a remote device
    Download {
        /// Connect to a specific address (ip:port)
        #[arg(short, long)]
        from: Option<String>,

        /// Remote directory to browse (defaults to shared root)
        #[arg(short, long)]
        remote_path: Option<String>,

        /// Local directory to save downloaded files
        #[arg(short, long)]
        save_dir: Option<PathBuf>,
    },

    /// Send a text message directly to another device
    Text {
        /// The text message to send
        message: String,

        /// Send directly to a specific address (ip:port)
        #[arg(short, long)]
        to: Option<String>,
    },

    /// Manage device configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Manage trusted devices
    Devices {
        #[command(subcommand)]
        action: DevicesAction,
    },

    /// View transaction history
    History {
        /// Number of records to display (default: 20)
        #[arg(default_value = "20")]
        limit: usize,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Set the device display name for network broadcasts
    SetName {
        /// The display name for this device
        name: String,
    },

    /// Show current configuration
    Show,
}

#[derive(Subcommand, Debug)]
pub enum DevicesAction {
    /// List all trusted devices
    List,

    /// Revoke trust for a device (by name/fingerprint), or choose interactively
    Revoke {
        /// Device name or fingerprint (or fingerprint prefix)
        identifier: Option<String>,
    },
}
