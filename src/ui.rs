use console::style;
use dialoguer::{Confirm, MultiSelect, Select};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::time::Duration;

use crate::config::{AccessDuration, AccessScope};
use crate::discovery::DiscoveredDevice;
use crate::transfer::protocol::{BrowseResponse, RequestType, TransferManifest};

// ────────────────────────────────────────────────────────────────
// Custom spinner frames for different phases
// ────────────────────────────────────────────────────────────────

const SPINNER_TRANSFER: &[&str] = &[
    "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏",
];

const SPINNER_QUANTUM: &[&str] = &[
    "◐", "◓", "◑", "◒", "◐", "◓", "◑", "◒",
];

const SPINNER_SCANNING: &[&str] = &[
    "∙∙∙", "●∙∙", "∙●∙", "∙∙●", "∙∙∙", "●∙∙", "∙●∙", "∙∙●",
];

const SPINNER_FILES: &[&str] = &[
    "▹▹▹", "▸▹▹", "▹▸▹", "▹▹▸", "▸▸▹", "▹▸▸", "▸▸▸", "▹▹▹",
];

// ────────────────────────────────────────────────────────────────
// BrowseAction enum
// ────────────────────────────────────────────────────────────────

/// What the user wants to do while browsing remote files
pub enum BrowseAction {
    /// Navigate into a directory
    EnterDirectory(String),
    /// Select files/dirs for download
    SelectFiles(Vec<String>),
    /// Go back to parent directory
    GoBack,
    /// Start downloading selected files
    Download,
    /// Cancel and quit
    Quit,
}

// ────────────────────────────────────────────────────────────────
// Animated phase banners
// ────────────────────────────────────────────────────────────────

/// Show a connecting/handshake animation
pub fn show_connecting_spinner(addr: &str) -> ProgressBar {
    let sp = ProgressBar::new_spinner();
    sp.set_style(
        ProgressStyle::with_template("  {spinner} {msg}")
            .unwrap()
            .tick_strings(SPINNER_QUANTUM),
    );
    sp.enable_steady_tick(Duration::from_millis(150));
    sp.set_message(format!(
        "{}  Establishing quantum-safe TLS connection to {}",
        style(">>").cyan().bold(),
        style(addr).yellow()
    ));
    sp
}

/// Show a device scanning animation
pub fn show_scanning_spinner() -> ProgressBar {
    let sp = ProgressBar::new_spinner();
    sp.set_style(
        ProgressStyle::with_template("  {spinner} {msg}")
            .unwrap()
            .tick_strings(SPINNER_SCANNING),
    );
    sp.enable_steady_tick(Duration::from_millis(200));
    sp.set_message(format!(
        "{}  Scanning for devices on LAN...",
        style(">>").cyan().bold()
    ));
    sp
}

/// Show a file preparation animation
pub fn show_preparing_spinner(total_files: u64, total_size: u64) -> ProgressBar {
    let sp = ProgressBar::new_spinner();
    sp.set_style(
        ProgressStyle::with_template("  {spinner} {msg}")
            .unwrap()
            .tick_strings(SPINNER_FILES),
    );
    sp.enable_steady_tick(Duration::from_millis(200));
    sp.set_message(format!(
        "{}  Preparing {} file(s) ({})...",
        style(">>").cyan().bold(),
        style(total_files).green().bold(),
        style(format_size(total_size)).green()
    ));
    sp
}

/// Finish a spinner with a success message
pub fn finish_spinner_success(sp: &ProgressBar, msg: &str) {
    sp.set_style(ProgressStyle::with_template("  {msg}").unwrap());
    sp.finish_with_message(format!(
        "{}  {}",
        style("[ok]").green().bold(),
        style(msg).green()
    ));
}

/// Finish a spinner with an error message
#[allow(dead_code)]
pub fn finish_spinner_error(sp: &ProgressBar, msg: &str) {
    sp.set_style(ProgressStyle::with_template("  {msg}").unwrap());
    sp.finish_with_message(format!(
        "{}  {}",
        style("[err]").red().bold(),
        style(msg).red()
    ));
}

// ────────────────────────────────────────────────────────────────
// Transfer progress — multi-bar with per-file + overall
// ────────────────────────────────────────────────────────────────

/// Transfer progress tracking with animated multi-progress bars
pub struct TransferProgress {
    #[allow(dead_code)]
    pub multi: MultiProgress,
    pub overall: ProgressBar,
    pub file_pb: ProgressBar,
    pub status_pb: ProgressBar,
    total_files: u64,
}

impl TransferProgress {
    /// Create a rich multi-progress bar layout for file transfers
    pub fn new(total_size: u64, total_files: u64) -> Self {
        let multi = MultiProgress::new();

        // Status line (top) — shows current phase
        let status_pb = multi.add(ProgressBar::new_spinner());
        status_pb.set_style(
            ProgressStyle::with_template("  {spinner} {msg}")
                .unwrap()
                .tick_strings(SPINNER_TRANSFER),
        );
        status_pb.enable_steady_tick(Duration::from_millis(100));
        status_pb.set_message(format!(
            "{}",
            style("Starting transfer...").cyan()
        ));

        // Per-file progress (middle)
        let file_pb = multi.add(ProgressBar::new(0));
        file_pb.set_style(
            ProgressStyle::with_template(
                "  {spinner:.dim} {msg}"
            )
            .unwrap()
            .tick_strings(&["|", "|", "|", "|"]),
        );
        file_pb.set_message(format!(
            "{}",
            style("Waiting for first file...").dim()
        ));

        // Overall progress bar (bottom) — the main visual
        let overall = multi.add(ProgressBar::new(total_size));
        overall.set_style(
            ProgressStyle::with_template(&format!(
                "  {} [{{elapsed_precise}}] {{wide_bar:.cyan/dark.gray}} {{bytes}}/{{total_bytes}} {} {{bytes_per_sec}} {} {{eta}}",
                style(">>").cyan().bold(),
                style("@").dim(),
                style("~").dim()
            ))
            .unwrap()
            .progress_chars("━━╸─"),
        );

        Self {
            multi,
            overall,
            file_pb,
            status_pb,
            total_files,
        }
    }

    /// Update progress when starting a new file
    pub fn start_file(&self, file_name: &str, file_num: u64, file_size: u64) {
        self.status_pb.set_message(format!(
            "{}  Transferring file {}/{} {}",
            style(">>").cyan().bold(),
            style(file_num).yellow().bold(),
            style(self.total_files).yellow(),
            style(format!("({})", format_size(file_size))).dim()
        ));

        self.file_pb.set_message(format!(
            "  {} {}",
            style("->").cyan(),
            style(truncate_str(file_name, 60)).white().bold()
        ));
    }

    /// Update progress when a file is completed
    pub fn finish_file(&self, file_name: &str, file_num: u64) {
        self.file_pb.set_message(format!(
            "  {} {} {}",
            style("[ok]").green(),
            style(truncate_str(file_name, 50)).green(),
            style(format!("[{}/{}]", file_num, self.total_files)).dim()
        ));
    }

    /// Update overall byte progress
    pub fn set_bytes(&self, bytes: u64) {
        self.overall.set_position(bytes);
    }

    /// Finish all progress bars with a summary
    pub fn finish(&self, files_completed: u64, total_bytes: u64, elapsed_secs: f64) {
        let speed = if elapsed_secs > 0.0 {
            format_size((total_bytes as f64 / elapsed_secs) as u64)
        } else {
            "~".to_string()
        };

        self.status_pb.set_style(ProgressStyle::with_template("  {msg}").unwrap());
        self.status_pb.finish_with_message(format!(
            "{}  {}",
            style("[ok]").green().bold(),
            style("Transfer complete!").green().bold()
        ));

        self.file_pb.set_style(ProgressStyle::with_template("  {msg}").unwrap());
        self.file_pb.finish_with_message(format!(
            "  {} {} files  |  {} transferred  |  {}/s avg",
            style("`-").dim(),
            style(files_completed).white().bold(),
            style(format_size(total_bytes)).white().bold(),
            style(speed).cyan()
        ));

        self.overall.set_style(
            ProgressStyle::with_template(
                "  {wide_bar:.green} {msg}"
            )
            .unwrap()
            .progress_chars("━━╸─"),
        );
        self.overall.finish_with_message(format!(
            "{} in {:.1}s",
            style("100%").green().bold(),
            elapsed_secs
        ));
    }
}

/// Create transfer progress (backwards-compat wrapper)
pub fn create_transfer_progress(total_size: u64, total_files: u64) -> (ProgressBar, ProgressBar) {
    let overall = ProgressBar::new(total_size);
    overall.set_style(
        ProgressStyle::with_template(&format!(
            "  {} [{{elapsed_precise}}] [{{wide_bar:.cyan/dark.gray}}] {{bytes}}/{{total_bytes}} ({{bytes_per_sec}}) {{msg}}",
            style(">>").cyan().bold()
        ))
        .unwrap()
        .progress_chars("━━╸─"),
    );
    overall.set_message(format!("0/{} files", total_files));

    let file_pb = ProgressBar::hidden();

    (overall, file_pb)
}

// ────────────────────────────────────────────────────────────────
// Transfer summary banner
// ────────────────────────────────────────────────────────────────

/// Print a beautiful transfer complete summary
pub fn print_transfer_summary(
    direction: &str,
    files: u64,
    bytes: u64,
    elapsed_secs: f64,
    destination: &str,
) {
    let speed = if elapsed_secs > 0.0 {
        format!("{}/s", format_size((bytes as f64 / elapsed_secs) as u64))
    } else {
        "instant".to_string()
    };

    println!();
    println!("  {}", style("+---------------------------------------------+").green());
    println!("  {}  {}  {}",
        style("|").green(),
        style(format!("[ok] {} Complete", direction)).green().bold(),
        style("                        |").green()
    );
    println!("  {}", style("|---------------------------------------------|").green());
    println!("  {}  {}  {:<38} {}",
        style("|").green(),
        style("Files:").dim(),
        format!("{} file(s)", files),
        style("|").green()
    );
    println!("  {}  {}  {:<38} {}",
        style("|").green(),
        style("Size: ").dim(),
        format_size(bytes),
        style("|").green()
    );
    println!("  {}  {}  {:<38} {}",
        style("|").green(),
        style("Speed:").dim(),
        speed,
        style("|").green()
    );
    println!("  {}  {}  {:<38} {}",
        style("|").green(),
        style("Time: ").dim(),
        format!("{:.2}s", elapsed_secs),
        style("|").green()
    );
    println!("  {}  {}  {:<38} {}",
        style("|").green(),
        style("Dest: ").dim(),
        truncate_str(destination, 38),
        style("|").green()
    );
    println!("  {}", style("+---------------------------------------------+").green());
    println!();
}

// ────────────────────────────────────────────────────────────────
// Device selection
// ────────────────────────────────────────────────────────────────

/// Prompt user to select a device from the list of discovered devices
pub fn select_device(devices: &[DiscoveredDevice]) -> Option<usize> {
    if devices.is_empty() {
        println!();
        println!("  {}  {}", style("[err]").red().bold(), style("No devices found on the network.").red());
        println!("  {}  Make sure the receiver is running: {}",
            style(" ").dim(),
            style("secure-transfer listen").yellow().bold()
        );
        return None;
    }

    let display_items: Vec<String> = devices
        .iter()
        .map(|d| {
            format!(
                "{}  {}  {}:{}  {}  [{}...]",
                style(">>").cyan(),
                style(&d.hostname).white().bold(),
                style(d.ip).yellow(),
                style(d.port).yellow(),
                style("|").dim(),
                style(&d.fingerprint[..std::cmp::min(12, d.fingerprint.len())]).dim()
            )
        })
        .collect();

    println!();
    println!("  {}", style("+-------------------------------------------+").cyan());
    println!("  {}  {}                      {}",
        style("|").cyan(),
        style("Discovered Devices").white().bold(),
        style("|").cyan()
    );
    println!("  {}", style("+-------------------------------------------+").cyan());
    println!();

    Select::new()
        .with_prompt("  Select target device")
        .items(&display_items)
        .default(0)
        .interact_opt()
        .ok()
        .flatten()
}

/// Prompt user to confirm an incoming file transfer
pub fn confirm_transfer(manifest: &TransferManifest) -> std::io::Result<bool> {
    println!();
    println!("  {}", style("+-----------------------------------------------+").cyan());
    println!("  {}  {}  {}",
        style("|").cyan(),
        style("Incoming Transfer").white().bold(),
        style("                            |").cyan()
    );
    println!("  {}", style("|-----------------------------------------------|").cyan());
    println!("  {}  {} {:<42}{}",
        style("|").cyan(),
        style("From: ").dim(),
        style(&manifest.sender_hostname).yellow().bold(),
        style("|").cyan()
    );
    println!("  {}  {} {:<42}{}",
        style("|").cyan(),
        style("Files:").dim(),
        style(format!("{} file(s)", manifest.total_files)).white(),
        style("|").cyan()
    );
    println!("  {}  {} {:<42}{}",
        style("|").cyan(),
        style("Size: ").dim(),
        style(format_size(manifest.total_size)).white().bold(),
        style("|").cyan()
    );
    println!("  {}  {} {:<42}{}",
        style("|").cyan(),
        style("Enc:  ").dim(),
        if manifest.quantum_safe {
            format!("{}", style("[ok] Quantum-Safe (X25519MLKEM768)").green())
        } else {
            format!("{}", style("[!!] Classical TLS only").yellow())
        },
        style("|").cyan()
    );
    println!("  {}", style("+-----------------------------------------------+").cyan());
    println!();

    let accepted = Confirm::new()
        .with_prompt("  Accept transfer?")
        .default(true)
        .interact()
        .unwrap_or(false);

    Ok(accepted)
}

/// Prompt user to confirm a download before receiving files
pub fn confirm_download(manifest: &TransferManifest) -> std::io::Result<bool> {
    println!();
    println!("  {}", style("+-----------------------------------------------+").cyan());
    println!("  {}  {}  {}",
        style("|").cyan(),
        style("Download Summary").white().bold(),
        style("                             |").cyan()
    );
    println!("  {}", style("|-----------------------------------------------|").cyan());
    println!("  {}  {} {:<42}{}",
        style("|").cyan(),
        style("From: ").dim(),
        style(&manifest.sender_hostname).yellow().bold(),
        style("|").cyan()
    );
    println!("  {}  {} {:<42}{}",
        style("|").cyan(),
        style("Files:").dim(),
        style(format!("{} file(s)", manifest.total_files)).white(),
        style("|").cyan()
    );
    println!("  {}  {} {:<42}{}",
        style("|").cyan(),
        style("Size: ").dim(),
        style(format_size(manifest.total_size)).white().bold(),
        style("|").cyan()
    );
    println!("  {}  {} {:<42}{}",
        style("|").cyan(),
        style("Enc:  ").dim(),
        if manifest.quantum_safe {
            format!("{}", style("[ok] Quantum-Safe (X25519MLKEM768)").green())
        } else {
            format!("{}", style("[!!] Classical TLS only").yellow())
        },
        style("|").cyan()
    );
    println!("  {}", style("+-----------------------------------------------+").cyan());
    println!();

    let accepted = Confirm::new()
        .with_prompt("  Start download?")
        .default(true)
        .interact()
        .unwrap_or(false);

    Ok(accepted)
}

/// Interactive file browser for remote devices
pub fn browse_remote_files(
    response: &BrowseResponse,
    selected_so_far: &[String],
) -> std::io::Result<BrowseAction> {
    println!();
    println!("  {}", style("+-----------------------------------------------+").cyan());
    println!("  {}  {}                                    {}",
        style("|").cyan(),
        style("Remote Files").white().bold(),
        style("|").cyan()
    );
    println!("  {}", style("|-----------------------------------------------|").cyan());
    if response.current_path.is_empty() {
        println!("  {}  {} {:<40}{}",
            style("|").cyan(),
            style("Location:").dim(),
            style("/ (shared roots)").yellow(),
            style("|").cyan()
        );
    } else {
        println!(
            "  {}  {} {:<40}{}",
            style("|").cyan(),
            style("Location:").dim(),
            style(truncate_str(&response.current_path, 40)).yellow(),
            style("|").cyan()
        );
    }
    if !selected_so_far.is_empty() {
        println!(
            "  {}  {} {:<40}{}",
            style("|").cyan(),
            style("Selected:").dim(),
            style(format!("{} item(s) [ok]", selected_so_far.len())).green(),
            style("|").cyan()
        );
    }
    println!("  {}", style("+-----------------------------------------------+").cyan());
    println!();

    // Build menu items
    let mut menu_items: Vec<String> = Vec::new();
    let mut action_map: Vec<&str> = Vec::new();

    // Navigation options
    if !response.current_path.is_empty() {
        menu_items.push(format!("{} Go back (parent directory)", style("..").dim()));
        action_map.push("back");
    }

    // File/directory entries
    for entry in &response.entries {
        menu_items.push(format!("  {}", entry));
        action_map.push("entry");
    }

    // Action options
    menu_items.push(format!("{}", style("─────────────────────────────────").dim()));
    action_map.push("separator");

    menu_items.push("[*] Select files to download".to_string());
    action_map.push("select");

    if !selected_so_far.is_empty() {
        menu_items.push(format!(
            "{} Download {} selected item(s)",
            style("[v]").green(),
            style(selected_so_far.len()).green().bold()
        ));
        action_map.push("download");
    }

    menu_items.push("[x] Cancel".to_string());
    action_map.push("quit");

    let selection = Select::new()
        .with_prompt("  Choose action")
        .items(&menu_items)
        .default(0)
        .interact_opt()
        .map_err(std::io::Error::other)?;

    match selection {
        None => Ok(BrowseAction::Quit),
        Some(idx) => {
            match action_map[idx] {
                "back" => Ok(BrowseAction::GoBack),
                "entry" => {
                    let offset = if response.current_path.is_empty() { 0 } else { 1 };
                    let entry_idx = idx - offset;
                    let entry = &response.entries[entry_idx];

                    if entry.is_dir {
                        Ok(BrowseAction::EnterDirectory(entry.relative_path.clone()))
                    } else {
                        Ok(BrowseAction::SelectFiles(vec![entry.relative_path.clone()]))
                    }
                }
                "select" => {
                    let items: Vec<String> = response
                        .entries
                        .iter()
                        .map(|e| format!("{}", e))
                        .collect();

                    if items.is_empty() {
                        println!("  {}  No files to select.", style(">>").dim());
                        return Ok(BrowseAction::GoBack);
                    }

                    let selections = MultiSelect::new()
                        .with_prompt("  Select files/folders (space to toggle, enter to confirm)")
                        .items(&items)
                        .interact()
                        .map_err(std::io::Error::other)?;

                    let paths: Vec<String> = selections
                        .iter()
                        .map(|&i| response.entries[i].relative_path.clone())
                        .collect();

                    Ok(BrowseAction::SelectFiles(paths))
                }
                "download" => Ok(BrowseAction::Download),
                "quit" => Ok(BrowseAction::Quit),
                _ => Ok(BrowseAction::Quit),
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────
// Utilities
// ────────────────────────────────────────────────────────────────

/// Display the certificate fingerprint for verification
#[allow(dead_code)]
pub fn print_fingerprint(fingerprint: &str) {
    println!();
    println!("  {}", style("+----------------------------------------------------+").cyan());
    println!("  {}  {}                             {}",
        style("|").cyan(),
        style("Certificate Fingerprint").white().bold(),
        style("|").cyan()
    );
    println!("  {}", style("|----------------------------------------------------|").cyan());
    println!("  {}  {}  {}", style("|").cyan(), &fingerprint[..48], style("|").cyan());
    println!("  {}  {}          {}", style("|").cyan(), &fingerprint[48..], style("|").cyan());
    println!("  {}", style("+----------------------------------------------------+").cyan());
    println!();
}

/// Format bytes into a human-readable size string (public version)
pub fn format_size_pub(bytes: u64) -> String {
    format_size(bytes)
}

/// Format bytes into a human-readable size string
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

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("...{}", &s[s.len() - (max_len - 3)..])
    }
}

// ────────────────────────────────────────────────────────────────
// Access Control Prompts
// ────────────────────────────────────────────────────────────────

/// Result of an access grant prompt
pub struct AccessDecision {
    pub granted: bool,
    pub scope: AccessScope,
    pub duration: AccessDuration,
}

/// Prompt the user to verify a new receiver's certificate fingerprint (TOFU).
///
/// Used when connecting to a device that isn't in the trusted-peer list and
/// whose fingerprint wasn't obtained via mDNS discovery. The user must
/// confirm out-of-band that the fingerprint shown matches the one displayed
/// on the receiver (similar to SSH host-key verification).
///
/// Returns `true` if the user accepts, `false` if they decline.
pub fn prompt_verify_fingerprint(fingerprint: &str, peer_name: &str) -> std::io::Result<bool> {
    // Show in groups of 8 hex chars for readability, e.g. "a1b2c3d4 e5f6a7b8 …"
    let fp_grouped: String = fingerprint
        .as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ");

    println!();
    println!("  {}", style("+-----------------------------------------------+").yellow());
    println!(
        "  {}  {}  {}",
        style("|").yellow(),
        style("New Device — Verify Fingerprint").white().bold(),
        style("         |").yellow()
    );
    println!("  {}", style("|-----------------------------------------------|").yellow());
    println!(
        "  {}  {} {:<40}{}",
        style("|").yellow(),
        style("Device: ").dim(),
        style(peer_name).cyan().bold(),
        style("|").yellow()
    );
    println!("  {}", style("|-----------------------------------------------|").yellow());
    println!(
        "  {}  {}{}",
        style("|").yellow(),
        style(format!("  {}", &fp_grouped[..fp_grouped.len().min(46)])).dim(),
        style("|").yellow()
    );
    if fp_grouped.len() > 46 {
        println!(
            "  {}  {}{}",
            style("|").yellow(),
            style(format!("  {}", &fp_grouped[46..])).dim(),
            style("|").yellow()
        );
    }
    println!("  {}", style("|-----------------------------------------------|").yellow());
    println!(
        "  {}  {}{}",
        style("|").yellow(),
        style("Verify this fingerprint matches the receiver   ").dim(),
        style("|").yellow()
    );
    println!(
        "  {}  {}{}",
        style("|").yellow(),
        style("before trusting. Once trusted, future          ").dim(),
        style("|").yellow()
    );
    println!(
        "  {}  {}{}",
        style("|").yellow(),
        style("connections will be verified automatically.    ").dim(),
        style("|").yellow()
    );
    println!("  {}", style("+-----------------------------------------------+").yellow());
    println!();

    let confirmed = Confirm::new()
        .with_prompt("  Trust this device?")
        .default(false)
        .interact()
        .map_err(std::io::Error::other)?;

    Ok(confirmed)
}

/// Prompt the user to grant access to an incoming peer connection
///
/// Displays device name, fingerprint, and request type, then offers
/// tiered access options (one-time, persistent, full access, or deny).
pub fn prompt_access_grant(
    peer_name: &str,
    fingerprint: &str,
    request_type: &RequestType,
) -> std::io::Result<AccessDecision> {
    let request_label = match request_type {
        RequestType::Send => "Send Files",
        RequestType::Browse => "Browse Files",
        RequestType::Download => "Download Files",
    };

    let fp_display = if fingerprint.len() > 12 {
        format!("{}...", &fingerprint[..12])
    } else {
        fingerprint.to_string()
    };

    println!();
    println!("  {}", style("+-----------------------------------------------+").yellow());
    println!("  {}  {}  {}",
        style("|").yellow(),
        style("Access Request").white().bold(),
        style("                                |\n").yellow()
    );
    println!("  {}", style("|-----------------------------------------------|").yellow());
    println!("  {}  {} {:<40}{}",
        style("|").yellow(),
        style("Device: ").dim(),
        style(peer_name).cyan().bold(),
        style("|").yellow()
    );
    println!("  {}  {} {:<40}{}",
        style("|").yellow(),
        style("ID:     ").dim(),
        style(&fp_display).dim(),
        style("|").yellow()
    );
    println!("  {}  {} {:<40}{}",
        style("|").yellow(),
        style("Request:").dim(),
        style(request_label).white().bold(),
        style("|").yellow()
    );
    // Option 2 label and scope depend on the request type so we don't save
    // SendOnly scope for a device that is asking to Browse or Download.
    let (opt2_label, opt2_scope) = match request_type {
        RequestType::Browse | RequestType::Download => (
            "Trust this device for browsing & downloads",
            AccessScope::SharedReadOnly,
        ),
        RequestType::Send => (
            "Trust this device for file sends",
            AccessScope::SendOnly,
        ),
    };

    println!("  {}", style("|-----------------------------------------------|").yellow());
    println!("  {}  {}                            {}",
        style("|").yellow(),
        style("1. Allow this request only").white(),
        style("|").yellow()
    );
    println!("  {}  {:<44}{}",
        style("|").yellow(),
        style(format!("2. {}", opt2_label)).white(),
        style("|").yellow()
    );
    println!("  {}  {}{}",
        style("|").yellow(),
        style("3. Trust this device with full access").white(),
        style("  |").yellow()
    );
    println!("  {}  {}                                  {}",
        style("|").yellow(),
        style("4. Deny access").red(),
        style("|").yellow()
    );
    println!("  {}", style("+-----------------------------------------------+").yellow());
    println!();

    let items = vec![
        "Allow this request only",
        opt2_label,
        "Trust this device with full access",
        "Deny access",
    ];

    let selection = Select::new()
        .with_prompt("  Select an access policy")
        .items(&items)
        .default(0)
        .interact()
        .map_err(std::io::Error::other)?;

    let decision = match selection {
        0 => {
            // Accept once — scope matches the current request type
            let scope = match request_type {
                RequestType::Send => AccessScope::SendOnly,
                RequestType::Browse | RequestType::Download => AccessScope::SharedReadOnly,
            };
            AccessDecision {
                granted: true,
                scope,
                duration: AccessDuration::OneTime,
            }
        }
        1 => AccessDecision {
            granted: true,
            scope: opt2_scope,
            duration: AccessDuration::Persistent,
        },
        2 => AccessDecision {
            granted: true,
            scope: AccessScope::FullAccess,
            duration: AccessDuration::Persistent,
        },
        _ => AccessDecision {
            granted: false,
            scope: AccessScope::SendOnly,
            duration: AccessDuration::OneTime,
        },
    };

    if decision.granted {
        println!("  {}  Access approved: {} ({})",
            style("[ok]").green().bold(),
            style(format!("{}", decision.scope)).green(),
            style(format!("{}", decision.duration)).dim()
        );
    } else {
        println!("  {}  Access request denied",
            style("[!!]").red().bold()
        );
    }

    Ok(decision)
}

/// Print a formatted table of trusted devices
pub fn print_trusted_devices(peers: &[(String, crate::config::TrustedPeer)]) {
    if peers.is_empty() {
        println!();
        println!("  {}  {}", style("[info]").cyan().bold(), style("No trusted devices found.").dim());
        println!();
        return;
    }

    println!();
    println!("  {}", style("+--------------------------------------------------------------+").cyan());
    println!("  {}  {}                                                  {}",
        style("|").cyan(),
        style("Trusted Devices").white().bold(),
        style("|").cyan()
    );
    println!("  {}", style("|--------------------------------------------------------------|").cyan());

    for (fingerprint, peer) in peers {
        let fp_short = if fingerprint.len() > 12 {
            format!("{}...", &fingerprint[..12])
        } else {
            fingerprint.clone()
        };

        println!("  {}  {} {:<20} {} {:<14} {} {:<12} {} {:<10} {}",
            style("|").cyan(),
            style("Name:").dim(),
            style(&peer.name).white().bold(),
            style("|").dim(),
            style(&fp_short).dim(),
            style("|").dim(),
            style(format!("{}", peer.scope)).yellow(),
            style("|").dim(),
            style(format!("{}", peer.duration)).dim(),
            style("|").cyan()
        );
    }

    println!("  {}", style("+--------------------------------------------------------------+").cyan());
    println!();
}

pub enum RevokeSelection {
    Device(String),
    All,
    Cancel,
}

/// Prompt the user to select a trusted device to revoke, or revoke all.
pub fn select_device_to_revoke(
    peers: &[(String, crate::config::TrustedPeer)],
) -> std::io::Result<RevokeSelection> {
    if peers.is_empty() {
        println!();
        println!("  {}  {}", style("[info]").cyan().bold(), style("No trusted devices found.").dim());
        println!();
        return Ok(RevokeSelection::Cancel);
    }

    let mut items = vec![format!(
        "{}  {}",
        style("[!]").red().bold(),
        style("Remove access for ALL trusted devices").red()
    )];

    for (fingerprint, peer) in peers {
        let fp_short = if fingerprint.len() > 12 {
            format!("{}...", &fingerprint[..12])
        } else {
            fingerprint.clone()
        };

        items.push(format!(
            "{}  {}  [{}]  {}",
            style(">>").cyan(),
            style(&peer.name).white().bold(),
            style(fp_short).dim(),
            style(format!("{}", peer.scope)).yellow()
        ));
    }

    let selection = Select::new()
        .with_prompt("  Select device access to revoke")
        .items(&items)
        .default(0)
        .interact_opt()
        .map_err(std::io::Error::other)?;

    match selection {
        None => Ok(RevokeSelection::Cancel),
        Some(0) => Ok(RevokeSelection::All),
        Some(idx) => Ok(RevokeSelection::Device(peers[idx - 1].0.clone())),
    }
}

/// Print formatted transaction history
pub fn print_history(records: &[crate::history::TransactionRecord], limit: usize) {
    if records.is_empty() {
        println!();
        println!("  {}  {}", style("[info]").cyan().bold(), style("No transaction history found.").dim());
        println!();
        return;
    }

    let display_records: Vec<_> = records.iter().rev().take(limit).collect();

    println!();
    println!("  {}", style("+----------------------------------------------------------------------+").cyan());
    println!("  {}  {} ({} most recent)                                  {}",
        style("|").cyan(),
        style("Transaction History").white().bold(),
        display_records.len(),
        style("|").cyan()
    );
    println!("  {}", style("|----------------------------------------------------------------------|").cyan());

    for record in &display_records {
        let status_styled = match record.status.as_str() {
            "Success" => style(&record.status).green(),
            "Denied" => style(&record.status).red(),
            _ => style(&record.status).yellow(),
        };

        println!("  {}  {} {} {} {:<12} {} {:<20} {} {:<10} {} {}",
            style("|").cyan(),
            style(&record.timestamp[..19]).dim(),
            style("|").dim(),
            style(&record.action).white().bold(),
            "",
            style("|").dim(),
            truncate_str(&record.peer_name, 20),
            style("|").dim(),
            status_styled,
            style("|").dim(),
            style(format_size_pub(record.bytes_transferred)).dim()
        );
    }

    println!("  {}", style("+----------------------------------------------------------------------+").cyan());
    println!();
}
