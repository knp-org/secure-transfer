# 🛡️ secure-transfer

**Quantum-safe secure file transfer over LAN**

A blazing-fast CLI tool for securely transferring files between devices on your local network, protected by post-quantum cryptography.

## ✨ Features

- **🔍 Auto-Discovery** — Finds devices on your LAN via mDNS (zero-config)
- **🛡️ Quantum-Safe Encryption** — X25519MLKEM768 hybrid key exchange (NIST FIPS 203)
- **📁 Multi-File & Directory** — Send files, directories, or both recursively
- **✅ Integrity Verification** — SHA-256 checksums for every file
- **📊 Progress Tracking** — Real-time progress bar with transfer speed
- **🔒 Trust On First Use** — SSH-like certificate fingerprint verification

## 🚀 Quick Start

### Receiver (machine that accepts files)
```bash
# Start listening with defaults (port 9876, saves to ~/Downloads/secure-transfer/)
secure-transfer listen

# Custom port and save directory
secure-transfer listen --port 8888 --save-dir /tmp/received
```

### Sender (machine that sends files)
```bash
# Send a single file (interactive device selection)
secure-transfer send ./document.pdf

# Send multiple files
secure-transfer send ./photo.jpg ./video.mp4 ./report.docx

# Send an entire directory (recursively)
secure-transfer send ./my-project/

# Mix files and folders
secure-transfer send ./src/ ./README.md ./Cargo.toml

# Send directly to a known IP (skip discovery)
secure-transfer send ./file.txt --to 192.168.1.42:9876
```

## 🔐 Security

### Quantum-Safe Key Exchange
All connections use **X25519MLKEM768** — a hybrid key exchange combining:
- **X25519** (classical elliptic curve Diffie-Hellman)
- **ML-KEM-768** (NIST FIPS 203, formerly Kyber768)

This provides defense-in-depth against both classical and quantum computer attacks.

### Certificate Trust Model
On first run, the app generates a self-signed TLS certificate stored in `~/.config/secure-transfer/`. Certificate fingerprints are verified using a Trust-On-First-Use (TOFU) model, similar to SSH.

### Wire Protocol
```
┌──────────────────────────────────────────────┐
│  Quantum-Safe TLS 1.3 Encrypted TCP Stream   │
│  Key Exchange: X25519MLKEM768 (hybrid)       │
│  Cipher: AES-256-GCM / ChaCha20-Poly1305    │
├──────────────────────────────────────────────┤
│  Manifest (file count, total size)           │
│  Per-file: Header → Data chunks → Ack       │
│  Final transfer summary                     │
└──────────────────────────────────────────────┘
```

## 📦 Installation

### One-liner (pre-built binary)
```bash
curl -fsSL https://raw.githubusercontent.com/knp-org/secure-transfer/main/install.sh | sh
```

### From crates.io
```bash
cargo install secure-transfer
```

### From GitHub (source)
```bash
cargo install --git https://github.com/knp-org/secure-transfer
```

### From Source (local)
```bash
git clone https://github.com/knp-org/secure-transfer.git
cd secure-transfer
cargo install --path .
```

### Requirements
- Pre-built binaries: Linux (x86_64, aarch64), macOS (x86_64, aarch64)
- From source: Rust 1.75+
- Both sender and receiver must be on the same local network

## 🏗️ Architecture

```
src/
├── main.rs              # Entry point, CLI dispatch
├── cli.rs               # clap command definitions
├── config.rs            # App config & cert storage
├── ui.rs                # Interactive prompts & progress
├── crypto/
│   ├── mod.rs
│   └── certs.rs         # TLS cert gen & quantum-safe config
├── discovery/
│   ├── mod.rs
│   ├── advertise.rs     # mDNS service registration
│   └── browse.rs        # mDNS device browsing
└── transfer/
    ├── mod.rs
    ├── protocol.rs      # Wire protocol frames
    ├── sender.rs        # File sending logic
    └── receiver.rs      # File receiving logic
```

## 📄 License

GNU Affero General Public License v3.0 only (AGPL-3.0-only)
