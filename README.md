# secure-transfer

**Quantum-safe secure file transfer over LAN**

A blazing-fast CLI tool for securely transferring files between devices on your local network, protected by post-quantum cryptography.

## Features

- **Auto-Discovery** — Finds devices on your LAN via mDNS (zero-config)
- **Quantum-Safe Encryption** — X25519MLKEM768 hybrid key exchange (NIST FIPS 203)
- **Multi-File & Directory** — Send files, directories, or both recursively
- **Integrity Verification** — SHA-256 checksums for every file
- **Progress Tracking** — Real-time progress bar with transfer speed
- **Trust On First Use** — SSH-like certificate fingerprint verification

## Quick Start

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

## Security

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

## Installation

### One-liner (pre-built binary)
```bash
curl -fsSL https://raw.githubusercontent.com/knp-org/secure-transfer/main/install.sh | sh
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

## Architecture

```
src/
├── main.rs              # Entry point, command dispatch, runtime setup
├── cli.rs               # clap command and subcommand definitions
├── config.rs            # Persistent app config, trust policy, shared paths
├── history.rs           # Transaction history persistence and timestamps
├── ui.rs                # Interactive prompts, status cards, progress output
├── crypto/
│   ├── mod.rs
│   └── certs.rs         # TLS certificate generation and fingerprint helpers
├── discovery/
│   ├── mod.rs
│   ├── advertise.rs     # mDNS advertisement for receivers
│   └── browse.rs        # mDNS browsing and peer discovery
└── transfer/
    ├── mod.rs
    ├── protocol.rs      # Wire protocol frames, manifests, browse/download types
    ├── sender.rs        # Push-based file sending flow
    ├── receiver.rs      # Incoming connection handling and access control
    └── downloader.rs    # Browse-and-pull download flow from remote peers
```

## License

GNU Affero General Public License v3.0 only (AGPL-3.0-only)
