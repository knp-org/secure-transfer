# Technical Implementation Plan: Robustness & Security Fixes

This document outlines the plan to address memory exhaustion risks, TLS security bypasses, and UI improvements in the `secure-transfer` project.

## 1. Memory Exhaustion (OOM) Fix
**Issue**: `protocol::compute_file_checksum` reads the entire file into memory using `tokio::fs::read`. This will crash the app for large files.
**Solution**: Re-implement `compute_file_checksum` to use a buffered reader (`tokio::io::BufReader`) and process the file in 64KB chunks.

## 2. TLS Signature Verification Fix
**Issue**: `TofuCertVerifier` returns `Ok(HandshakeSignatureValid::assertion())` without checking signatures.
**Solution**: Enable handshake signature verification. We will use the public key from the validated certificate (whose fingerprint matches our pinned trust) to verify that the peer actually holds the private key.

## 3. UI/UX: Progress Feedback during Hashing
**Issue**: Hashing large files before transfer makes the CLI appear frozen.
**Solution**: Update the hashing function to accept a progress callback. The UI will show a "Hashing..." spinner or progress bar before the actual network transfer starts.

## 4. Virtual Path Mapping (Optional/TBD)
**Issue**: `Browse` exposes absolute host paths.
**Solution**: Implement a mapping system to show virtual paths (e.g., `Shared/Music`) instead of real paths (e.g., `/home/user/Music`).

## Verification Plan
- **Large File Test**: Transfer a 2GB+ file to verify no memory spike.
- **Security Check**: Attempt a MITM or cert-swap to ensure signatures are verified.
- **Unit Tests**: Add tests for incremental hashing in `protocol.rs`.
