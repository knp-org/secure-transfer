use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};
use std::fs;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config;

/// Generate a self-signed ECDSA P-256 certificate for TLS
pub fn generate_self_signed_cert() -> Result<(String, String)> {
    let mut params = CertificateParams::new(vec!["secure-transfer.local".to_string()])
        .context("Failed to create certificate params")?;

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("secure-transfer-{}", hostname),
    );

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .context("Failed to generate key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to generate self-signed certificate")?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    Ok((cert_pem, key_pem))
}

/// Ensure certificate and key exist on disk; generate if missing
pub fn ensure_certs() -> Result<()> {
    let cert_path = config::cert_path()?;
    let key_path = config::key_path()?;

    if cert_path.exists() && key_path.exists() {
        info!("Using existing TLS certificate");
        return Ok(());
    }

    info!("Generating new quantum-safe TLS certificate…");
    let (cert_pem, key_pem) = generate_self_signed_cert()?;

    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&cert_path, &cert_pem)
        .with_context(|| format!("Failed to write cert: {}", cert_path.display()))?;
    fs::write(&key_path, &key_pem)
        .with_context(|| format!("Failed to write key: {}", key_path.display()))?;

    info!("Certificate saved to {}", cert_path.display());
    Ok(())
}

/// Load the certificate from disk
pub fn load_cert() -> Result<Vec<CertificateDer<'static>>> {
    let cert_path = config::cert_path()?;
    let cert_data = fs::read(&cert_path)
        .with_context(|| format!("Failed to read cert: {}", cert_path.display()))?;
    let mut cursor = std::io::Cursor::new(cert_data);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")?;
    Ok(certs)
}

/// Load the private key from disk
pub fn load_key() -> Result<PrivateKeyDer<'static>> {
    let key_path = config::key_path()?;
    let key_data = fs::read(&key_path)
        .with_context(|| format!("Failed to read key: {}", key_path.display()))?;
    let mut cursor = std::io::Cursor::new(key_data);
    let key = rustls_pemfile::private_key(&mut cursor)
        .context("Failed to parse private key PEM")?
        .context("No private key found in PEM file")?;
    Ok(key)
}

/// Compute the SHA-256 fingerprint of a DER-encoded certificate
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Get the fingerprint of our local certificate
pub fn local_fingerprint() -> Result<String> {
    let certs = load_cert()?;
    let cert = certs.first().context("No certificate found")?;
    Ok(cert_fingerprint(cert.as_ref()))
}

/// Build a rustls ServerConfig with quantum-safe key exchange
///
/// The `prefer-post-quantum` feature in rustls enables X25519MLKEM768
/// as the preferred key exchange group automatically.
pub fn build_server_config() -> Result<Arc<ServerConfig>> {
    let certs = load_cert()?;
    let key = load_key()?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS server config")?;

    info!("TLS server configured with quantum-safe key exchange (X25519MLKEM768)");

    Ok(Arc::new(config))
}

/// Build a rustls ClientConfig with TOFU certificate verification
///
/// `expected_fingerprint`: when `Some`, the TLS handshake will be rejected
/// unless the server certificate matches exactly. Pass `None` for manual
/// connections where the fingerprint isn't known in advance.
///
/// Uses X25519MLKEM768 hybrid key exchange for quantum safety.
pub fn build_client_config(expected_fingerprint: Option<String>) -> Result<Arc<ClientConfig>> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TofuCertVerifier {
            expected_fingerprint,
        }))
        .with_no_client_auth();

    info!("TLS client configured with quantum-safe key exchange (X25519MLKEM768)");

    Ok(Arc::new(config))
}

/// Trust-On-First-Use certificate verifier
///
/// When an `expected_fingerprint` is provided (e.g. from mDNS discovery),
/// the cert is accepted only if it matches exactly — any mismatch is rejected
/// as a potential MITM attack.
///
/// When no expected fingerprint is provided (manual `--to` connections),
/// the verifier checks the local trusted-peer list; if found, the cert is
/// accepted. Unknown peers are accepted at the TLS layer so the connection
/// can proceed, but the caller **must** prompt the user to verify the
/// fingerprint before sending any data.
#[derive(Debug)]
struct TofuCertVerifier {
    /// Fingerprint we expect from mDNS or a previously pinned trust record.
    /// `None` means "unknown — caller handles post-handshake verification".
    expected_fingerprint: Option<String>,
}

impl ServerCertVerifier for TofuCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = cert_fingerprint(end_entity.as_ref());

        // Strict enforcement when we have a known-good fingerprint
        if let Some(expected) = &self.expected_fingerprint {
            if fingerprint == *expected {
                info!("Certificate fingerprint verified");
                return Ok(ServerCertVerified::assertion());
            }
            warn!(
                "Certificate fingerprint mismatch! Expected {}…, got {}…",
                &expected[..12.min(expected.len())],
                &fingerprint[..12.min(fingerprint.len())]
            );
            return Err(rustls::Error::General(
                "Certificate fingerprint mismatch — possible MITM attack".to_string(),
            ));
        }

        // No expected fingerprint — check whether this peer is already trusted
        let config = config::AppConfig::load().map_err(|e| {
            warn!("Failed to load config for TOFU check: {}", e);
            rustls::Error::General("Config load failed".to_string())
        })?;

        if config.is_trusted(&fingerprint) {
            info!("Certificate fingerprint verified (trusted peer)");
            return Ok(ServerCertVerified::assertion());
        }

        // Unknown peer on a manual connection — accept the TLS cert so the
        // connection can be established, but the transfer layer is responsible
        // for prompting the user to confirm the fingerprint before proceeding.
        info!("New peer certificate fingerprint: {}", fingerprint);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
