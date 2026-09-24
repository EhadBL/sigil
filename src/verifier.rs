use crate::crypto::{self, CryptoError};
use crate::envelope::{FileRecord, SigilEnvelope};
use crate::manifest::Capabilities;
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tar::Archive;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifierError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Crypto verification failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Tampered content: {0}")]
    Tampered(String),
    #[error("Key mismatch: Package signed by {actual}, expected {expected}")]
    KeyMismatch { actual: String, expected: String },
    #[error("Archive format error: {0}")]
    Archive(String),
}

#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub is_valid: bool,
    pub package_name: String,
    pub version: String,
    pub author_pubkey: String,
    pub content_hash: String,
    pub tree_root_hash: String,
    pub total_files: usize,
    pub timestamp: i64,
    pub capabilities: Capabilities,
}

pub struct Verifier;

impl Verifier {
    /// Performs a full zero-trust cryptographic audit and verification of a `.sigil` package.
    pub fn verify_package<P: AsRef<Path>>(
        package_file: P,
        expected_pubkey: Option<&str>,
    ) -> Result<VerificationReport, VerifierError> {
        let file = File::open(package_file)?;
        let mut bundle = Archive::new(file);

        let mut envelope_bytes = None;
        let mut content_tar_bytes = None;

        for entry in bundle.entries()? {
            let mut entry = entry?;
            let path_str = entry.path()?.to_string_lossy().to_string();

            if path_str == "envelope.sigil.json" {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                envelope_bytes = Some(buf);
            } else if path_str == "content.tar.gz" {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                content_tar_bytes = Some(buf);
            }
        }

        let envelope_bytes = envelope_bytes.ok_or_else(|| {
            VerifierError::Archive("Missing envelope.sigil.json in package archive".into())
        })?;
        let content_tar_bytes = content_tar_bytes.ok_or_else(|| {
            VerifierError::Archive("Missing content.tar.gz in package archive".into())
        })?;

        let envelope: SigilEnvelope = serde_json::from_slice(&envelope_bytes)?;

        // 1. Author Public Key Check (if expected publisher key is enforced)
        if let Some(expected) = expected_pubkey {
            if envelope.author_pubkey != expected {
                return Err(VerifierError::KeyMismatch {
                    actual: envelope.author_pubkey,
                    expected: expected.to_string(),
                });
            }
        }

        // 2. Cryptographic Signature Verification (Ed25519)
        envelope
            .verify_signature()
            .map_err(|e| VerifierError::Tampered(format!("Invalid Ed25519 signature: {}", e)))?;

        // 3. Bit-for-bit Content Hash Verification (BLAKE3)
        let computed_content_hash = crypto::hash_bytes(&content_tar_bytes).to_hex().to_string();
        if computed_content_hash != envelope.content_hash {
            return Err(VerifierError::Tampered(format!(
                "Content tarball has been tampered with! Expected hash {}, got {}",
                envelope.content_hash, computed_content_hash
            )));
        }

        // 4. File-by-File Hash & Tree Merkle Root Verification
        let gz = GzDecoder::new(&content_tar_bytes[..]);
        let mut inner_tar = Archive::new(gz);

        let mut extracted_records = Vec::new();
        for entry in inner_tar.entries()? {
            let mut entry = entry?;
            let rel_path = entry.path()?.to_string_lossy().replace('\\', "/");
            let mut file_content = Vec::new();
            entry.read_to_end(&mut file_content)?;

            let file_hash = crypto::hash_bytes(&file_content).to_hex().to_string();
            let size = file_content.len() as u64;

            extracted_records.push(FileRecord {
                path: rel_path,
                blake3_hash: file_hash,
                size_bytes: size,
            });
        }
        extracted_records.sort_by(|a, b| a.path.cmp(&b.path));

        // Recompute Merkle tree root hash
        let mut tree_hasher = blake3::Hasher::new();
        for file in &extracted_records {
            tree_hasher.update(file.path.as_bytes());
            tree_hasher.update(b":");
            tree_hasher.update(file.blake3_hash.as_bytes());
            tree_hasher.update(b";");
        }
        let computed_tree_root = tree_hasher.finalize().to_hex().to_string();

        if computed_tree_root != envelope.tree_root_hash {
            return Err(VerifierError::Tampered(format!(
                "Merkle tree root mismatch! Expected {}, recomputed {}",
                envelope.tree_root_hash, computed_tree_root
            )));
        }

        // 5. Compare with Envelope's listed files
        if extracted_records != envelope.files {
            return Err(VerifierError::Tampered(
                "Internal files list does not match envelope records".into(),
            ));
        }

        Ok(VerificationReport {
            is_valid: true,
            package_name: envelope.manifest.package.name,
            version: envelope.manifest.package.version,
            author_pubkey: envelope.author_pubkey,
            content_hash: envelope.content_hash,
            tree_root_hash: envelope.tree_root_hash,
            total_files: extracted_records.len(),
            timestamp: envelope.timestamp,
            capabilities: envelope.manifest.capabilities,
        })
    }
}
