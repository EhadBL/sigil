use crate::crypto::{self, CryptoError};
use crate::envelope::{FileRecord, SigilEnvelope};
use crate::manifest::Capabilities;
use crate::packager::{MAX_ENVELOPE_SIZE, MAX_SINGLE_FILE_SIZE, MAX_TOTAL_UNPACKED_SIZE};
use flate2::read::GzDecoder;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path};
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
    #[error("Security violation: {0}")]
    SecurityViolation(String),
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
    /// Performs a full zero-trust cryptographic audit of a `.sigil` package without unpacking.
    pub fn verify_package<P: AsRef<Path>>(
        package_file: P,
        expected_pubkey: Option<&str>,
    ) -> Result<VerificationReport, VerifierError> {
        Self::verify_and_extract::<_, &Path>(package_file, expected_pubkey, None).map(|(report, _)| report)
    }

    /// Single unified zero-trust verification and sandboxed extraction engine.
    /// Eliminates parser differential vulnerabilities by sharing identical verification and extraction logic.
    pub fn verify_and_extract<P: AsRef<Path>, D: AsRef<Path>>(
        package_file: P,
        expected_pubkey: Option<&str>,
        dest_dir: Option<D>,
    ) -> Result<(VerificationReport, SigilEnvelope), VerifierError> {
        let file = File::open(package_file)?;
        let mut bundle = Archive::new(file);

        let mut envelope_bytes = None;
        let mut content_tar_bytes = None;

        for entry in bundle.entries()? {
            let entry = entry?;
            let path_str = entry.path()?.to_string_lossy().to_string();

            if path_str == "envelope.sigil.json" {
                let mut buf = Vec::new();
                entry.take(MAX_ENVELOPE_SIZE + 1).read_to_end(&mut buf)?;
                if buf.len() as u64 > MAX_ENVELOPE_SIZE {
                    return Err(VerifierError::SecurityViolation(
                        "Envelope size exceeds maximum allowed threshold".into(),
                    ));
                }
                envelope_bytes = Some(buf);
            } else if path_str == "content.tar.gz" {
                let mut buf = Vec::new();
                entry.take(MAX_TOTAL_UNPACKED_SIZE + 1).read_to_end(&mut buf)?;
                if buf.len() as u64 > MAX_TOTAL_UNPACKED_SIZE {
                    return Err(VerifierError::SecurityViolation(
                        "Compressed content exceeds maximum size threshold".into(),
                    ));
                }
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
                    actual: envelope.author_pubkey.clone(),
                    expected: expected.to_string(),
                });
            }
        }

        // 2. Cryptographic Signature Verification (Ed25519 over Canonical Payload including Dependencies)
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

        // 4. File-by-File Hash & Tree Merkle Root Verification + Optional Sandboxed Extraction
        if let Some(ref dest) = dest_dir {
            fs::create_dir_all(dest.as_ref())?;
        }

        let gz = GzDecoder::new(&content_tar_bytes[..]);
        let mut inner_tar = Archive::new(gz);

        let mut extracted_records = Vec::new();
        let mut total_unpacked_bytes: u64 = 0;

        for entry in inner_tar.entries()? {
            let mut entry = entry?;
            let entry_type = entry.header().entry_type();

            // Zero-Trust Sandbox Invariant: Reject symlinks and hardlinks
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                return Err(VerifierError::SecurityViolation(format!(
                    "Forbidden symlink or hardlink entry detected in package: {:?}",
                    entry.path()?
                )));
            }

            if entry_type.is_dir() {
                if let Some(ref dest) = dest_dir {
                    let target_dir = dest.as_ref().join(entry.path()?);
                    fs::create_dir_all(&target_dir)?;
                }
                continue;
            }

            if !entry_type.is_file() {
                return Err(VerifierError::SecurityViolation(format!(
                    "Unsupported archive entry type in package: {:?}",
                    entry_type
                )));
            }

            let entry_path = entry.path()?.to_path_buf();
            let rel_path = entry_path.to_string_lossy().replace('\\', "/");

            if rel_path.contains(':') || rel_path.contains('\0') {
                return Err(VerifierError::SecurityViolation(format!(
                    "Illegal path characters detected in package: '{}'",
                    rel_path
                )));
            }

            for comp in entry_path.components() {
                match comp {
                    Component::ParentDir => {
                        return Err(VerifierError::SecurityViolation(format!(
                            "Parent directory traversal ('..') detected: {:?}",
                            entry_path
                        )));
                    }
                    Component::Prefix(_) | Component::RootDir => {
                        return Err(VerifierError::SecurityViolation(format!(
                            "Absolute path detected in package: {:?}",
                            entry_path
                        )));
                    }
                    _ => {}
                }
            }

            let declared_size = entry.size();
            if declared_size > MAX_SINGLE_FILE_SIZE {
                return Err(VerifierError::SecurityViolation(format!(
                    "File '{}' exceeds maximum allowed size ({} > {})",
                    rel_path, declared_size, MAX_SINGLE_FILE_SIZE
                )));
            }

            let mut file_content = Vec::new();
            let mut limited = (&mut entry).take(MAX_SINGLE_FILE_SIZE + 1);
            limited.read_to_end(&mut file_content)?;

            if file_content.len() as u64 > MAX_SINGLE_FILE_SIZE {
                return Err(VerifierError::SecurityViolation(format!(
                    "File '{}' exceeded maximum allowed size during verification (potential decompression bomb)",
                    rel_path
                )));
            }

            total_unpacked_bytes += file_content.len() as u64;
            if total_unpacked_bytes > MAX_TOTAL_UNPACKED_SIZE {
                return Err(VerifierError::SecurityViolation(format!(
                    "Cumulative package size exceeded maximum threshold ({} bytes)",
                    MAX_TOTAL_UNPACKED_SIZE
                )));
            }

            let file_hash = crypto::hash_bytes(&file_content).to_hex().to_string();
            let size = file_content.len() as u64;

            extracted_records.push(FileRecord {
                path: rel_path.clone(),
                blake3_hash: file_hash,
                size_bytes: size,
            });

            // Extract file safely if destination directory is provided
            if let Some(ref dest) = dest_dir {
                let target_path = dest.as_ref().join(&entry_path);
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut out_file = File::create(&target_path)?;
                out_file.write_all(&file_content)?;
            }
        }
        extracted_records.sort_by(|a, b| a.path.cmp(&b.path));

        // Recompute Merkle tree root hash
        let computed_tree_root = crate::merkle::compute_files_merkle_tree(&extracted_records).root_hex();

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

        let report = VerificationReport {
            is_valid: true,
            package_name: envelope.manifest.package.name.clone(),
            version: envelope.manifest.package.version.clone(),
            author_pubkey: envelope.author_pubkey.clone(),
            content_hash: envelope.content_hash.clone(),
            tree_root_hash: envelope.tree_root_hash.clone(),
            total_files: extracted_records.len(),
            timestamp: envelope.timestamp,
            capabilities: envelope.manifest.capabilities.clone(),
        };

        Ok((report, envelope))
    }
}
