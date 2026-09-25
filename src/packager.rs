use crate::crypto;
use crate::envelope::{FileRecord, SigilEnvelope};
use crate::manifest::SigilManifest;
use ed25519_dalek::SigningKey;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path};
use tar::{Archive, Builder, Header};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Error, Debug)]
pub enum PackagerError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Manifest error: {0}")]
    Manifest(#[from] crate::manifest::ManifestError),
    #[error("Envelope error: {0}")]
    Envelope(#[from] crate::envelope::EnvelopeError),
    #[error("Security violation: path traversal detected: {0}")]
    PathTraversal(String),
    #[error("Integrity check failed: {0}")]
    Integrity(String),
    #[error("Package archive format invalid: {0}")]
    InvalidArchive(String),
    #[error("Security violation: {0}")]
    SecurityViolation(String),
}

/// Strict decompression and size limits to prevent Decompression Bomb (DoS / OOM)
pub const MAX_SINGLE_FILE_SIZE: u64 = 64 * 1024 * 1024; // 64 MB max per file
pub const MAX_TOTAL_UNPACKED_SIZE: u64 = 256 * 1024 * 1024; // 256 MB max cumulative package size
pub const MAX_ENVELOPE_SIZE: u64 = 5 * 1024 * 1024; // 5 MB max envelope metadata

pub struct Packager;

impl Packager {
    /// Builds a deterministic canonical tar.gz of the directory and signs it into an output `.sigil` bundle.
    pub fn pack<P: AsRef<Path>, O: AsRef<Path>>(
        src_dir: P,
        output_file: O,
        signing_key: &SigningKey,
    ) -> Result<SigilEnvelope, PackagerError> {
        let src_dir = src_dir.as_ref();
        let manifest_path = src_dir.join("sigil.toml");
        let manifest = SigilManifest::from_file(&manifest_path)?;

        // Collect all files in deterministic order
        let mut entries = Vec::new();
        for entry in WalkDir::new(src_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                let rel_path = path.strip_prefix(src_dir).unwrap();
                let rel_str = rel_path.to_string_lossy().replace('\\', "/");

                // Skip VCS, artifacts, and output files
                if rel_str.starts_with(".git")
                    || rel_str.starts_with("target")
                    || rel_str.starts_with("node_modules")
                    || rel_str.ends_with(".sigil")
                {
                    continue;
                }
                entries.push((rel_str, path.to_path_buf()));
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        // Calculate individual BLAKE3 hashes and build canonical tar
        let mut file_records = Vec::new();
        let mut tar_buffer = Vec::new();

        {
            let gz = GzEncoder::new(&mut tar_buffer, Compression::best());
            let mut tar = Builder::new(gz);

            for (rel_path, abs_path) in &entries {
                let mut f = File::open(abs_path)?;
                let mut content = Vec::new();
                f.read_to_end(&mut content)?;

                let file_hash = crypto::hash_bytes(&content).to_hex().to_string();
                let size = content.len() as u64;

                file_records.push(FileRecord {
                    path: rel_path.clone(),
                    blake3_hash: file_hash,
                    size_bytes: size,
                });

                // Deterministic tar header: 0 mtime, 0 uid, 0 gid for bitwise reproducibility
                let mut header = Header::new_gnu();
                header.set_size(size);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_uid(0);
                header.set_gid(0);
                header.set_cksum();

                tar.append_data(&mut header, rel_path, &content[..])?;
            }
            tar.into_inner()?.finish()?;
        }

        // Compute BLAKE3 content hash of the reproducible tarball
        let content_hash = crypto::hash_bytes(&tar_buffer).to_hex().to_string();

        // Generate and sign the envelope
        let envelope = SigilEnvelope::sign_and_create(
            manifest,
            content_hash,
            file_records,
            signing_key,
        )?;

        // Package into the final .sigil archive (an outer tar holding envelope.json + content.tar.gz)
        let out_file = File::create(output_file)?;
        let mut bundle_tar = Builder::new(out_file);

        // 1. Append envelope.json
        let envelope_json = serde_json::to_vec_pretty(&envelope)
            .map_err(|e| PackagerError::Envelope(e.into()))?;
        let mut env_header = Header::new_gnu();
        env_header.set_size(envelope_json.len() as u64);
        env_header.set_mode(0o644);
        env_header.set_mtime(0);
        env_header.set_cksum();
        bundle_tar.append_data(&mut env_header, "envelope.sigil.json", &envelope_json[..])?;

        // 2. Append content.tar.gz
        let mut content_header = Header::new_gnu();
        content_header.set_size(tar_buffer.len() as u64);
        content_header.set_mode(0o644);
        content_header.set_mtime(0);
        content_header.set_cksum();
        bundle_tar.append_data(&mut content_header, "content.tar.gz", &tar_buffer[..])?;

        bundle_tar.finish()?;
        Ok(envelope)
    }

    /// Safely unpacks a verified package archive into the destination directory.
    /// Strictly protects against Path Traversal, symlink escapes, decompression bombs, and tampering.
    pub fn unpack_verified<P: AsRef<Path>, D: AsRef<Path>>(
        package_file: P,
        dest_dir: D,
    ) -> Result<SigilEnvelope, PackagerError> {
        let dest_dir = dest_dir.as_ref();
        let file = File::open(package_file)?;
        let mut bundle_archive = Archive::new(file);

        let mut envelope_bytes = None;
        let mut content_tar_bytes = None;

        for entry in bundle_archive.entries()? {
            let entry = entry?;
            let path_str = entry.path()?.to_string_lossy().to_string();

            if path_str == "envelope.sigil.json" {
                let mut buf = Vec::new();
                entry.take(MAX_ENVELOPE_SIZE + 1).read_to_end(&mut buf)?;
                if buf.len() as u64 > MAX_ENVELOPE_SIZE {
                    return Err(PackagerError::SecurityViolation(
                        "Envelope size exceeds maximum allowed threshold".into(),
                    ));
                }
                envelope_bytes = Some(buf);
            } else if path_str == "content.tar.gz" {
                let mut buf = Vec::new();
                entry.take(MAX_TOTAL_UNPACKED_SIZE + 1).read_to_end(&mut buf)?;
                if buf.len() as u64 > MAX_TOTAL_UNPACKED_SIZE {
                    return Err(PackagerError::SecurityViolation(
                        "Compressed content exceeds maximum size threshold".into(),
                    ));
                }
                content_tar_bytes = Some(buf);
            }
        }

        let envelope_bytes = envelope_bytes.ok_or_else(|| {
            PackagerError::InvalidArchive("Missing envelope.sigil.json in package".into())
        })?;
        let content_tar_bytes = content_tar_bytes.ok_or_else(|| {
            PackagerError::InvalidArchive("Missing content.tar.gz in package".into())
        })?;

        let envelope: SigilEnvelope = serde_json::from_slice(&envelope_bytes)
            .map_err(|e| PackagerError::Envelope(e.into()))?;

        // 1. Verify cryptographic signature of the envelope itself
        envelope
            .verify_signature()
            .map_err(|e| PackagerError::SecurityViolation(format!("Cryptographic signature invalid: {}", e)))?;

        // 2. Verify bit-for-bit content tarball hash
        let computed_content_hash = crypto::hash_bytes(&content_tar_bytes).to_hex().to_string();
        if computed_content_hash != envelope.content_hash {
            return Err(PackagerError::Integrity(format!(
                "Content hash mismatch! Expected: {}, Found: {}",
                envelope.content_hash, computed_content_hash
            )));
        }

        // 3. Create destination directory
        fs::create_dir_all(dest_dir)?;

        let mut envelope_file_map: HashMap<String, &FileRecord> = HashMap::new();
        for file_rec in &envelope.files {
            envelope_file_map.insert(file_rec.path.clone(), file_rec);
        }

        // 4. Unpack content.tar.gz safely with strict zero-trust sandbox rules
        let gz = GzDecoder::new(&content_tar_bytes[..]);
        let mut inner_tar = Archive::new(gz);

        let mut total_unpacked_bytes: u64 = 0;
        let mut extracted_files = HashSet::new();

        for entry in inner_tar.entries()? {
            let mut entry = entry?;
            let entry_type = entry.header().entry_type();

            // Zero-Trust Sandbox: Strictly forbid symlinks and hardlinks
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                return Err(PackagerError::SecurityViolation(format!(
                    "Symlinks and hardlinks are strictly prohibited in Sigil packages: {:?}",
                    entry.path()?
                )));
            }

            if !entry_type.is_file() && !entry_type.is_dir() {
                return Err(PackagerError::SecurityViolation(format!(
                    "Unsupported archive entry type in package: {:?}",
                    entry_type
                )));
            }

            let entry_path = entry.path()?.to_path_buf();
            let rel_str = entry_path.to_string_lossy().replace('\\', "/");

            if rel_str.contains(':') || rel_str.contains('\0') {
                return Err(PackagerError::PathTraversal(format!(
                    "Illegal path characters detected: '{}'",
                    rel_str
                )));
            }

            for comp in entry_path.components() {
                match comp {
                    Component::ParentDir => {
                        return Err(PackagerError::PathTraversal(format!(
                            "Parent directory traversal ('..') detected: {:?}",
                            entry_path
                        )));
                    }
                    Component::Prefix(_) | Component::RootDir => {
                        return Err(PackagerError::PathTraversal(format!(
                            "Absolute path detected: {:?}",
                            entry_path
                        )));
                    }
                    _ => {}
                }
            }

            let target_path = dest_dir.join(&entry_path);

            if entry_type.is_dir() {
                fs::create_dir_all(&target_path)?;
                continue;
            }

            // Regular file: size limit check to prevent Decompression Bomb (Tar Bomb / OOM)
            let declared_size = entry.size();
            if declared_size > MAX_SINGLE_FILE_SIZE {
                return Err(PackagerError::SecurityViolation(format!(
                    "File '{}' exceeds maximum allowed size ({} > {})",
                    rel_str, declared_size, MAX_SINGLE_FILE_SIZE
                )));
            }

            let mut content = Vec::new();
            let mut limited = (&mut entry).take(MAX_SINGLE_FILE_SIZE + 1);
            limited.read_to_end(&mut content)?;

            if content.len() as u64 > MAX_SINGLE_FILE_SIZE {
                return Err(PackagerError::SecurityViolation(format!(
                    "File '{}' exceeded maximum allowed size during extraction (potential decompression bomb)",
                    rel_str
                )));
            }

            total_unpacked_bytes += content.len() as u64;
            if total_unpacked_bytes > MAX_TOTAL_UNPACKED_SIZE {
                return Err(PackagerError::SecurityViolation(format!(
                    "Cumulative package size exceeded maximum threshold ({} bytes)",
                    MAX_TOTAL_UNPACKED_SIZE
                )));
            }

            // Verify individual file content hash against envelope file record
            let file_hash = crypto::hash_bytes(&content).to_hex().to_string();
            if let Some(expected_record) = envelope_file_map.get(&rel_str) {
                if expected_record.blake3_hash != file_hash {
                    return Err(PackagerError::Integrity(format!(
                        "File hash mismatch for '{}'! Expected: {}, Found: {}",
                        rel_str, expected_record.blake3_hash, file_hash
                    )));
                }
                extracted_files.insert(rel_str.clone());
            } else {
                return Err(PackagerError::Integrity(format!(
                    "Archive contains unexpected file '{}' not listed in signed envelope",
                    rel_str
                )));
            }

            // Ensure parent directory exists
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut out_file = File::create(&target_path)?;
            out_file.write_all(&content)?;
        }

        // Verify that all files listed in the signed envelope were present in the payload
        for expected in &envelope.files {
            if !extracted_files.contains(&expected.path) {
                return Err(PackagerError::Integrity(format!(
                    "Expected file '{}' was missing from package payload",
                    expected.path
                )));
            }
        }

        Ok(envelope)
    }
}
