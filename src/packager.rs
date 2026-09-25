use crate::crypto;
use crate::envelope::{FileRecord, SigilEnvelope};
use crate::manifest::SigilManifest;
use ed25519_dalek::SigningKey;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use tar::{Builder, Header};
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
    #[error("Verification error: {0}")]
    Verifier(#[from] crate::verifier::VerifierError),
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
    /// Reuses the unified zero-trust verification engine to eliminate parser differential risks.
    pub fn unpack_verified<P: AsRef<Path>, D: AsRef<Path>>(
        package_file: P,
        dest_dir: D,
    ) -> Result<SigilEnvelope, PackagerError> {
        let (_report, envelope) =
            crate::verifier::Verifier::verify_and_extract(package_file, None, Some(dest_dir))?;
        Ok(envelope)
    }
}
