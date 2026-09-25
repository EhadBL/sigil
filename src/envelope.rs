use crate::crypto::{self, CryptoError};
use crate::manifest::{Capabilities, SigilManifest};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EnvelopeError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Envelope validation error: {0}")]
    Validation(String),
}

/// An entry describing a single file inside the package payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileRecord {
    pub path: String,
    pub blake3_hash: String,
    pub size_bytes: u64,
}

/// The Cryptographic Envelope that accompanies every `.sigil` package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigilEnvelope {
    pub manifest: SigilManifest,
    /// BLAKE3 hash of the tarball payload
    pub content_hash: String,
    /// BLAKE3 Merkle root computed over the canonical list of files
    pub tree_root_hash: String,
    /// Canonical file manifest with individual hashes
    pub files: Vec<FileRecord>,
    /// Unix timestamp when the package was signed
    pub timestamp: i64,
    /// Hex-encoded Ed25519 public key of the publisher
    pub author_pubkey: String,
    /// Hex-encoded Ed25519 signature
    pub signature: String,
}

impl SigilEnvelope {
    /// Constructs a canonical byte slice to be signed or verified.
    /// This prevents signature malleability and ensures zero-trust authenticity.
    pub fn canonical_payload(
        name: &str,
        version: &str,
        content_hash: &str,
        tree_root_hash: &str,
        timestamp: i64,
        author_pubkey: &str,
        capabilities: &Capabilities,
    ) -> Result<Vec<u8>, EnvelopeError> {
        // Deterministic JSON map representation
        let mut map = BTreeMap::new();
        map.insert("name", serde_json::to_value(name)?);
        map.insert("version", serde_json::to_value(version)?);
        map.insert("content_hash", serde_json::to_value(content_hash)?);
        map.insert("tree_root_hash", serde_json::to_value(tree_root_hash)?);
        map.insert("timestamp", serde_json::to_value(timestamp)?);
        map.insert("author_pubkey", serde_json::to_value(author_pubkey)?);
        map.insert("capabilities", serde_json::to_value(capabilities)?);

        let canonical_bytes = serde_json::to_vec(&map)?;
        Ok(canonical_bytes)
    }

    /// Signs and creates a new SigilEnvelope
    pub fn sign_and_create(
        manifest: SigilManifest,
        content_hash: String,
        mut files: Vec<FileRecord>,
        signing_key: &SigningKey,
    ) -> Result<Self, EnvelopeError> {
        let verifying_key = signing_key.verifying_key();
        let author_pubkey = crypto::export_verifying_key_hex(&verifying_key);
        let timestamp = chrono::Utc::now().timestamp();

        // Sort files canonically by path for deterministic tree calculation
        files.sort_by(|a, b| a.path.cmp(&b.path));

        // Compute genuine binary Merkle tree root hash over all canonical file records
        let tree_root_hash = crate::merkle::compute_files_merkle_tree(&files).root_hex();

        let canonical = Self::canonical_payload(
            &manifest.package.name,
            &manifest.package.version,
            &content_hash,
            &tree_root_hash,
            timestamp,
            &author_pubkey,
            &manifest.capabilities,
        )?;

        let signature = crypto::sign_payload(signing_key, &canonical);

        Ok(Self {
            manifest,
            content_hash,
            tree_root_hash,
            files,
            timestamp,
            author_pubkey,
            signature,
        })
    }

    /// Verifies the internal consistency and cryptographic signature of the envelope.
    pub fn verify_signature(&self) -> Result<(), EnvelopeError> {
        let verifying_key: VerifyingKey = crypto::import_verifying_key_hex(&self.author_pubkey)?;

        let canonical = Self::canonical_payload(
            &self.manifest.package.name,
            &self.manifest.package.version,
            &self.content_hash,
            &self.tree_root_hash,
            self.timestamp,
            &self.author_pubkey,
            &self.manifest.capabilities,
        )?;

        crypto::verify_signature(&verifying_key, &canonical, &self.signature)?;
        Ok(())
    }
}
