use crate::lockfile::SigilLockfile;
use crate::merkle::MerkleInclusionProof;
use crate::packager::Packager;
use crate::trust::TrustStore;
use crate::verifier::Verifier;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Verification error: {0}")]
    Verifier(#[from] crate::verifier::VerifierError),
    #[error("Packaging/unpacking error: {0}")]
    Packager(#[from] crate::packager::PackagerError),
    #[error("Lockfile error: {0}")]
    Lockfile(#[from] crate::lockfile::LockfileError),
    #[error("Registry error: {0}")]
    Registry(String),
    #[error("Untrusted publisher key {pubkey} for package {package}! Run 'sigil trust add' to approve.")]
    UntrustedPublisher { pubkey: String, package: String },
    #[error("Security alert: {0}")]
    SecurityAlert(String),
}

pub struct SigilClient {
    pub registry_url: String,
    http: reqwest::Client,
}

impl SigilClient {
    pub fn new(registry_url: &str) -> Self {
        Self {
            registry_url: registry_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder().build().unwrap(),
        }
    }

    /// Publishes a cryptographically signed .sigil package file to the remote registry
    pub async fn publish<P: AsRef<Path>>(&self, package_path: P) -> Result<serde_json::Value, ClientError> {
        let package_path = package_path.as_ref();
        let bytes = fs::read(package_path)?;

        let url = format!("{}/api/v1/publish", self.registry_url);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(bytes)
            .send()
            .await?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_else(|_| "Unknown error".into());
            return Err(ClientError::Registry(error_text));
        }

        let json = resp.json::<serde_json::Value>().await?;
        Ok(json)
    }

    /// Resolves, downloads, cryptographically audits, and safely installs a package from the registry
    pub async fn install_package(
        &self,
        package_name: &str,
        version_opt: Option<&str>,
        dest_dir: &Path,
        trust_store_path: &Path,
        enforce_trust_store: bool,
        skip_transparency_proof: bool,
    ) -> Result<PathBuf, ClientError> {
        // 1. Resolve version
        let version = match version_opt {
            Some(v) => v.to_string(),
            None => {
                let info_url = format!("{}/api/v1/packages/{}", self.registry_url, package_name);
                let resp = self.http.get(&info_url).send().await?;
                if !resp.status().is_success() {
                    return Err(ClientError::Registry(format!(
                        "Package '{}' not found on registry at {}",
                        package_name, self.registry_url
                    )));
                }
                let info = resp.json::<serde_json::Value>().await?;
                let versions = info["versions"]
                    .as_array()
                    .ok_or_else(|| ClientError::Registry("Invalid version list from registry".into()))?;
                let latest = versions.last().ok_or_else(|| {
                    ClientError::Registry(format!("No releases found for package '{}'", package_name))
                })?;
                latest["version"]
                    .as_str()
                    .ok_or_else(|| ClientError::Registry("Missing version field".into()))?
                    .to_string()
            }
        };

        // 2. Download package bytes
        let download_url = format!(
            "{}/api/v1/packages/{}/{}/download",
            self.registry_url, package_name, version
        );
        let resp = self.http.get(&download_url).send().await?;
        if !resp.status().is_success() {
            return Err(ClientError::Registry(format!(
                "Failed to download package from {}: HTTP {}",
                download_url,
                resp.status()
            )));
        }
        let package_bytes = resp.bytes().await?;

        // 3. Save to isolated temporary file
        let temp_dir = std::env::temp_dir().join("sigil_inbound_downloads");
        fs::create_dir_all(&temp_dir)?;
        let temp_file_path = temp_dir.join(format!("{}-{}.sigil", package_name.replace('/', "-"), version));
        {
            let mut f = File::create(&temp_file_path)?;
            f.write_all(&package_bytes)?;
        }

        // 4. ZERO-TRUST CLIENT AUDIT: Verify package locally before unpacking!
        let report = Verifier::verify_package(&temp_file_path, None)?;
        if report.package_name != package_name || report.version != version {
            let _ = fs::remove_file(&temp_file_path);
            return Err(ClientError::SecurityAlert(format!(
                "Package metadata mismatch! Requested: {}@{}, but package claims: {}@{}",
                package_name, version, report.package_name, report.version
            )));
        }

        // 5. TRANSPARENCY LOG AUDIT: Verify Merkle inclusion proof from Registry (Strict Fail-Closed)
        if !skip_transparency_proof {
            let proof_url = format!("{}/api/v1/packages/{}/{}/proof", self.registry_url, package_name, version);
            let proof_resp = self.http.get(&proof_url).send().await?;
            if !proof_resp.status().is_success() {
                let _ = fs::remove_file(&temp_file_path);
                return Err(ClientError::SecurityAlert(format!(
                    "CRITICAL: Failed to retrieve transparency log proof from registry at {}: HTTP {}. Installation aborted (fail-closed).",
                    proof_url,
                    proof_resp.status()
                )));
            }
            let proof: MerkleInclusionProof = proof_resp.json().await?;

            let info_url = format!("{}/api/v1/packages/{}", self.registry_url, package_name);
            let info_resp = self.http.get(&info_url).send().await?;
            if !info_resp.status().is_success() {
                let _ = fs::remove_file(&temp_file_path);
                return Err(ClientError::SecurityAlert(format!(
                    "CRITICAL: Failed to retrieve package metadata from registry at {}: HTTP {}. Installation aborted (fail-closed).",
                    info_url,
                    info_resp.status()
                )));
            }

            let info = info_resp.json::<serde_json::Value>().await?;
            let versions = info["versions"].as_array().ok_or_else(|| {
                let _ = fs::remove_file(&temp_file_path);
                ClientError::SecurityAlert("Corrupted metadata: versions array missing from registry response".into())
            })?;

            let matching_entry = versions.iter().find(|e| e["version"] == version).ok_or_else(|| {
                let _ = fs::remove_file(&temp_file_path);
                ClientError::SecurityAlert(format!(
                    "Version {} missing from registry version metadata for package {}",
                    version, package_name
                ))
            })?;

            let prev_hash = matching_entry["prev_log_hash"].as_str().unwrap_or_default();
            let canonical_leaf = format!(
                "{}:{}:{}:{}:{}:{}",
                proof.leaf_index,
                report.package_name,
                report.version,
                report.content_hash,
                report.author_pubkey,
                prev_hash
            )
            .into_bytes();

            let is_valid = crate::merkle::verify_inclusion_proof_raw(
                &proof.root_hash,
                &canonical_leaf,
                &proof,
            )
            .map_err(|e| {
                let _ = fs::remove_file(&temp_file_path);
                ClientError::Registry(format!("Merkle proof verification error: {}", e))
            })?;

            if !is_valid {
                let _ = fs::remove_file(&temp_file_path);
                return Err(ClientError::SecurityAlert(format!(
                    "CRITICAL: Merkle transparency log proof failed for {}@{}. Potential split-view attack!",
                    package_name, version
                )));
            }
        }

        // 6. Zero-Trust Keyring / Trust Store check (Strict Fail-Closed)
        if enforce_trust_store {
            let trust_store = TrustStore::load_from(trust_store_path).unwrap_or_default();
            if !trust_store.is_trusted(&report.author_pubkey, package_name) {
                let _ = fs::remove_file(&temp_file_path);
                return Err(ClientError::UntrustedPublisher {
                    pubkey: report.author_pubkey,
                    package: package_name.to_string(),
                });
            }
        }

        // 7. Safe installation with Path-Traversal sandbox protection
        let final_install_path = dest_dir.join(&report.package_name);
        let envelope = Packager::unpack_verified(&temp_file_path, &final_install_path)?;

        // 8. Update sigil.lock
        let lockfile_path = Path::new("sigil.lock");
        let mut lockfile = SigilLockfile::load(lockfile_path).unwrap_or_default();
        lockfile.record_package(&envelope);
        let _ = lockfile.save(lockfile_path);

        // Clean up temp
        let _ = fs::remove_file(temp_file_path);

        Ok(final_install_path)
    }
}
