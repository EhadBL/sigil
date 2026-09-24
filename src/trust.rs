use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrustError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedKey {
    pub pubkey: String,
    pub identity: String,
    pub scope: String, // e.g. "@acme/*", "*", "lodash"
    pub added_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustStore {
    pub keys: Vec<TrustedKey>,
}

impl TrustStore {
    /// Loads the trust store from an explicit path
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, TrustError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        let store = serde_json::from_str(&content)?;
        Ok(store)
    }

    /// Saves the trust store to an explicit path
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<(), TrustError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn add_key(&mut self, pubkey: String, identity: String, scope: String) -> Result<(), TrustError> {
        if hex::decode(&pubkey).map_err(|e| TrustError::InvalidKey(e.to_string()))?.len() != 32 {
            return Err(TrustError::InvalidKey("Public key must be 32 bytes hex".into()));
        }

        // Remove duplicate if exists
        self.keys.retain(|k| k.pubkey != pubkey || k.scope != scope);

        self.keys.push(TrustedKey {
            pubkey,
            identity,
            scope,
            added_at: chrono::Utc::now().timestamp(),
        });
        Ok(())
    }

    pub fn remove_key(&mut self, pubkey: &str) -> bool {
        let initial_len = self.keys.len();
        self.keys.retain(|k| k.pubkey != pubkey);
        self.keys.len() < initial_len
    }

    /// Verifies if a given publisher public key is trusted for a package name
    pub fn is_trusted(&self, pubkey: &str, package_name: &str) -> bool {
        for entry in &self.keys {
            if entry.pubkey.eq_ignore_ascii_case(pubkey) {
                if entry.scope == "*" {
                    return true;
                }
                if entry.scope.ends_with("/*") {
                    let prefix = &entry.scope[..entry.scope.len() - 1]; // e.g. "@acme/"
                    if package_name.starts_with(prefix) {
                        return true;
                    }
                }
                if entry.scope == package_name {
                    return true;
                }
            }
        }
        false
    }
}
