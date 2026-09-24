use crate::envelope::SigilEnvelope;
use crate::manifest::Capabilities;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LockfileError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML serialization error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("Integrity mismatch in lockfile for package {package}: expected {expected}, found {found}")]
    Mismatch {
        package: String,
        expected: String,
        found: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedPackage {
    pub version: String,
    pub content_blake3: String,
    pub tree_root_blake3: String,
    pub author_pubkey: String,
    pub signature: String,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigilLockfile {
    pub version: u32,
    #[serde(default)]
    pub packages: BTreeMap<String, LockedPackage>,
}

impl SigilLockfile {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, LockfileError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self {
                version: 1,
                packages: BTreeMap::new(),
            });
        }
        let content = fs::read_to_string(path)?;
        let lockfile: SigilLockfile = toml::from_str(&content)?;
        Ok(lockfile)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), LockfileError> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Records or updates a verified package envelope into the lockfile
    pub fn record_package(&mut self, envelope: &SigilEnvelope) {
        let key = format!("{}@{}", envelope.manifest.package.name, envelope.manifest.package.version);
        self.packages.insert(
            key,
            LockedPackage {
                version: envelope.manifest.package.version.clone(),
                content_blake3: envelope.content_hash.clone(),
                tree_root_blake3: envelope.tree_root_hash.clone(),
                author_pubkey: envelope.author_pubkey.clone(),
                signature: envelope.signature.clone(),
                capabilities: envelope.manifest.capabilities.clone(),
            },
        );
    }

    /// Verifies that a package strictly matches the pinned lockfile entry
    pub fn verify_against_lock(&self, envelope: &SigilEnvelope) -> Result<(), LockfileError> {
        let key = format!("{}@{}", envelope.manifest.package.name, envelope.manifest.package.version);
        if let Some(locked) = self.packages.get(&key) {
            if locked.content_blake3 != envelope.content_hash {
                return Err(LockfileError::Mismatch {
                    package: key,
                    expected: locked.content_blake3.clone(),
                    found: envelope.content_hash.clone(),
                });
            }
            if locked.author_pubkey != envelope.author_pubkey {
                return Err(LockfileError::Mismatch {
                    package: key,
                    expected: format!("Signed by key {}", locked.author_pubkey),
                    found: format!("Signed by key {}", envelope.author_pubkey),
                });
            }
        }
        Ok(())
    }
}
