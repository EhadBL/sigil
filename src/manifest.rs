use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ManifestError {
    #[error("IO error reading manifest: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse TOML manifest: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("Failed to serialize manifest: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("Invalid manifest: {0}")]
    Validation(String),
}

/// Zero-Trust capability model: Packages must declare what permissions they require.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// Does the package require outbound or inbound network access?
    #[serde(default)]
    pub allow_network: bool,
    /// Does the package require file system read access?
    #[serde(default)]
    pub allow_fs_read: bool,
    /// Does the package require file system write access?
    #[serde(default)]
    pub allow_fs_write: bool,
    /// Does the package require access to process environment variables?
    #[serde(default)]
    pub allow_env: bool,
    /// Does the package spawn child processes? (Strictly audited)
    #[serde(default)]
    pub allow_child_process: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageMeta {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    pub license: Option<String>,
    pub repository: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigilManifest {
    pub package: PackageMeta,
    #[serde(default)]
    pub capabilities: Capabilities,
    #[serde(default)]
    pub dependencies: HashMap<String, String>,
}

impl SigilManifest {
    /// Load manifest from `sigil.toml` file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ManifestError> {
        let content = fs::read_to_string(path)?;
        let manifest: SigilManifest = toml::from_str(&content)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Save manifest to a `sigil.toml` file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ManifestError> {
        self.validate()?;
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Basic structural validation
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.package.name.trim().is_empty() {
            return Err(ManifestError::Validation("Package name cannot be empty".into()));
        }
        if self.package.version.trim().is_empty() {
            return Err(ManifestError::Validation("Package version cannot be empty".into()));
        }
        // Name check: only allow alphanumeric, hyphens, underscores, and forward slashes for scoped packages (@scope/name)
        let valid_chars = self.package.name.chars().all(|c| {
            c.is_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '@' || c == '.'
        });
        if !valid_chars {
            return Err(ManifestError::Validation(format!(
                "Package name contains illegal characters: '{}'",
                self.package.name
            )));
        }
        Ok(())
    }

    /// Generates a default manifest template
    pub fn default_template(name: &str) -> Self {
        Self {
            package: PackageMeta {
                name: name.to_string(),
                version: "0.1.0".to_string(),
                description: Some("A cryptographically secure package".to_string()),
                authors: vec!["Author Name <author@example.com>".to_string()],
                license: Some("MIT".to_string()),
                repository: None,
            },
            capabilities: Capabilities::default(), // All false by default (Zero-Trust)
            dependencies: HashMap::new(),
        }
    }
}
