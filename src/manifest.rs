use crate::server::{is_valid_package_name, is_valid_version};
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

/// Fine-grained network capability specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NetworkCapability {
    #[serde(default)]
    pub allow: bool,
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// Fine-grained filesystem capability specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FsCapability {
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub write: Vec<String>,
}

/// Fine-grained environment capability specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EnvCapability {
    #[serde(default)]
    pub read: Vec<String>,
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

    /// Fine-grained declarative network restrictions (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkCapability>,
    /// Fine-grained declarative filesystem restrictions (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<FsCapability>,
    /// Fine-grained declarative environment restrictions (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EnvCapability>,
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

    /// Strict structural validation
    pub fn validate(&self) -> Result<(), ManifestError> {
        if !is_valid_package_name(&self.package.name) {
            return Err(ManifestError::Validation(format!(
                "Invalid package name '{}': must be alphanumeric with optional @scope/",
                self.package.name
            )));
        }
        if !is_valid_version(&self.package.version) {
            return Err(ManifestError::Validation(format!(
                "Invalid package version '{}': must conform to standard SemVer format",
                self.package.version
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
