use crate::merkle::{MerkleInclusionProof, MerkleTree};
use crate::verifier::Verifier;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxPath, State},
    http::StatusCode,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

pub const MAX_PUBLISH_PAYLOAD_SIZE: usize = 64 * 1024 * 1024; // 64 MB max upload

/// Validates package name to prevent path traversal and enforce naming hygiene
pub fn is_valid_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    let (scope, pkg) = if name.starts_with('@') {
        let parts: Vec<&str> = name[1..].split('/').collect();
        if parts.len() != 2 {
            return false;
        }
        (Some(parts[0]), parts[1])
    } else {
        (None, name)
    };

    if let Some(s) = scope {
        if s.is_empty() || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return false;
        }
    }

    if pkg.is_empty() || !pkg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return false;
    }
    true
}

/// Validates SemVer version string
pub fn is_valid_version(version: &str) -> bool {
    if version.is_empty() || version.len() > 64 {
        return false;
    }
    version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyLogEntry {
    pub index: u64,
    pub timestamp: i64,
    pub package_name: String,
    pub version: String,
    pub content_hash: String,
    pub author_pubkey: String,
    pub prev_log_hash: String,
    pub entry_hash: String,
}

impl TransparencyLogEntry {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{}:{}:{}:{}:{}:{}",
            self.index,
            self.package_name,
            self.version,
            self.content_hash,
            self.author_pubkey,
            self.prev_log_hash
        )
        .into_bytes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryIndex {
    pub entries: Vec<TransparencyLogEntry>,
    #[serde(default)]
    pub package_owners: HashMap<String, String>, // package_name -> author_pubkey
    #[serde(default)]
    pub tree_root_head: String,
}

#[derive(Clone)]
pub struct ServerState {
    pub storage_dir: PathBuf,
    pub log_state: Arc<Mutex<RegistryIndex>>,
}

pub struct RegistryServer;

impl RegistryServer {
    pub async fn run(port: u16, storage_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(&storage_dir)?;
        let packages_dir = storage_dir.join("packages");
        fs::create_dir_all(&packages_dir)?;

        let log_file = storage_dir.join("transparency_log.json");
        let mut initial_index: RegistryIndex = if log_file.exists() {
            let content = fs::read_to_string(&log_file)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            RegistryIndex::default()
        };

        // Ensure tree root head is properly computed
        if !initial_index.entries.is_empty() && initial_index.tree_root_head.is_empty() {
            let leaves: Vec<Vec<u8>> = initial_index.entries.iter().map(|e| e.canonical_bytes()).collect();
            let leaf_slices: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
            let tree = MerkleTree::from_raw_leaves(&leaf_slices);
            initial_index.tree_root_head = tree.root_hex();
        }

        let state = ServerState {
            storage_dir,
            log_state: Arc::new(Mutex::new(initial_index)),
        };

        let app = Router::new()
            .route("/api/v1/health", get(health_handler))
            .route("/api/v1/log", get(log_handler))
            .route("/api/v1/tree/head", get(tree_head_handler))
            .route("/api/v1/publish", post(publish_handler))
            .route("/api/v1/packages/:name", get(package_info_handler))
            .route("/api/v1/packages/:name/:version/proof", get(proof_handler))
            .route("/api/v1/packages/:name/:version/download", get(download_handler))
            .layer(DefaultBodyLimit::max(MAX_PUBLISH_PAYLOAD_SIZE))
            .layer(CorsLayer::permissive())
            .with_state(state);

        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        println!("🚀 Sigil Transparency Registry running on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn health_handler(State(state): State<ServerState>) -> Json<serde_json::Value> {
    let log = state.log_state.lock().unwrap();
    Json(serde_json::json!({
        "status": "healthy",
        "service": "sigil-transparency-registry",
        "total_packages_logged": log.entries.len(),
        "tree_root_head": log.tree_root_head,
        "namespaces_registered": log.package_owners.len(),
    }))
}

async fn log_handler(State(state): State<ServerState>) -> Json<Vec<TransparencyLogEntry>> {
    let log = state.log_state.lock().unwrap();
    Json(log.entries.clone())
}

async fn tree_head_handler(State(state): State<ServerState>) -> Json<serde_json::Value> {
    let log = state.log_state.lock().unwrap();
    Json(serde_json::json!({
        "tree_size": log.entries.len(),
        "root_hash": log.tree_root_head,
        "timestamp": chrono::Utc::now().timestamp(),
    }))
}

async fn publish_handler(
    State(state): State<ServerState>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty payload".into()));
    }

    // Write temporary package file to verify
    let temp_dir = std::env::temp_dir().join("sigil_server_inbound");
    fs::create_dir_all(&temp_dir).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let temp_pkg_path = temp_dir.join(format!("{}.sigil", blake3::hash(&body).to_hex()));

    {
        let mut temp_file = File::create(&temp_pkg_path)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        temp_file.write_all(&body)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    // ZERO-TRUST INGESTION: Server verifies author cryptographic signature before accepting
    let report = Verifier::verify_package(&temp_pkg_path, None).map_err(|e| {
        let _ = fs::remove_file(&temp_pkg_path);
        (
            StatusCode::BAD_REQUEST,
            format!("Package rejected: Cryptographic verification failed: {}", e),
        )
    })?;

    // Validate package name and version syntax
    if !is_valid_package_name(&report.package_name) || !is_valid_version(&report.version) {
        let _ = fs::remove_file(&temp_pkg_path);
        return Err((
            StatusCode::BAD_REQUEST,
            "Package name or version contains invalid characters".into(),
        ));
    }

    let mut log = state.log_state.lock().unwrap();

    // 1. Namespace Ownership Protection: Prevent package hijacking by unauthorized public keys
    if let Some(existing_owner) = log.package_owners.get(&report.package_name) {
        if existing_owner != &report.author_pubkey {
            let _ = fs::remove_file(&temp_pkg_path);
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "Package namespace '{}' is owned by public key {}. Publish rejected.",
                    report.package_name, existing_owner
                ),
            ));
        }
    } else {
        // First publisher claims ownership of this package namespace
        log.package_owners.insert(report.package_name.clone(), report.author_pubkey.clone());
    }

    // 2. Immutability Guarantee: Reject duplicate versions
    let version_exists = log
        .entries
        .iter()
        .any(|e| e.package_name == report.package_name && e.version == report.version);
    if version_exists {
        let _ = fs::remove_file(&temp_pkg_path);
        return Err((
            StatusCode::CONFLICT,
            format!(
                "Package '{}' version '{}' is already published. Releases in Sigil are strictly immutable.",
                report.package_name, report.version
            ),
        ));
    }

    // 3. Append to Transparency Log
    let index = log.entries.len() as u64;
    let prev_hash = log
        .entries
        .last()
        .map(|e| e.entry_hash.clone())
        .unwrap_or_else(|| "0".repeat(64));

    let timestamp = chrono::Utc::now().timestamp();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&index.to_le_bytes());
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(report.package_name.as_bytes());
    hasher.update(report.version.as_bytes());
    hasher.update(report.content_hash.as_bytes());
    hasher.update(report.author_pubkey.as_bytes());
    hasher.update(prev_hash.as_bytes());
    let entry_hash = hasher.finalize().to_hex().to_string();

    let entry = TransparencyLogEntry {
        index,
        timestamp,
        package_name: report.package_name.clone(),
        version: report.version.clone(),
        content_hash: report.content_hash.clone(),
        author_pubkey: report.author_pubkey.clone(),
        prev_log_hash: prev_hash,
        entry_hash: entry_hash.clone(),
    };

    log.entries.push(entry);

    // 4. Update Merkle Tree Root Head over all entries
    let leaves: Vec<Vec<u8>> = log.entries.iter().map(|e| e.canonical_bytes()).collect();
    let leaf_slices: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    let tree = MerkleTree::from_raw_leaves(&leaf_slices);
    log.tree_root_head = tree.root_hex();

    // 5. Save transparency log to disk
    let log_file = state.storage_dir.join("transparency_log.json");
    if let Ok(json) = serde_json::to_string_pretty(&*log) {
        let _ = fs::write(log_file, json);
    }

    // 6. Save package into permanent content-addressable storage
    let pkg_storage_name = format!("{}-{}.sigil", report.package_name.replace('/', "-"), report.version);
    let target_path = state.storage_dir.join("packages").join(pkg_storage_name);
    fs::rename(&temp_pkg_path, &target_path).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to persist package: {}", e))
    })?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Package verified, sealed into transparency log, and namespace locked",
        "package": report.package_name,
        "version": report.version,
        "log_index": index,
        "entry_hash": entry_hash,
        "tree_root_head": log.tree_root_head
    })))
}

async fn package_info_handler(
    State(state): State<ServerState>,
    AxPath(name): AxPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if !is_valid_package_name(&name) {
        return Err((StatusCode::BAD_REQUEST, "Invalid package name format".into()));
    }

    let log = state.log_state.lock().unwrap();
    let matching_versions: Vec<&TransparencyLogEntry> = log
        .entries
        .iter()
        .filter(|e| e.package_name == name)
        .collect();

    if matching_versions.is_empty() {
        return Err((StatusCode::NOT_FOUND, format!("Package '{}' not found", name)));
    }

    let owner = log.package_owners.get(&name).cloned();

    Ok(Json(serde_json::json!({
        "package": name,
        "owner_pubkey": owner,
        "versions": matching_versions,
    })))
}

async fn proof_handler(
    State(state): State<ServerState>,
    AxPath((name, version)): AxPath<(String, String)>,
) -> Result<Json<MerkleInclusionProof>, (StatusCode, String)> {
    if !is_valid_package_name(&name) || !is_valid_version(&version) {
        return Err((StatusCode::BAD_REQUEST, "Invalid package name or version format".into()));
    }

    let log = state.log_state.lock().unwrap();
    let entry_idx = log
        .entries
        .iter()
        .position(|e| e.package_name == name && e.version == version)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("Package '{}-{}' not found in transparency log", name, version),
            )
        })?;

    let leaves: Vec<Vec<u8>> = log.entries.iter().map(|e| e.canonical_bytes()).collect();
    let leaf_slices: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    let tree = MerkleTree::from_raw_leaves(&leaf_slices);

    let proof = tree.generate_inclusion_proof(entry_idx).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to generate Merkle inclusion proof: {}", e),
        )
    })?;

    Ok(Json(proof))
}

async fn download_handler(
    State(state): State<ServerState>,
    AxPath((name, version)): AxPath<(String, String)>,
) -> Result<Response, (StatusCode, String)> {
    if !is_valid_package_name(&name) || !is_valid_version(&version) {
        return Err((StatusCode::BAD_REQUEST, "Invalid package name or version format".into()));
    }

    let packages_dir = match state.storage_dir.join("packages").canonicalize() {
        Ok(dir) => dir,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Storage directory error: {}", e))),
    };

    let pkg_file_name = format!("{}-{}.sigil", name.replace('/', "-"), version);
    let path = packages_dir.join(&pkg_file_name);

    // Boundary containment check to strictly prevent path traversal
    if !path.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Package version '{}-{}' not found", name, version),
        ));
    }

    let canonical_file = match path.canonicalize() {
        Ok(p) => p,
        Err(_) => return Err((StatusCode::NOT_FOUND, "File not found".into())),
    };

    if !canonical_file.starts_with(&packages_dir) {
        return Err((StatusCode::BAD_REQUEST, "Invalid path resolution".into()));
    }

    let bytes = fs::read(&canonical_file)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Read error: {}", e)))?;

    let response = Response::builder()
        .header("Content-Type", "application/octet-stream")
        .header("Content-Disposition", format!("attachment; filename=\"{}\"", pkg_file_name))
        .body(Bytes::from(bytes).into())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(response)
}
