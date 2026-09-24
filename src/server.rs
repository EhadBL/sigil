use crate::verifier::Verifier;
use axum::{
    body::Bytes,
    extract::{Path as AxPath, State},
    http::StatusCode,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryIndex {
    pub entries: Vec<TransparencyLogEntry>,
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
        let initial_index = if log_file.exists() {
            let content = fs::read_to_string(&log_file)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            RegistryIndex::default()
        };

        let state = ServerState {
            storage_dir,
            log_state: Arc::new(Mutex::new(initial_index)),
        };

        let app = Router::new()
            .route("/api/v1/health", get(health_handler))
            .route("/api/v1/log", get(log_handler))
            .route("/api/v1/publish", post(publish_handler))
            .route("/api/v1/packages/:name", get(package_info_handler))
            .route("/api/v1/packages/:name/:version/download", get(download_handler))
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
    }))
}

async fn log_handler(State(state): State<ServerState>) -> Json<Vec<TransparencyLogEntry>> {
    let log = state.log_state.lock().unwrap();
    Json(log.entries.clone())
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

    // ZERO-TRUST INGESTION: Server verifies author cryptographic signature before accepting!
    let report = Verifier::verify_package(&temp_pkg_path, None).map_err(|e| {
        let _ = fs::remove_file(&temp_pkg_path);
        (
            StatusCode::BAD_REQUEST,
            format!("Package rejected: Cryptographic verification failed: {}", e),
        )
    })?;

    // Record into append-only Transparency Log
    let mut log = state.log_state.lock().unwrap();
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

    // Save transparency log to disk
    let log_file = state.storage_dir.join("transparency_log.json");
    if let Ok(json) = serde_json::to_string_pretty(&*log) {
        let _ = fs::write(log_file, json);
    }

    // Save package into permanent content-addressable storage
    let pkg_storage_name = format!("{}-{}.sigil", report.package_name.replace('/', "-"), report.version);
    let target_path = state.storage_dir.join("packages").join(pkg_storage_name);
    fs::rename(&temp_pkg_path, &target_path).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to persist package: {}", e))
    })?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Package verified and sealed into transparency log",
        "package": report.package_name,
        "version": report.version,
        "log_index": index,
        "entry_hash": entry_hash
    })))
}

async fn package_info_handler(
    State(state): State<ServerState>,
    AxPath(name): AxPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let log = state.log_state.lock().unwrap();
    let matching_versions: Vec<&TransparencyLogEntry> = log
        .entries
        .iter()
        .filter(|e| e.package_name == name)
        .collect();

    if matching_versions.is_empty() {
        return Err((StatusCode::NOT_FOUND, format!("Package '{}' not found", name)));
    }

    Ok(Json(serde_json::json!({
        "package": name,
        "versions": matching_versions,
    })))
}

async fn download_handler(
    State(state): State<ServerState>,
    AxPath((name, version)): AxPath<(String, String)>,
) -> Result<Response, (StatusCode, String)> {
    let pkg_file_name = format!("{}-{}.sigil", name.replace('/', "-"), version);
    let path = state.storage_dir.join("packages").join(&pkg_file_name);

    if !path.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Package version '{}-{}' not found", name, version),
        ));
    }

    let bytes = fs::read(&path)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Read error: {}", e)))?;

    let response = Response::builder()
        .header("Content-Type", "application/octet-stream")
        .header("Content-Disposition", format!("attachment; filename=\"{}\"", pkg_file_name))
        .body(Bytes::from(bytes).into())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(response)
}
