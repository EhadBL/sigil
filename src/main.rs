use clap::Parser;
use colored::*;
use ed25519_dalek::SigningKey;
use sigil::cli::{Cli, Commands, ServerCommands, TrustCommands};
use sigil::client::SigilClient;
use sigil::crypto;
use sigil::manifest::SigilManifest;
use sigil::packager::Packager;
use sigil::server::RegistryServer;
use sigil::trust::TrustStore;
use sigil::verifier::Verifier;
use std::fs;
use std::path::{Path, PathBuf};

/// Loads a signing key strictly from an explicitly provided file path or hex string.
/// ZERO-TRUST ENFORCEMENT: No magic fallback paths or implicit home-directory defaults allowed.
fn load_explicit_signing_key(key_str: &str) -> Result<SigningKey, String> {
    let trimmed = key_str.trim();
    if trimmed.is_empty() {
        return Err("Signing key cannot be empty. Specify a valid path to an Ed25519 key file or a 32-byte hex string.".into());
    }

    let path = Path::new(trimmed);
    if path.exists() && path.is_file() {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read explicit key file '{}': {}", path.display(), e))?;
        return crypto::import_signing_key_hex(content.trim())
            .map_err(|e| format!("Failed to parse private key from file '{}': {}", path.display(), e));
    }

    if let Ok(key) = crypto::import_signing_key_hex(trimmed) {
        return Ok(key);
    }

    Err(format!(
        "Explicit key '{}' is invalid: file does not exist, and it is not a valid 32-byte hex string.",
        trimmed
    ))
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { out } => {
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        eprintln!("{} Failed to create directory '{}': {}", "[-]".red().bold(), parent.display(), e);
                        std::process::exit(1);
                    }
                }
            }

            let (signing_key, verifying_key) = crypto::generate_keypair();
            let priv_hex = crypto::export_signing_key_hex(&signing_key);
            let pub_hex = crypto::export_verifying_key_hex(&verifying_key);

            let priv_path = if out.extension().is_some() {
                out.clone()
            } else {
                PathBuf::from(format!("{}.key", out.display()))
            };

            let pub_path = if let Some(ext) = out.extension() {
                out.with_extension(format!("{}.pub", ext.to_string_lossy()))
            } else {
                PathBuf::from(format!("{}.pub", out.display()))
            };

            if let Err(e) = fs::write(&priv_path, &priv_hex) {
                eprintln!("{} Failed to write private key to '{}': {}", "[-]".red().bold(), priv_path.display(), e);
                std::process::exit(1);
            }
            if let Err(e) = fs::write(&pub_path, &pub_hex) {
                eprintln!("{} Failed to write public key to '{}': {}", "[-]".red().bold(), pub_path.display(), e);
                std::process::exit(1);
            }

            println!("{}", "══════════════════════════════════════════════════════════".cyan());
            println!("  {} {}", "✔".green().bold(), "New Ed25519 Cryptographic Keypair Generated!".bold());
            println!("{}", "══════════════════════════════════════════════════════════".cyan());
            println!("  {} Private Key : {}", "•".yellow(), priv_path.display().to_string().bold());
            println!("  {} Public Key  : {}", "•".yellow(), pub_path.display().to_string().bold());
            println!("  {} Public ID   : {}", "•".cyan(), pub_hex.bright_white().bold());
            println!("\n  {} Keep your private key secret and secure!", "⚠".yellow().bold());
        }

        Commands::Init { name } => {
            let target_file = Path::new("sigil.toml");
            if target_file.exists() {
                eprintln!("{} sigil.toml already exists in this directory!", "[-]".red().bold());
                std::process::exit(1);
            }

            let pkg_name = name.unwrap_or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                    .unwrap_or_else(|| "unnamed-package".to_string())
            });

            let manifest = SigilManifest::default_template(&pkg_name);
            if let Err(e) = manifest.to_file(target_file) {
                eprintln!("{} Failed to initialize manifest: {}", "[-]".red().bold(), e);
                std::process::exit(1);
            }

            println!("{} Initialized {} with Zero-Trust capability model in {}",
                "✔".green().bold(),
                pkg_name.bold(),
                target_file.display()
            );
        }

        Commands::Pack { dir, out, key } => {
            let signing_key = match load_explicit_signing_key(&key) {
                Ok(k) => k,
                Err(err) => {
                    eprintln!("{} {}", "[-]".red().bold(), err);
                    std::process::exit(1);
                }
            };

            let manifest_path = dir.join("sigil.toml");
            let manifest = match SigilManifest::from_file(&manifest_path) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("{} Failed to load manifest at {}: {}", "[-]".red().bold(), manifest_path.display(), e);
                    std::process::exit(1);
                }
            };

            let out_file = out.unwrap_or_else(|| {
                PathBuf::from(format!("{}-{}.sigil", manifest.package.name.replace('/', "-"), manifest.package.version))
            });

            println!("{} Packaging and deterministically signing {}...", "▶".cyan().bold(), manifest.package.name.bold());
            match Packager::pack(&dir, &out_file, &signing_key) {
                Ok(env) => {
                    println!("{}", "══════════════════════════════════════════════════════════".green());
                    println!("  {} {}", "✔".green().bold(), "Package Successfully Packed & Cryptographically Sealed!".bold());
                    println!("{}", "══════════════════════════════════════════════════════════".green());
                    println!("  {} Package File : {}", "•".yellow(), out_file.display().to_string().bold());
                    println!("  {} Files Hashed : {}", "•".yellow(), env.files.len());
                    println!("  {} Content BLAKE3: {}", "•".yellow(), env.content_hash);
                    println!("  {} Merkle Root  : {}", "•".yellow(), env.tree_root_hash);
                    println!("  {} Author Key   : {}", "•".cyan(), env.author_pubkey);
                    println!("  {} Signature    : {}...", "•".green(), &env.signature[..32]);
                }
                Err(e) => {
                    eprintln!("{} Packaging failed: {}", "[-]".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Publish { package, registry, key } => {
            let package_to_send = match package {
                Some(p) => p,
                None => {
                    let key_str = match key {
                        Some(k) => k,
                        None => {
                            eprintln!("{} Explicit signing key is required via --key when packing before publishing!", "[-]".red().bold());
                            std::process::exit(1);
                        }
                    };
                    let signing_key = match load_explicit_signing_key(&key_str) {
                        Ok(k) => k,
                        Err(err) => {
                            eprintln!("{} {}", "[-]".red().bold(), err);
                            std::process::exit(1);
                        }
                    };
                    let manifest = SigilManifest::from_file("sigil.toml").unwrap_or_else(|e| {
                        eprintln!("{} Failed to read sigil.toml: {}", "[-]".red().bold(), e);
                        std::process::exit(1);
                    });
                    let out = PathBuf::from(format!("{}-{}.sigil", manifest.package.name.replace('/', "-"), manifest.package.version));
                    println!("{} Packaging {} for publishing...", "▶".cyan().bold(), manifest.package.name.bold());
                    Packager::pack(Path::new("."), &out, &signing_key).unwrap_or_else(|e| {
                        eprintln!("{} Packaging failed: {}", "[-]".red().bold(), e);
                        std::process::exit(1);
                    });
                    out
                }
            };

            let client = SigilClient::new(&registry);
            println!("{} Publishing {} to Transparency Registry at {}...", "🚀".cyan().bold(), package_to_send.display(), registry);

            match client.publish(&package_to_send).await {
                Ok(resp) => {
                    println!("{}", "══════════════════════════════════════════════════════════".green());
                    println!("  {} {}", "✔".green().bold(), "Package Successfully Verified & Logged by Registry!".bold());
                    println!("{}", "══════════════════════════════════════════════════════════".green());
                    println!("  {} Log Index  : {}", "•".yellow(), resp["log_index"]);
                    println!("  {} Entry Hash : {}", "•".yellow(), resp["entry_hash"]);
                    println!("  {} Status     : {}", "•".green(), "Immutably Recorded".green().bold());
                }
                Err(e) => {
                    eprintln!("{} Publishing failed: {}", "[-]".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Add { package, version, registry, dest, trust_store, enforce_trust } => {
            let client = SigilClient::new(&registry);
            println!("{} Fetching '{}' from Transparency Registry ({})...", "📥".cyan().bold(), package.bold(), registry);

            match client.install_package(&package, version.as_deref(), &dest, &trust_store, enforce_trust).await {
                Ok(installed_path) => {
                    println!("{}", "══════════════════════════════════════════════════════════".green());
                    println!("  {} {}", "✔".green().bold(), "Package Downloaded, Cryptographically Audited & Installed!".bold());
                    println!("{}", "══════════════════════════════════════════════════════════".green());
                    println!("  {} Destination : {}", "•".yellow(), installed_path.display());
                    println!("  {} Lockfile    : Updated sigil.lock", "•".cyan());
                    println!("  {} Execution   : 0 scripts run (Zero-Day Immune)", "•".green().bold());
                }
                Err(e) => {
                    eprintln!("{} Installation failed: {}", "[-]".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Verify { package, trusted_key } => {
            println!("{} Auditing cryptographic envelope for {}...", "🔍".cyan().bold(), package.display());
            match Verifier::verify_package(&package, trusted_key.as_deref()) {
                Ok(report) => {
                    println!("{}", "══════════════════════════════════════════════════════════".green());
                    println!("  {} {}", "✔".green().bold(), "CRYPTOGRAPHIC VERIFICATION PASSED (ZERO-TRUST VALID)".bold());
                    println!("{}", "══════════════════════════════════════════════════════════".green());
                    println!("  {} Package     : {} v{}", "•".yellow(), report.package_name.bold(), report.version);
                    println!("  {} Publisher   : {}", "•".cyan(), report.author_pubkey.bright_white().bold());
                    println!("  {} BLAKE3 Hash : {}", "•".yellow(), report.content_hash);
                    println!("  {} Merkle Root : {}", "•".yellow(), report.tree_root_hash);
                    println!("  {} File Count  : {}", "•".yellow(), report.total_files);
                    println!("  {} Tamper Check: {}", "•".green(), "PASSED (0 bit difference)".green().bold());
                    println!("\n  {} Declared Capabilities:", "🛡".magenta().bold());
                    println!("    - Network Access     : {}", if report.capabilities.allow_network { "ALLOW".yellow() } else { "DENIED".green() });
                    println!("    - FS Read Access     : {}", if report.capabilities.allow_fs_read { "ALLOW".yellow() } else { "DENIED".green() });
                    println!("    - FS Write Access    : {}", if report.capabilities.allow_fs_write { "ALLOW".yellow() } else { "DENIED".green() });
                    println!("    - Env Vars Access    : {}", if report.capabilities.allow_env { "ALLOW".yellow() } else { "DENIED".green() });
                    println!("    - Child Process Spawns: {}", if report.capabilities.allow_child_process { "ALLOW".red().bold() } else { "DENIED".green() });
                }
                Err(e) => {
                    eprintln!("{}", "══════════════════════════════════════════════════════════".red());
                    eprintln!("  {} {}", "✖".red().bold(), "SECURITY VIOLATION / VERIFICATION FAILED!".red().bold());
                    eprintln!("{}", "══════════════════════════════════════════════════════════".red());
                    eprintln!("  {} Reason: {}", "•".red(), e.to_string().bold());
                    std::process::exit(1);
                }
            }
        }

        Commands::Install { package, dest, trusted_key } => {
            println!("{} Verifying package {} prior to installation...", "🔒".cyan().bold(), package.display());

            let report = match Verifier::verify_package(&package, trusted_key.as_deref()) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{} Installation Aborted: Cryptographic verification failed: {}", "[-]".red().bold(), e);
                    std::process::exit(1);
                }
            };

            let install_dest = dest.join(&report.package_name);
            println!("{} Unpacking verified files into {}...", "▶".cyan().bold(), install_dest.display());

            match Packager::unpack_verified(&package, &install_dest) {
                Ok(envelope) => {
                    let lockfile_path = Path::new("sigil.lock");
                    let mut lock = sigil::lockfile::SigilLockfile::load(lockfile_path).unwrap_or_default();
                    lock.record_package(&envelope);
                    let _ = lock.save(lockfile_path);

                    println!("{}", "══════════════════════════════════════════════════════════".green());
                    println!("  {} {} v{} installed safely!", "✔".green().bold(), report.package_name.bold(), report.version);
                    println!("{}", "══════════════════════════════════════════════════════════".green());
                    println!("  {} Destination: {}", "•".yellow(), install_dest.display());
                    println!("  {} Security   : Zero install scripts executed (Zero-Day Protected)", "•".green());
                }
                Err(e) => {
                    eprintln!("{} Safe extraction failed: {}", "[-]".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Trust { store_path, command } => match command {
            TrustCommands::Add { pubkey, identity, scope } => {
                let mut store = TrustStore::load_from(&store_path).unwrap_or_default();
                match store.add_key(pubkey.clone(), identity.clone(), scope.clone()) {
                    Ok(_) => match store.save_to(&store_path) {
                        Ok(_) => {
                            println!("{} Trusted publisher added to '{}'!", "✔".green().bold(), store_path.display());
                            println!("  {} Key     : {}", "•".cyan(), pubkey);
                            println!("  {} Identity: {}", "•".yellow(), identity);
                            println!("  {} Scope   : {}", "•".yellow(), scope);
                        }
                        Err(e) => eprintln!("{} Failed to save trust store: {}", "[-]".red().bold(), e),
                    },
                    Err(e) => eprintln!("{} Failed to add key: {}", "[-]".red().bold(), e),
                }
            }
            TrustCommands::Remove { pubkey } => {
                let mut store = TrustStore::load_from(&store_path).unwrap_or_default();
                if store.remove_key(&pubkey) {
                    if let Err(e) = store.save_to(&store_path) {
                        eprintln!("{} Failed to save trust store: {}", "[-]".red().bold(), e);
                    } else {
                        println!("{} Removed key {} from '{}'.", "✔".green().bold(), pubkey, store_path.display());
                    }
                } else {
                    println!("{} Key not found in '{}'.", "[-]".yellow().bold(), store_path.display());
                }
            }
            TrustCommands::List => {
                let store = TrustStore::load_from(&store_path).unwrap_or_default();
                if store.keys.is_empty() {
                    println!("Trust store at '{}' is currently empty.", store_path.display());
                } else {
                    println!("Trusted Publishers in '{}':", store_path.display().to_string().bold());
                    for (i, key) in store.keys.iter().enumerate() {
                        println!("{}. {} ({})", i + 1, key.identity.bold(), key.scope.cyan());
                        println!("   Key: {}", key.pubkey);
                    }
                }
            }
        },

        Commands::Server { command } => match command {
            ServerCommands::Start { port, storage } => {
                println!("{} Initializing Sigil Transparency Registry Server...", "🛡".cyan().bold());
                println!("  Storage directory: {}", storage.display().to_string().bold());

                if let Err(e) = RegistryServer::run(port, storage).await {
                    eprintln!("{} Server error: {}", "[-]".red().bold(), e);
                    std::process::exit(1);
                }
            }
        },

        Commands::Info { package } => {
            match Verifier::verify_package(&package, None) {
                Ok(report) => {
                    println!("Package Information: {} v{}", report.package_name.bold(), report.version);
                    println!("Author Key        : {}", report.author_pubkey);
                    println!("Content BLAKE3    : {}", report.content_hash);
                    println!("Merkle Root Hash  : {}", report.tree_root_hash);
                    println!("Contained Files   : {}", report.total_files);
                    println!("Capabilities      : {:?}", report.capabilities);
                }
                Err(e) => {
                    eprintln!("{} Failed to read package info: {}", "[-]".red().bold(), e);
                    std::process::exit(1);
                }
            }
        }
    }
}
