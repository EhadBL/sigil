use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sigil",
    author = "Sigil Security Architecture Team",
    version = "0.1.0",
    about = "Zero-Trust, Cryptographically Signed Package Distribution & Verification System",
    long_about = "Sigil eliminates software supply chain attacks and zero-days \
                  via mandatory Ed25519 author signatures, BLAKE3 Merkle hashing, \
                  append-only Transparency Logs, zero-execution installs, and capability permissions.\n\n\
                  ZERO-TRUST PRINCIPLE: All signing keys and storage targets MUST be explicitly specified. \
                  Magic defaults and implicit key guessing are strictly prohibited."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate a new Ed25519 cryptographic signing keypair with explicit destination
    Keygen {
        /// Explicit output path prefix for the generated keypair (e.g. ./keys/publisher_id)
        #[arg(short, long)]
        out: PathBuf,
    },

    /// Initialize a new secure sigil.toml manifest in current directory
    Init {
        /// Package name
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Package and cryptographically sign the current project into a .sigil bundle
    Pack {
        /// Source directory containing sigil.toml (default: current directory)
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,

        /// Output path for the .sigil package file
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Path to the Ed25519 private signing key file or 32-byte hex string (REQUIRED - No magic defaults)
        #[arg(short, long)]
        key: String,
    },

    /// Cryptographically audit and verify a .sigil package against tampering and forgery
    Verify {
        /// Path to the .sigil package to verify
        package: PathBuf,

        /// Optional: Enforce that the package was signed by this specific public key (hex)
        #[arg(short, long)]
        trusted_key: Option<String>,
    },

    /// Securely verify and install a local .sigil package file
    Install {
        /// Path to the .sigil package to install
        package: PathBuf,

        /// Destination directory (default: ./sigil_modules)
        #[arg(short, long, default_value = "./sigil_modules")]
        dest: PathBuf,

        /// Optional: Enforce that the package was signed by this specific public key (hex)
        #[arg(short, long)]
        trusted_key: Option<String>,
    },

    /// Download, audit, and install a package from a remote Sigil Transparency Registry
    Add {
        /// Package name (e.g. core-utils or @scope/core-utils)
        package: String,

        /// Optional package version (defaults to latest)
        #[arg(short, long)]
        version: Option<String>,

        /// Registry URL
        #[arg(short, long, default_value = "http://localhost:8080")]
        registry: String,

        /// Destination directory (default: ./sigil_modules)
        #[arg(short, long, default_value = "./sigil_modules")]
        dest: PathBuf,

        /// Explicit path to trust store (default: ./sigil.trust.json)
        #[arg(long, default_value = "sigil.trust.json")]
        trust_store: PathBuf,

        /// Enforce that author public key must be registered in the trust store
        #[arg(long, default_value_t = false)]
        enforce_trust: bool,

        /// Bypass fail-closed Merkle transparency log proof validation (INSECURE: local/dev only)
        #[arg(long, default_value_t = false)]
        skip_transparency_proof: bool,
    },

    /// Cryptographically pack, sign, and publish package to a Sigil Transparency Registry
    Publish {
        /// Pre-built .sigil package file to publish (optional; if omitted, packs current directory)
        #[arg(short, long)]
        package: Option<PathBuf>,

        /// Registry URL
        #[arg(short, long, default_value = "http://localhost:8080")]
        registry: String,

        /// Path to the Ed25519 private signing key file or 32-byte hex string (REQUIRED when packing)
        #[arg(short, long)]
        key: Option<String>,
    },

    /// Manage trusted publisher public keys (Keyring / Trust Store)
    Trust {
        /// Path to the trust store JSON file (default: ./sigil.trust.json)
        #[arg(long, default_value = "sigil.trust.json")]
        store_path: PathBuf,

        #[command(subcommand)]
        command: TrustCommands,
    },

    /// Start a local or production Sigil Transparency Registry server
    Server {
        #[command(subcommand)]
        command: ServerCommands,
    },

    /// Inspect package metadata, capabilities, and author public key without installing
    Info {
        /// Path to the .sigil package
        package: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum TrustCommands {
    /// Add a trusted publisher public key to explicit keyring
    Add {
        /// Author's 32-byte Ed25519 public key in hex
        pubkey: String,

        /// Identity or label (e.g. "Alice <alice@corp.com>")
        #[arg(short, long)]
        identity: String,

        /// Package scope pattern to trust (e.g. "@acme/*" or "*")
        #[arg(short, long, default_value = "*")]
        scope: String,
    },

    /// Remove a publisher key from explicit keyring
    Remove {
        /// Public key in hex
        pubkey: String,
    },

    /// Revoke a compromised or retired publisher key
    Revoke {
        /// Public key in hex
        pubkey: String,

        /// Reason for revocation (e.g. "Key leaked", "Employee departure")
        #[arg(short, long, default_value = "Compromised or retired key")]
        reason: String,
    },

    /// List all trusted publisher public keys in explicit keyring
    List,
}

#[derive(Subcommand, Debug)]
pub enum ServerCommands {
    /// Start the Sigil Transparency Log and Package Distribution Registry server
    Start {
        /// Port to bind the server to
        #[arg(short, long, default_value_t = 8080)]
        port: u16,

        /// Explicit data storage directory for transparency log and packages (REQUIRED)
        #[arg(short, long)]
        storage: PathBuf,
    },
}
