use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid hex encoding: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Invalid signature bytes")]
    InvalidSignature,
    #[error("Signature verification failed: package has been tampered with or key is invalid")]
    VerificationFailed,
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
}

/// Generates a new cryptographically secure Ed25519 keypair using OS entropy.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Hashes arbitrary bytes using BLAKE3 (cryptographically secure and fast).
pub fn hash_bytes(data: &[u8]) -> blake3::Hash {
    blake3::hash(data)
}

/// Computes the BLAKE3 hash of a file by streaming chunks.
pub fn hash_file<P: AsRef<Path>>(path: P) -> Result<String, CryptoError> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Signs a canonical byte payload using an Ed25519 signing key.
pub fn sign_payload(signing_key: &SigningKey, payload: &[u8]) -> String {
    let signature = signing_key.sign(payload);
    hex::encode(signature.to_bytes())
}

/// Verifies that an Ed25519 signature corresponds to the payload and public key.
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), CryptoError> {
    let sig_bytes = hex::decode(signature_hex)?;
    if sig_bytes.len() != 64 {
        return Err(CryptoError::InvalidSignature);
    }

    let mut sig_fixed = [0u8; 64];
    sig_fixed.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_fixed);

    verifying_key
        .verify(payload, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Exports a signing key as hex bytes.
pub fn export_signing_key_hex(signing_key: &SigningKey) -> String {
    hex::encode(signing_key.to_bytes())
}

/// Imports a signing key from a hex string.
pub fn import_signing_key_hex(hex_str: &str) -> Result<SigningKey, CryptoError> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKey("Signing key must be 32 bytes".into()));
    }
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&fixed))
}

/// Exports a verifying key as hex bytes.
pub fn export_verifying_key_hex(verifying_key: &VerifyingKey) -> String {
    hex::encode(verifying_key.to_bytes())
}

/// Imports a verifying key from a hex string.
pub fn import_verifying_key_hex(hex_str: &str) -> Result<VerifyingKey, CryptoError> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKey("Verifying key must be 32 bytes".into()));
    }
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&fixed).map_err(|e| CryptoError::InvalidKey(e.to_string()))
}
