use sigil::crypto;
use sigil::lockfile::SigilLockfile;
use sigil::manifest::SigilManifest;
use sigil::packager::Packager;
use sigil::trust::TrustStore;
use sigil::verifier::Verifier;
use std::fs;

#[test]
fn test_crypto_signing_and_verification() {
    let (signing_key, verifying_key) = crypto::generate_keypair();
    let data = b"CRITICAL_ZERO_DAY_PROOF_PAYLOAD";

    let signature = crypto::sign_payload(&signing_key, data);
    assert!(crypto::verify_signature(&verifying_key, data, &signature).is_ok());

    // Tampered payload must fail
    let tampered_data = b"TAMPERED_PAYLOAD";
    assert!(crypto::verify_signature(&verifying_key, tampered_data, &signature).is_err());
}

#[test]
fn test_full_pack_verify_lockfile_and_trust_flow() {
    let temp_dir = std::env::temp_dir().join("sigil_test_full_suite");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let src_dir = temp_dir.join("my_package");
    fs::create_dir_all(&src_dir).unwrap();

    // 1. Create a valid sigil.toml
    let manifest = SigilManifest::default_template("@corp/secure-core");
    manifest.to_file(src_dir.join("sigil.toml")).unwrap();

    // Create source files
    fs::write(src_dir.join("index.js"), b"console.log('Secure module running');").unwrap();
    fs::write(src_dir.join("util.js"), b"export const add = (a, b) => a + b;").unwrap();

    // 2. Generate Keypair
    let (signing_key, verifying_key) = crypto::generate_keypair();
    let pub_hex = crypto::export_verifying_key_hex(&verifying_key);

    // 3. Test Trust Store & Scope Enforcement with explicit path
    let trust_path = temp_dir.join("explicit_trust.json");
    let mut trust_store = TrustStore::default();
    trust_store.add_key(pub_hex.clone(), "Alice Corp".into(), "@corp/*".into()).unwrap();
    trust_store.save_to(&trust_path).unwrap();

    let loaded_store = TrustStore::load_from(&trust_path).unwrap();
    assert!(loaded_store.is_trusted(&pub_hex, "@corp/secure-core"));
    assert!(!loaded_store.is_trusted(&pub_hex, "@malicious/other-package"));

    // 4. Pack and Sign
    let package_path = temp_dir.join("corp-secure-core-0.1.0.sigil");
    let envelope = Packager::pack(&src_dir, &package_path, &signing_key).unwrap();
    assert_eq!(envelope.manifest.package.name, "@corp/secure-core");
    assert_eq!(envelope.files.len(), 3); // sigil.toml, index.js, util.js

    // 5. Verify Cryptographic Integrity
    let report = Verifier::verify_package(&package_path, Some(&pub_hex)).unwrap();
    assert!(report.is_valid);
    assert_eq!(report.package_name, "@corp/secure-core");
    assert_eq!(report.author_pubkey, pub_hex);

    // 6. Test Lockfile recording & verification
    let lock_path = temp_dir.join("sigil.lock");
    let mut lockfile = SigilLockfile::default();
    lockfile.record_package(&envelope);
    lockfile.save(&lock_path).unwrap();

    let reloaded_lock = SigilLockfile::load(&lock_path).unwrap();
    assert!(reloaded_lock.verify_against_lock(&envelope).is_ok());

    // Tampered envelope check against lockfile
    let mut tampered_envelope = envelope.clone();
    tampered_envelope.content_hash = "0".repeat(64);
    assert!(reloaded_lock.verify_against_lock(&tampered_envelope).is_err());

    // 7. Test Safe Extraction (Path Traversal Protection)
    let install_dest = temp_dir.join("installed_modules").join("corp-secure-core");
    let unpack_res = Packager::unpack_verified(&package_path, &install_dest);
    assert!(unpack_res.is_ok());
    assert!(install_dest.join("index.js").exists());
    assert!(install_dest.join("util.js").exists());

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_tampered_package_bytes_strictly_fails() {
    let temp_dir = std::env::temp_dir().join("sigil_tamper_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let src_dir = temp_dir.join("tamper_pkg");
    fs::create_dir_all(&src_dir).unwrap();

    let manifest = SigilManifest::default_template("tamper-proof-lib");
    manifest.to_file(src_dir.join("sigil.toml")).unwrap();
    fs::write(src_dir.join("code.js"), b"const secure = true;").unwrap();

    let (signing_key, verifying_key) = crypto::generate_keypair();
    let pub_hex = crypto::export_verifying_key_hex(&verifying_key);

    let package_path = temp_dir.join("tamper-lib.sigil");
    Packager::pack(&src_dir, &package_path, &signing_key).unwrap();

    // Valid check first
    assert!(Verifier::verify_package(&package_path, Some(&pub_hex)).is_ok());

    // Corrupt 1 byte in the package file
    let mut bytes = fs::read(&package_path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF; // Flip bits
    fs::write(&package_path, bytes).unwrap();

    // MUST FAIL with error
    assert!(Verifier::verify_package(&package_path, Some(&pub_hex)).is_err(), "Corrupted package bytes must fail verification!");

    let _ = fs::remove_dir_all(&temp_dir);
}

