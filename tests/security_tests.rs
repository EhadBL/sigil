use sigil::crypto;
use sigil::envelope::SigilEnvelope;
use sigil::lockfile::SigilLockfile;
use sigil::manifest::SigilManifest;
use sigil::merkle::{self, MerkleTree};
use sigil::packager::Packager;
use sigil::server::{is_valid_package_name, is_valid_version};
use sigil::trust::TrustStore;
use sigil::verifier::Verifier;
use std::fs::{self, File};
use tar::{Builder, Header};

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
    assert!(unpack_res.is_ok(), "unpack failed: {:?}", unpack_res.err());
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
    assert!(
        Verifier::verify_package(&package_path, Some(&pub_hex)).is_err(),
        "Corrupted package bytes must fail verification!"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_key_revocation_and_fail_closed() {
    let (_signing_key, verifying_key) = crypto::generate_keypair();
    let pub_hex = crypto::export_verifying_key_hex(&verifying_key);

    let mut store = TrustStore::default();

    // 1. Empty trust store fails closed
    assert!(!store.is_trusted(&pub_hex, "any-package"));

    // 2. Add trusted key
    store
        .add_key(pub_hex.clone(), "Lead Architect".into(), "*".into())
        .unwrap();
    assert!(store.is_trusted(&pub_hex, "any-package"));

    // 3. Revoke key
    store
        .revoke_key(&pub_hex, "Laptop stolen in transit")
        .unwrap();
    assert!(store.is_revoked(&pub_hex));

    // 4. Revoked key must never be trusted even with wildcard scope
    assert!(!store.is_trusted(&pub_hex, "any-package"));

    // 5. Trying to add a revoked key again must be rejected
    assert!(store
        .add_key(pub_hex.clone(), "Attacker".into(), "*".into())
        .is_err());
}

#[test]
fn test_merkle_inclusion_proofs_and_domain_separation() {
    let leaves: Vec<&[u8]> = vec![
        b"entry-0:core@1.0.0",
        b"entry-1:react@18.2.0",
        b"entry-2:utils@2.1.0",
        b"entry-3:crypto@0.4.0",
        b"entry-4:sigil@1.0.0",
    ];

    let tree = MerkleTree::from_raw_leaves(&leaves);
    let root = tree.root_hex();

    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.generate_inclusion_proof(i).unwrap();
        let valid = merkle::verify_inclusion_proof_raw(&root, leaf, &proof).unwrap();
        assert!(valid, "Inclusion proof for leaf {} must succeed", i);

        // Verification must fail with forged leaf
        let forged_leaf = b"entry-fake:malicious@99.9.9";
        let forged_valid = merkle::verify_inclusion_proof_raw(&root, forged_leaf, &proof).unwrap();
        assert!(!forged_valid, "Forged leaf must fail inclusion proof");
    }
}

#[test]
fn test_naming_and_version_sanitization() {
    // Valid names
    assert!(is_valid_package_name("my-package"));
    assert!(is_valid_package_name("@acme/core-utils"));
    assert!(is_valid_package_name("sigil_tool.rs"));

    // Illegal / path traversal names
    assert!(!is_valid_package_name(""));
    assert!(!is_valid_package_name("../../etc/passwd"));
    assert!(!is_valid_package_name("foo/../../bar"));
    assert!(!is_valid_package_name("@scope/nested/tool"));
    assert!(!is_valid_package_name("pkg:name"));
    assert!(!is_valid_package_name("pkg\0null"));

    // Valid versions
    assert!(is_valid_version("0.1.0"));
    assert!(is_valid_version("1.2.3-beta.1"));
    assert!(is_valid_version("2.0.0+build123"));

    // Illegal versions
    assert!(!is_valid_version(""));
    assert!(!is_valid_version("1.0/../../evil"));
    assert!(!is_valid_version("1.0\0bad"));
    assert!(!is_valid_version("1.0;rm -rf /"));
}

#[test]
fn test_symlink_zip_slip_payload_strictly_rejected() {
    let temp_dir = std::env::temp_dir().join("sigil_symlink_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let malicious_sigil = temp_dir.join("malicious.sigil");

    // Construct a tar containing a symlink entry in content.tar.gz
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let mut gz_buf = Vec::new();
    {
        let gz = GzEncoder::new(&mut gz_buf, Compression::best());
        let mut tar = Builder::new(gz);

        let mut header = Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        tar.append_link(&mut header, "escape_link", "/etc/passwd").unwrap();
        tar.into_inner().unwrap().finish().unwrap();
    }

    let (signing_key, _verifying_key) = crypto::generate_keypair();
    let content_hash = crypto::hash_bytes(&gz_buf).to_hex().to_string();
    let manifest = SigilManifest::default_template("evil-pkg");

    let envelope = SigilEnvelope::sign_and_create(manifest, content_hash, vec![], &signing_key).unwrap();
    let envelope_json = serde_json::to_vec(&envelope).unwrap();

    // Package into .sigil outer tar
    {
        let out = File::create(&malicious_sigil).unwrap();
        let mut bundle = Builder::new(out);

        let mut env_h = Header::new_gnu();
        env_h.set_size(envelope_json.len() as u64);
        env_h.set_mode(0o644);
        env_h.set_cksum();
        bundle.append_data(&mut env_h, "envelope.sigil.json", &envelope_json[..]).unwrap();

        let mut cnt_h = Header::new_gnu();
        cnt_h.set_size(gz_buf.len() as u64);
        cnt_h.set_mode(0o644);
        cnt_h.set_cksum();
        bundle.append_data(&mut cnt_h, "content.tar.gz", &gz_buf[..]).unwrap();

        bundle.finish().unwrap();
    }

    // Unpack must strictly reject with security violation
    let unpack_dest = temp_dir.join("extracted");
    let unpack_result = Packager::unpack_verified(&malicious_sigil, &unpack_dest);
    assert!(
        unpack_result.is_err(),
        "Malicious archive with symlink must be strictly rejected!"
    );

    // Verify must also reject it
    let verify_result = Verifier::verify_package(&malicious_sigil, None);
    assert!(
        verify_result.is_err(),
        "Verification of package with symlink must fail!"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}
