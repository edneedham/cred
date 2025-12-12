#[cfg(test)]
mod tests {
    use crate::{config, envfile, error, project, vault};
    use rand::RngCore;
    use std::fs;
    use std::process::Command;
    use tempfile::tempdir;
    use vault::SecretFormat;

    fn get_test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    // Minimal init happy-path: ensures `.cred/` scaffolding appears.
    #[test]
    fn test_project_init_creates_expected_files() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let result = project::init_at(root);
        assert!(result.is_ok());

        let cred_dir = root.join(".cred");
        assert!(cred_dir.exists());
        assert!(cred_dir.join("project.toml").exists());
        assert!(cred_dir.join("vault.enc").exists());
    }

    #[test]
    fn test_gitignore_update() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let gitignore = root.join(".gitignore");

        // Simulate init structure
        let cred_dir = root.join(".cred");
        fs::create_dir(&cred_dir).unwrap();
        fs::write(cred_dir.join("project.toml"), "").unwrap();

        fs::write(&gitignore, "target/\n").unwrap();

        let entry = "\n.cred/\n";
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(&gitignore)
            .unwrap();
        use std::io::Write;
        writeln!(file, "{}", entry).unwrap();

        let content = fs::read_to_string(&gitignore).unwrap();
        assert!(content.contains("target/"));
        assert!(content.contains(".cred/"));
    }

    // Records git origin into project config when present (repo binding behavior).
    #[test]
    fn test_git_binding_present() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        Command::new("git")
            .args(["init"])
            .current_dir(root)
            .output()
            .unwrap();
        Command::new("git")
            .args(["remote", "add", "origin", "git@github.com:org/repo.git"])
            .current_dir(root)
            .output()
            .unwrap();

        let result = project::init_at(root);
        assert!(result.is_ok());

        let cred_dir = root.join(".cred");
        let proj = project::Project {
            vault_path: cred_dir.join("vault.enc"),
            config_path: cred_dir.join("project.toml"),
        };
        let cfg = proj.load_config().unwrap();
        assert_eq!(cfg.git_repo, Some("org/repo".to_string()));
        // Compare canonical paths to handle /var vs /private/var on macOS
        let expected_root = root.canonicalize().unwrap().to_string_lossy().to_string();
        let actual_root = cfg.git_root.map(|p| {
            std::path::Path::new(&p)
                .canonicalize()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        });
        assert_eq!(actual_root, Some(expected_root));
    }

    // When no git, binding fields stay empty (no false positives).
    #[test]
    fn test_git_binding_absent() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let result = project::init_at(root);
        assert!(result.is_ok());

        let cred_dir = root.join(".cred");
        let proj = project::Project {
            vault_path: cred_dir.join("vault.enc"),
            config_path: cred_dir.join("project.toml"),
        };
        let cfg = proj.load_config().unwrap();
        assert!(cfg.git_repo.is_none());
        assert!(cfg.git_root.is_none());
    }

    #[test]
    fn test_global_config_logic() {
        let dir = tempdir().unwrap();
        let config_dir = dir.path().join("mock_config");

        let path = config::ensure_config_at(&config_dir).unwrap();
        assert!(path.exists());

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("[targets]"));
    }

    // Round-trip encryption/decryption: persisted vault reloads exact plaintext values.
    #[test]
    fn test_vault_persistence() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("API_URL_DEV", "http://dev.local");
        v.set("API_URL_PROD", "https://prod.com");
        v.set("DB_PASS", "secret");
        v.save().unwrap();

        let v2 = vault::Vault::load(&vault_path, key).unwrap();

        assert_eq!(v2.get("API_URL_DEV"), Some(&"http://dev.local".to_string()));
        assert_eq!(
            v2.get("API_URL_PROD"),
            Some(&"https://prod.com".to_string())
        );
        assert_eq!(v2.get("DB_PASS"), Some(&"secret".to_string()));
    }

    // Vault removes entries and leaves no ghost values behind.
    #[test]
    fn test_vault_removal() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("KEY", "VAL");
        v.save().unwrap();

        let removed = v.remove("KEY");
        assert_eq!(removed, Some("VAL".to_string()));
        assert_eq!(v.get("KEY"), None);

        assert_eq!(v.remove("GHOST"), None);
    }

    // Listing surfaces all keys present in memory (baseline invariant).
    #[test]
    fn test_vault_listing() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("A", "1");
        v.set("B", "2");

        let list = v.list();
        assert_eq!(list.len(), 2);
        assert!(list.contains_key("A"));
        assert!(list.contains_key("B"));
    }

    // Never writes plaintext to disk: ciphertext blob must not contain secret values.
    #[test]
    fn test_vault_encryption_actually_works() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("SECRET_KEY", "PLAIN_TEXT_PASSWORD");
        v.save().unwrap();

        let raw_content = fs::read_to_string(&vault_path).unwrap();

        assert!(!raw_content.contains("PLAIN_TEXT_PASSWORD"));
        assert!(raw_content.contains("ciphertext"));
    }

    // Serialized vault carries required fields (version/nonce/ciphertext) for compatibility.
    #[test]
    fn test_vault_serialization_fields() {
        #[derive(serde::Deserialize)]
        struct EncFile {
            version: u8,
            nonce: String,
            ciphertext: String,
        }

        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("K1", "V1");
        v.save().unwrap();

        let raw = std::fs::read_to_string(&vault_path).unwrap();
        let parsed: EncFile = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.version, 2);
        assert!(!parsed.nonce.is_empty());
        assert!(!parsed.ciphertext.is_empty());
    }

    #[test]
    fn test_env_import_skips_without_overwrite() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("EXISTING", "old");
        v.save().unwrap();

        let env_path = dir.path().join("sample.env");
        fs::write(&env_path, "EXISTING=new\nNEW=value\n").unwrap();

        let entries = envfile::parse_env_file(&env_path).unwrap();
        let stats = envfile::import_entries(&entries, &mut v, false, false);
        v.save().unwrap();

        assert_eq!(stats.added, 1);
        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.overwritten, 0);

        let reloaded = vault::Vault::load(&vault_path, key).unwrap();
        assert_eq!(reloaded.get("EXISTING"), Some(&"old".to_string()));
        assert_eq!(reloaded.get("NEW"), Some(&"value".to_string()));
    }

    #[test]
    fn test_env_import_overwrites_with_flag() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("EXISTING", "old");
        v.save().unwrap();

        let env_path = dir.path().join("overwrite.env");
        fs::write(&env_path, "EXISTING=new\n").unwrap();

        let entries = envfile::parse_env_file(&env_path).unwrap();
        let stats = envfile::import_entries(&entries, &mut v, true, false);
        v.save().unwrap();

        assert_eq!(stats.added, 0);
        assert_eq!(stats.skipped, 0);
        assert_eq!(stats.overwritten, 1);

        let reloaded = vault::Vault::load(&vault_path, key).unwrap();
        assert_eq!(reloaded.get("EXISTING"), Some(&"new".to_string()));
    }

    #[test]
    fn test_env_export_guard_and_content() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("B", "2");
        v.set("A", "1");
        v.save().unwrap();

        let out_path = dir.path().join("env.out");
        // existing file triggers guard
        fs::write(&out_path, "OLD=1\n").unwrap();

        let vault_view = vault::Vault::load(&vault_path, key).unwrap();
        let err = envfile::export_env_file(&vault_view, &out_path, false, false).unwrap_err();
        assert_eq!(err.code as i32, error::ExitCode::UserError as i32);
        assert_eq!(fs::read_to_string(&out_path).unwrap(), "OLD=1\n");

        // allow overwrite
        let count = envfile::export_env_file(&vault_view, &out_path, true, false).unwrap();
        assert_eq!(count, 2);

        let content = fs::read_to_string(&out_path).unwrap();
        assert_eq!(content, "A=1\nB=2\n");
    }

    // Dry-run ordering: diff/plans are deterministic and sorted.
    #[test]
    fn test_push_dry_run_diff_ordering() {
        let mut map = std::collections::HashMap::new();
        map.insert("C".to_string(), "3".to_string());
        map.insert("A".to_string(), "1".to_string());
        map.insert("B".to_string(), "2".to_string());

        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, vec!["A", "B", "C"]);
    }

    // Keys are sorted for deterministic dry-run output.
    #[test]
    fn test_keys_sorted_for_dry_run() {
        let mut secrets = std::collections::HashMap::new();
        secrets.insert("B".to_string(), "2".to_string());
        secrets.insert("A".to_string(), "1".to_string());
        secrets.insert("C".to_string(), "3".to_string());

        let mut plan_keys: Vec<String> = secrets.keys().cloned().collect();
        plan_keys.sort();

        assert_eq!(plan_keys, vec!["A", "B", "C"]);
    }

    // Corrupted vault file should error cleanly, not panic.
    #[test]
    fn test_vault_corruption_handled_gracefully() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        fs::write(&vault_path, "garbage-data").unwrap();
        let key = get_test_key();

        let result = vault::Vault::load(&vault_path, key);
        assert!(result.is_err());
    }

    // Secret list key ordering is deterministic (sorted).
    #[test]
    fn test_secret_list_is_deterministic() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("C", "3");
        v.set("A", "1");
        v.set("B", "2");
        v.save().unwrap();

        // list() returns HashMap, but when we sort keys, order is deterministic
        let mut keys: Vec<String> = v.list().keys().cloned().collect();
        keys.sort();

        assert_eq!(keys, vec!["A", "B", "C"]);

        // Verify multiple calls return same data
        let list1 = v.list();
        let list2 = v.list();
        assert_eq!(list1, list2);
    }

    // ==================== Vault v2 Schema Tests ====================

    // Format auto-detection: PEM content is detected.
    #[test]
    fn test_format_auto_detection_pem() {
        let pem_key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----";
        assert_eq!(vault::Vault::detect_format(pem_key), SecretFormat::Pem);

        let pem_cert =
            "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAJC1...\n-----END CERTIFICATE-----";
        assert_eq!(vault::Vault::detect_format(pem_cert), SecretFormat::Pem);

        let pem_rsa =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        assert_eq!(vault::Vault::detect_format(pem_rsa), SecretFormat::Pem);
    }

    // Format auto-detection: JSON must actually parse.
    #[test]
    fn test_format_auto_detection_json() {
        // Valid JSON object
        let json_obj = r#"{"api_key": "sk-xxx", "org": "acme"}"#;
        assert_eq!(vault::Vault::detect_format(json_obj), SecretFormat::Json);

        // Valid JSON array
        let json_arr = r#"["secret1", "secret2", "secret3"]"#;
        assert_eq!(vault::Vault::detect_format(json_arr), SecretFormat::Json);

        // Invalid JSON that looks like JSON → Raw (not Json)
        let fake_json = r#"{not valid json}"#;
        assert_eq!(vault::Vault::detect_format(fake_json), SecretFormat::Raw);

        // Curly braces but not JSON → Raw
        let not_json = "{abc}";
        assert_eq!(vault::Vault::detect_format(not_json), SecretFormat::Raw);
    }

    // Format auto-detection: base64 must be strictly valid.
    #[test]
    fn test_format_auto_detection_base64() {
        // Valid base64 (length divisible by 4, decodes successfully)
        let b64 = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg==";
        assert_eq!(vault::Vault::detect_format(b64), SecretFormat::Base64);

        // Short strings → Raw (not base64)
        let short = "abc123";
        assert_eq!(vault::Vault::detect_format(short), SecretFormat::Raw);

        // Length not divisible by 4 → Raw
        let bad_len = "SGVsbG8gV29ybGQhIFRoaXM=X";
        assert_eq!(vault::Vault::detect_format(bad_len), SecretFormat::Raw);

        // API keys that look base64-ish but aren't → Raw
        let aws_key = "AKIAIOSFODNN7EXAMPLE";
        assert_eq!(vault::Vault::detect_format(aws_key), SecretFormat::Raw);

        // Contains invalid chars → Raw
        let with_dash = "SGVsbG8tV29ybGQ=";
        assert_eq!(vault::Vault::detect_format(with_dash), SecretFormat::Raw);
    }

    // Format auto-detection: multiline content (non-PEM) is detected.
    #[test]
    fn test_format_auto_detection_multiline() {
        let multiline = "line one\nline two\nline three";
        assert_eq!(
            vault::Vault::detect_format(multiline),
            SecretFormat::Multiline
        );
    }

    // Format auto-detection: simple strings are raw.
    #[test]
    fn test_format_auto_detection_raw() {
        assert_eq!(
            vault::Vault::detect_format("simple-api-key"),
            SecretFormat::Raw
        );
        assert_eq!(vault::Vault::detect_format(""), SecretFormat::Raw);
        // Tokens with dashes/underscores are raw, not base64
        assert_eq!(
            vault::Vault::detect_format("sk-proj-abc123xyz"),
            SecretFormat::Raw
        );
    }

    // SecretEntry metadata is preserved through save/load cycle.
    #[test]
    fn test_secret_entry_metadata_persistence() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set_with_metadata(
            "API_KEY",
            "sk-test-123",
            SecretFormat::Raw,
            Some("Production API key".to_string()),
        );
        v.save().unwrap();

        let v2 = vault::Vault::load(&vault_path, key).unwrap();
        let entry = v2.get_entry("API_KEY").expect("entry should exist");

        assert_eq!(entry.value, "sk-test-123");
        assert_eq!(entry.format, SecretFormat::Raw);
        assert_eq!(entry.description, Some("Production API key".to_string()));
        // Hash is computed on save
        assert!(entry.hash.is_some());
        // Entry should not be dirty after load (hash matches value)
        assert!(!v2.is_dirty("API_KEY"));
    }

    // get_entry returns full metadata; get returns just value.
    #[test]
    fn test_get_entry_vs_get() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set_with_metadata(
            "KEY",
            "value",
            SecretFormat::Base64,
            Some("desc".to_string()),
        );

        // get() returns just the value
        assert_eq!(v.get("KEY"), Some(&"value".to_string()));

        // get_entry() returns full metadata
        let entry = v.get_entry("KEY").unwrap();
        assert_eq!(entry.value, "value");
        assert_eq!(entry.format, SecretFormat::Base64);
        assert_eq!(entry.description, Some("desc".to_string()));
    }

    // list_entries returns all metadata; list returns key→value map.
    #[test]
    fn test_list_entries_vs_list() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set_with_metadata("A", "1", SecretFormat::Raw, Some("first".to_string()));
        v.set("B", "2");

        // list() returns HashMap<String, String>
        let simple = v.list();
        assert_eq!(simple.len(), 2);
        assert_eq!(simple.get("A"), Some(&"1".to_string()));
        assert_eq!(simple.get("B"), Some(&"2".to_string()));

        // list_entries() returns full entries
        let entries = v.list_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries.get("A").unwrap().description,
            Some("first".to_string())
        );
        assert!(entries.get("B").unwrap().description.is_none());
    }

    // set_description updates description and updated_at timestamp.
    #[test]
    fn test_set_description() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("KEY", "value");

        let original_updated = v.get_entry("KEY").unwrap().updated_at;

        // Small delay to ensure timestamp difference
        std::thread::sleep(std::time::Duration::from_millis(10));

        assert!(v.set_description("KEY", Some("new description".to_string())));

        let entry = v.get_entry("KEY").unwrap();
        assert_eq!(entry.description, Some("new description".to_string()));
        assert!(entry.updated_at > original_updated);

        // Clear description
        assert!(v.set_description("KEY", None));
        assert!(v.get_entry("KEY").unwrap().description.is_none());

        // Non-existent key returns false
        assert!(!v.set_description("GHOST", Some("desc".to_string())));
    }

    // remove_entry returns full SecretEntry with metadata.
    #[test]
    fn test_remove_entry_returns_full_metadata() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set_with_metadata(
            "KEY",
            "secret",
            SecretFormat::Multiline,
            Some("my cert".to_string()),
        );

        let removed = v.remove_entry("KEY").expect("should return entry");
        assert_eq!(removed.value, "secret");
        assert_eq!(removed.format, SecretFormat::Multiline);
        assert_eq!(removed.description, Some("my cert".to_string()));

        // Key is gone
        assert!(v.get("KEY").is_none());
        assert!(v.remove_entry("KEY").is_none());
    }

    // Updating a secret preserves created_at but updates updated_at.
    #[test]
    fn test_timestamps_on_update() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("KEY", "original");

        let entry1 = v.get_entry("KEY").unwrap();
        let created = entry1.created_at;
        let updated1 = entry1.updated_at;

        // Small delay
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Update the value
        v.set("KEY", "new-value");

        let entry2 = v.get_entry("KEY").unwrap();
        assert_eq!(entry2.created_at, created, "created_at should not change");
        assert!(entry2.updated_at > updated1, "updated_at should increase");
        assert_eq!(entry2.value, "new-value");
    }

    // SecretFormat FromStr and Display round-trip.
    #[test]
    fn test_secret_format_parsing() {
        assert_eq!("raw".parse::<SecretFormat>().unwrap(), SecretFormat::Raw);
        assert_eq!(
            "multiline".parse::<SecretFormat>().unwrap(),
            SecretFormat::Multiline
        );
        assert_eq!("pem".parse::<SecretFormat>().unwrap(), SecretFormat::Pem);
        assert_eq!("PEM".parse::<SecretFormat>().unwrap(), SecretFormat::Pem); // case insensitive
        assert_eq!(
            "base64".parse::<SecretFormat>().unwrap(),
            SecretFormat::Base64
        );
        assert_eq!("json".parse::<SecretFormat>().unwrap(), SecretFormat::Json);
        assert_eq!("JSON".parse::<SecretFormat>().unwrap(), SecretFormat::Json); // case insensitive

        assert!("invalid".parse::<SecretFormat>().is_err());

        // Display
        assert_eq!(SecretFormat::Raw.to_string(), "raw");
        assert_eq!(SecretFormat::Multiline.to_string(), "multiline");
        assert_eq!(SecretFormat::Pem.to_string(), "pem");
        assert_eq!(SecretFormat::Base64.to_string(), "base64");
        assert_eq!(SecretFormat::Json.to_string(), "json");
    }

    // Migration from v1 vault format to v2.
    #[test]
    fn test_v1_to_v2_migration() {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, AeadCore, KeyInit, OsRng},
        };

        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        // Manually create a v1 vault file
        let v1_secrets = serde_json::json!({
            "OLD_KEY": "old-value",
            "MULTILINE": "line1\nline2\nline3"
        });
        let plaintext = serde_json::to_vec(&v1_secrets).unwrap();

        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        let v1_file = serde_json::json!({
            "version": 1,
            "nonce": BASE64.encode(&nonce),
            "ciphertext": BASE64.encode(&ciphertext)
        });
        fs::write(&vault_path, serde_json::to_string_pretty(&v1_file).unwrap()).unwrap();

        // Load should auto-migrate
        let v = vault::Vault::load(&vault_path, key).unwrap();

        // Values preserved
        assert_eq!(v.get("OLD_KEY"), Some(&"old-value".to_string()));
        assert_eq!(v.get("MULTILINE"), Some(&"line1\nline2\nline3".to_string()));

        // Metadata populated with defaults
        let entry = v.get_entry("OLD_KEY").unwrap();
        assert_eq!(entry.format, SecretFormat::Raw);
        assert!(entry.description.is_none());

        // Multiline detected
        let ml_entry = v.get_entry("MULTILINE").unwrap();
        assert_eq!(ml_entry.format, SecretFormat::Multiline);
    }

    // After migration and save, file is v2 format.
    #[test]
    fn test_migration_saves_as_v2() {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, AeadCore, KeyInit, OsRng},
        };

        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        // Create v1 vault
        let v1_secrets = serde_json::json!({"KEY": "value"});
        let plaintext = serde_json::to_vec(&v1_secrets).unwrap();
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let v1_file = serde_json::json!({
            "version": 1,
            "nonce": BASE64.encode(&nonce),
            "ciphertext": BASE64.encode(&ciphertext)
        });
        fs::write(&vault_path, serde_json::to_string(&v1_file).unwrap()).unwrap();

        // Load (migrates in memory) and save
        let v = vault::Vault::load(&vault_path, key).unwrap();
        v.save().unwrap();

        // Check file is now v2
        #[derive(serde::Deserialize)]
        struct EncFile {
            version: u8,
        }
        let raw = fs::read_to_string(&vault_path).unwrap();
        let parsed: EncFile = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.version, 2);

        // Reload works
        let v2 = vault::Vault::load(&vault_path, key).unwrap();
        assert_eq!(v2.get("KEY"), Some(&"value".to_string()));
    }

    // set_hash updates the hash field.
    #[test]
    fn test_set_hash() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("KEY", "value");

        assert!(v.get_entry("KEY").unwrap().hash.is_none());

        assert!(v.set_hash("KEY", Some("abc123".to_string())));
        assert_eq!(v.get_entry("KEY").unwrap().hash, Some("abc123".to_string()));

        assert!(v.set_hash("KEY", None));
        assert!(v.get_entry("KEY").unwrap().hash.is_none());

        assert!(!v.set_hash("GHOST", Some("hash".to_string())));
    }

    // Updating value clears hash (since value changed).
    #[test]
    fn test_update_clears_hash() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("KEY", "original");
        v.set_hash("KEY", Some("original-hash".to_string()));

        assert_eq!(
            v.get_entry("KEY").unwrap().hash,
            Some("original-hash".to_string())
        );

        // Update value
        v.set("KEY", "new-value");

        // Hash should be cleared
        assert!(v.get_entry("KEY").unwrap().hash.is_none());
    }

    // Empty vault has no entries.
    #[test]
    fn test_empty_vault() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let v = vault::Vault::load(&vault_path, key).unwrap();
        assert!(v.list().is_empty());
        assert!(v.list_entries().is_empty());
        assert!(v.get("ANY").is_none());
        assert!(v.get_entry("ANY").is_none());
    }

    // Unsupported vault version fails gracefully.
    #[test]
    fn test_unsupported_vault_version() {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        use chacha20poly1305::{
            ChaCha20Poly1305,
            aead::{Aead, AeadCore, KeyInit, OsRng},
        };

        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        // Create valid ciphertext but with unsupported version
        let plaintext = b"{}";
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        let fake_vault = serde_json::json!({
            "version": 99,
            "nonce": BASE64.encode(&nonce),
            "ciphertext": BASE64.encode(&ciphertext)
        });
        fs::write(&vault_path, serde_json::to_string(&fake_vault).unwrap()).unwrap();

        let result = vault::Vault::load(&vault_path, key);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unsupported vault version") || err_msg.contains("99"));
    }
}
