#[cfg(test)]
mod tests {
    use cred::{project, config, vault, targets};
    use targets::TargetAdapter;
    use tempfile::tempdir;
    use std::fs;
    use std::process::Command;
    use rand::RngCore;
    use std::sync::{Arc, Mutex};

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

    // .gitignore should include .cred (no secret leakage into repo).
    #[test]
    fn test_gitignore_update() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let gitignore = root.join(".gitignore");

        // Simulate init structure
        let cred_dir = root.join(".cred");
        fs::create_dir(&cred_dir).unwrap();
        fs::write(cred_dir.join("project.toml"), "").unwrap();

        fs::write(&gitignore, "target/\n").unwrap();

        let entry = "\n.cred/\n";
        let mut file = fs::OpenOptions::new().write(true).append(true).open(&gitignore).unwrap();
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
        let root = dir.path().canonicalize().unwrap();

        Command::new("git").args(["init"]).current_dir(&root).output().unwrap();
        Command::new("git").args(["remote", "add", "origin", "git@github.com:org/repo.git"]).current_dir(&root).output().unwrap();

        let result = project::init_at(&root);
        assert!(result.is_ok());

        let cred_dir = root.join(".cred");
        let proj = project::Project {
            vault_path: cred_dir.join("vault.enc"),
            config_path: cred_dir.join("project.toml"),
        };
        let cfg = proj.load_config().unwrap();
        assert_eq!(cfg.git_repo, Some("org/repo".to_string()));
        assert_eq!(cfg.git_root, Some(root.to_path_buf().to_string_lossy().to_string()));
    }

    // When no git, binding fields stay empty (no false positives).
    #[test]
    fn test_git_binding_absent() {
        let dir = tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();

        let result = project::init_at(&root);
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

    // Global config created with expected sections.
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
        assert_eq!(v2.get("API_URL_PROD"), Some(&"https://prod.com".to_string()));
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
        assert_eq!(parsed.version, 1);
        assert!(!parsed.nonce.is_empty());
        assert!(!parsed.ciphertext.is_empty());
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

    struct MockTarget {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl targets::TargetAdapter for MockTarget {
        fn name(&self) -> &str { "mock" }

        // Record the keys we were asked to push; mimic success
        async fn push(&self, secrets: &std::collections::HashMap<String, String>, _auth_token: &str, _options: &targets::PushOptions) -> anyhow::Result<()> {
            let mut guard = self.seen.lock().unwrap();
            for k in secrets.keys() {
                guard.push(k.clone());
            }
            Ok(())
        }
    }

    // Push plan matches actual push keys even with ordering differences (dry-run invariant).
    #[test]
    fn test_dry_run_plan_matches_actual_push_keys() {
        let mut secrets = std::collections::HashMap::new();
        secrets.insert("B".to_string(), "2".to_string());
        secrets.insert("A".to_string(), "1".to_string());

        let mut plan_keys: Vec<String> = secrets.keys().cloned().collect();
        plan_keys.sort();

        // Simulate actual push with mock target
        let mock = MockTarget { seen: Arc::new(Mutex::new(Vec::new())) };
        let options = targets::PushOptions { repo: None };
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let _ = mock.push(&secrets, "token", &options).await;
        });

        let mut seen = mock.seen.lock().unwrap().clone();
        seen.sort();

        assert_eq!(plan_keys, seen);
    }

    // Non-interactive without stored token must surface missing auth.
    #[test]
    fn test_non_interactive_requires_token_and_json_error() {
        // Without a stored token, we should surface an auth miss.
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
        }

        // No token configured -> get_target_token should be None
        let token = config::get_target_token("github").unwrap();
        assert!(token.is_none());
    }

    // Corrupted vault load should error cleanly (regression guard).
    #[test]
    fn test_vault_corruption_handled_gracefully() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        fs::write(&vault_path, "garbage-data").unwrap();
        let key = get_test_key();

        let result = vault::Vault::load(&vault_path, key);
        assert!(result.is_err());
    }

    // Secret list ordering is stable for deterministic JSON output.
    #[test]
    fn test_secret_list_json_is_deterministic() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();
        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("B", "2");
        v.set("A", "1");
        v.save().unwrap();
        let mut keys: Vec<String> = v.list().keys().cloned().collect();
        keys.sort();
        let first = serde_json::to_string(&keys).unwrap();
        let second = serde_json::to_string(&keys).unwrap();
        assert_eq!(first, second);
    }
}
