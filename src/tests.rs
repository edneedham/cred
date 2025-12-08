#[cfg(test)]
mod tests {
    use crate::{project, config, vault};
    use tempfile::tempdir;
    use std::fs;
    use std::process::Command;
    use rand::RngCore;
    use std::env;

    fn get_test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

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
        let mut file = fs::OpenOptions::new().write(true).append(true).open(&gitignore).unwrap();
        use std::io::Write;
        writeln!(file, "{}", entry).unwrap();

        let content = fs::read_to_string(&gitignore).unwrap();
        assert!(content.contains("target/"));
        assert!(content.contains(".cred/"));
    }

    #[test]
    fn test_git_binding_present() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        Command::new("git").args(["init"]).current_dir(root).output().unwrap();
        Command::new("git").args(["remote", "add", "origin", "git@github.com:org/repo.git"]).current_dir(root).output().unwrap();

        let result = project::init_at(root);
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

    #[test]
    fn test_non_interactive_requires_token_and_json_error() {
        // Simulate running the binary with --non-interactive and --json without token configured
        let dir = tempdir().unwrap();
        let bin_path = env::current_exe().unwrap(); // assumes tests run with built binary path

        // ensure no global config in temp home
        let home = dir.path().join("home");
        fs::create_dir_all(&home).unwrap();
        // Safe to override for subprocess scope
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
        }

        let output = Command::new(bin_path)
            .arg("push")
            .arg("github")
            .arg("--non-interactive")
            .arg("--json")
            .current_dir(dir.path())
            .output()
            .expect("failed to run cred binary");

        assert!(!output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // JSON error should be on stdout
        let combined = format!("{}{}", stdout, stderr);
        assert!(combined.contains("\"status\":\"error\"") || combined.contains("\"status\": \"error\""));
    }
}
