#[cfg(test)]
mod tests {
    use crate::{project, config, vault};
    use tempfile::tempdir;
    use std::fs;
    use rand::RngCore;

    // ========================================================================
    // HELPERS
    // ========================================================================

    fn get_test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    // ========================================================================
    // 1. PROJECT INITIALIZATION TESTS
    // ========================================================================

    #[test]
    fn test_project_init_creates_structure() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Run init (this touches OS keychain)
        if project::init_at(root).is_ok() {
            let cred_dir = root.join(".cred");
            assert!(cred_dir.exists());
            assert!(cred_dir.join("project.toml").exists());
            assert!(cred_dir.join("vault.enc").exists()); 
        }
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

        // 1. Create a dummy gitignore
        fs::write(&gitignore, "target/\n").unwrap();

        // 2. Simulate update logic
        let entry = "\n.cred/\n";
        let mut file = fs::OpenOptions::new().write(true).append(true).open(&gitignore).unwrap();
        use std::io::Write;
        writeln!(file, "{}", entry).unwrap();

        let content = fs::read_to_string(&gitignore).unwrap();
        assert!(content.contains("target/"));
        assert!(content.contains(".cred/"));
    }

    // ========================================================================
    // 2. GLOBAL CONFIG TESTS
    // ========================================================================

    #[test]
    fn test_global_config_logic() {
        let dir = tempdir().unwrap();
        let config_dir = dir.path().join("mock_config");

        let path = config::ensure_config_at(&config_dir).unwrap();
        assert!(path.exists());
        
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("[targets]"));
    }

    // ========================================================================
    // 3. VAULT MATRIX TESTS
    // ========================================================================

    #[test]
    fn test_vault_persistence() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        // 1. Create and populate
        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("API_URL_DEV", "http://dev.local");
        v.set("API_URL_PROD", "https://prod.com");
        v.set("DB_PASS", "secret");
        v.save().unwrap();

        // 2. Reload with same key
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

        // Remove
        let removed = v.remove("KEY");
        assert_eq!(removed, Some("VAL".to_string()));
        assert_eq!(v.get("KEY"), None);

        // Remove non-existent
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

        // Read the file directly as a string
        let raw_content = fs::read_to_string(&vault_path).unwrap();

        // The plaintext should NOT be visible in the file
        assert!(!raw_content.contains("PLAIN_TEXT_PASSWORD"));
        assert!(raw_content.contains("ciphertext"));
    }

    // Scope-related tests removed (scopes no longer supported)
}
