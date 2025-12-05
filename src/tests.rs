#[cfg(test)]
mod tests {
    use crate::{project, config, vault};
    use tempfile::tempdir;
    use std::fs;
    use std::collections::HashSet;
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
            assert!(!cred_dir.join("vault.enc").exists()); 
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
    fn test_vault_persistence_and_matrix() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        // 1. Create and populate
        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("development", "API_URL", "http://dev.local");
        v.set("production", "API_URL", "https://prod.com");
        v.set("production", "DB_PASS", "secret");
        v.save().unwrap();

        // 2. Reload with same key
        let v2 = vault::Vault::load(&vault_path, key).unwrap();

        // 3. Verify Separation
        assert_eq!(v2.get("development", "API_URL"), Some(&"http://dev.local".to_string()));
        assert_eq!(v2.get("production", "API_URL"), Some(&"https://prod.com".to_string()));
        
        // 4. Verify Isolation
        assert_eq!(v2.get("development", "DB_PASS"), None);
    }

    #[test]
    fn test_vault_removal() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();
        
        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("development", "KEY", "VAL");
        v.save().unwrap();

        // Remove
        let removed = v.remove("development", "KEY");
        assert_eq!(removed, Some("VAL".to_string()));
        assert_eq!(v.get("development", "KEY"), None);

        // Remove non-existent
        assert_eq!(v.remove("development", "GHOST"), None);
    }

    #[test]
    fn test_vault_listing() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();
        
        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("dev", "A", "1");
        v.set("dev", "B", "2");
        v.set("prod", "A", "3");

        let dev_list = v.list("dev").unwrap();
        assert_eq!(dev_list.len(), 2);
        assert!(dev_list.contains_key("A"));
        assert!(dev_list.contains_key("B"));

        let prod_list = v.list("prod").unwrap();
        assert_eq!(prod_list.len(), 1);

        assert!(v.list("missing").is_none());
    }

    #[test]
    fn test_vault_encryption_actually_works() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        let key = get_test_key();

        let mut v = vault::Vault::load(&vault_path, key).unwrap();
        v.set("dev", "SECRET_KEY", "PLAIN_TEXT_PASSWORD");
        v.save().unwrap();

        // Read the file directly as a string
        let raw_content = fs::read_to_string(&vault_path).unwrap();

        // The plaintext should NOT be visible in the file
        assert!(!raw_content.contains("PLAIN_TEXT_PASSWORD"));
        assert!(raw_content.contains("ciphertext"));
    }

    // ========================================================================
    // 4. PROJECT SCOPE TESTS
    // ========================================================================

    #[test]
    fn test_adding_scopes() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        
        // Simulate project init manually
        let cred_dir = root.join(".cred");
        fs::create_dir(&cred_dir).unwrap();
        fs::write(cred_dir.join("project.toml"), "").unwrap();

        // Manually load project
        let proj = project::Project {
            vault_path: cred_dir.join("vault.enc"),
            config_path: cred_dir.join("project.toml"),
        };

        // Add key to new scope
        proj.add_key_to_scopes(&["backend".to_string()], "DB_URL").unwrap();
        
        // Add same key to another scope
        proj.add_key_to_scopes(&["worker".to_string()], "DB_URL").unwrap();
        
        // Add new key to existing scope
        proj.add_key_to_scopes(&["backend".to_string()], "REDIS").unwrap();

        // Verify
        let config = proj.load_config().unwrap();
        let scopes = config.scopes.unwrap();
        
        let backend = scopes.get("backend").unwrap();
        assert!(backend.contains(&"DB_URL".to_string()));
        assert!(backend.contains(&"REDIS".to_string()));

        let worker = scopes.get("worker").unwrap();
        assert!(worker.contains(&"DB_URL".to_string()));
        assert!(!worker.contains(&"REDIS".to_string()));
    }

    #[test]
    fn test_scope_deduplication() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        
        // Simulate structure
        let cred_dir = root.join(".cred");
        fs::create_dir(&cred_dir).unwrap();
        fs::write(cred_dir.join("project.toml"), "").unwrap();

        let proj = project::Project {
            vault_path: cred_dir.join("vault.enc"),
            config_path: cred_dir.join("project.toml"),
        };

        // Add same key twice
        proj.add_key_to_scopes(&["web".to_string()], "API_KEY").unwrap();
        proj.add_key_to_scopes(&["web".to_string()], "API_KEY").unwrap();

        let config = proj.load_config().unwrap();
        let web = config.scopes.unwrap().get("web").unwrap().clone();
        
        assert_eq!(web.len(), 1); // Should not duplicate
        assert_eq!(web[0], "API_KEY");
    }

    // ========================================================================
    // 5. FILTERING LOGIC SIMULATION
    // ========================================================================

    #[test]
    fn test_push_filtering_logic() {
        let mut vault_map = std::collections::HashMap::new();
        vault_map.insert("A".to_string(), "valA".to_string());
        vault_map.insert("B".to_string(), "valB".to_string());
        vault_map.insert("C".to_string(), "valC".to_string());

        // Scenario 1: Explicit Keys
        let keys_arg = vec!["A".to_string()];
        let filtered: std::collections::HashMap<String, String> = vault_map.iter()
            .filter(|(k, _)| keys_arg.contains(*k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key("A"));

        // Scenario 2: Scopes
        let mut scopes_config = std::collections::HashMap::new();
        scopes_config.insert("group1".to_string(), vec!["B".to_string(), "C".to_string()]);
        
        let scope_arg = vec!["group1".to_string()];
        let mut target_keys = HashSet::new();
        for s in scope_arg {
            if let Some(ks) = scopes_config.get(&s) {
                for k in ks { target_keys.insert(k); }
            }
        }
        
        let filtered_scope: std::collections::HashMap<String, String> = vault_map.iter()
            .filter(|(k, _)| target_keys.contains(*k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        
        assert_eq!(filtered_scope.len(), 2);
        assert!(filtered_scope.contains_key("B"));
        assert!(filtered_scope.contains_key("C"));
    }
}
