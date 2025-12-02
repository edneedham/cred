#[cfg(test)]
mod tests {
    use crate::{project, config, vault};
    use tempfile::tempdir;
    use std::fs;
    use std::collections::HashSet;

    // ========================================================================
    // 1. PROJECT INITIALIZATION TESTS
    // ========================================================================

    #[test]
    fn test_project_init_creates_structure() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        // Run init
        assert!(project::init_at(root).is_ok());

        // Verify structure
        let cred_dir = root.join(".cred");
        assert!(cred_dir.exists());
        assert!(cred_dir.join("vault.json").exists());
        assert!(cred_dir.join("project.toml").exists());

        // Verify content defaults
        let project_content = fs::read_to_string(cred_dir.join("project.toml")).unwrap();
        assert!(project_content.contains("name = \"my-project\""));
        
        let vault_content = fs::read_to_string(cred_dir.join("vault.json")).unwrap();
        assert_eq!(vault_content, "{}");
    }

    #[test]
    fn test_gitignore_update() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let gitignore = root.join(".gitignore");

        // Case A: No .gitignore exists
        project::init_at(root).unwrap();
        let content = fs::read_to_string(&gitignore).unwrap();
        assert!(content.contains(".cred/"));

        // Case B: .gitignore exists but missing entry
        fs::write(&gitignore, "target/\n").unwrap();
        // Re-run update logic manually (since init fails if .cred exists)
        // We'll simulate it by deleting .cred first
        fs::remove_dir_all(root.join(".cred")).unwrap();
        project::init_at(root).unwrap();
        
        let content = fs::read_to_string(&gitignore).unwrap();
        assert!(content.contains("target/"));
        assert!(content.contains(".cred/"));
    }

    #[test]
    fn test_init_fails_if_already_exists() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        project::init_at(root).unwrap();
        // Run again
        let result = project::init_at(root);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already initialized"));
    }

    // ========================================================================
    // 2. GLOBAL CONFIG TESTS
    // ========================================================================

    #[test]
    fn test_global_config_logic() {
        let dir = tempdir().unwrap();
        // Simulate a custom config location
        let config_dir = dir.path().join("mock_config");

        let path = config::ensure_config_at(&config_dir).unwrap();
        assert!(path.exists());

        // Verify default content
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("[providers]"));
    }

    // ========================================================================
    // 3. VAULT MATRIX TESTS
    // ========================================================================

    #[test]
    fn test_vault_persistence_and_matrix() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");

        // 1. Create and populate
        let mut v = vault::Vault::load(&vault_path).unwrap();
        v.set("development", "API_URL", "http://dev.local");
        v.set("production", "API_URL", "https://prod.com");
        v.set("production", "DB_PASS", "secret");
        v.save().unwrap();

        // 2. Reload
        let v2 = vault::Vault::load(&vault_path).unwrap();

        // 3. Verify Separation
        assert_eq!(v2.get("development", "API_URL"), Some(&"http://dev.local".to_string()));
        assert_eq!(v2.get("production", "API_URL"), Some(&"https://prod.com".to_string()));
        
        // 4. Verify Isolation
        assert_eq!(v2.get("development", "DB_PASS"), None); 
    }

    #[test]
    fn test_vault_removal() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");
        let mut v = vault::Vault::load(&vault_path).unwrap();
        
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
        let vault_path = dir.path().join("vault.json");
        let mut v = vault::Vault::load(&vault_path).unwrap();
        
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

    // ========================================================================
    // 4. PROJECT SCOPE TESTS
    // ========================================================================

    #[test]
    fn test_adding_scopes() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        project::init_at(root).unwrap();

        // Manually load project
        let cred_dir = root.join(".cred");
        let proj = project::Project {
            vault_path: cred_dir.join("vault.json"),
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
        project::init_at(root).unwrap();
        let cred_dir = root.join(".cred");
        let proj = project::Project {
            vault_path: cred_dir.join("vault.json"),
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
    // 5. FILTERING LOGIC SIMULATION (Push Logic)
    // ========================================================================

    #[test]
    fn test_push_filtering_logic() {
        // Setup scenarios mimicking main.rs logic
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