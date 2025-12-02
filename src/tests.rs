#[cfg(test)]
mod tests {
    use crate::{project, config, vault};
    use tempfile::tempdir;
    use std::fs;
    use std::collections::HashMap;

    // --- PROJECT & INIT TESTS ---

    #[test]
    fn test_project_initialization() {
        let dir = tempdir().unwrap();
        let root_path = dir.path();

        // 1. Run init
        let result = project::init_at(root_path);
        assert!(result.is_ok());

        // 2. Verify files
        let cred_dir = root_path.join(".cred");
        assert!(cred_dir.exists(), ".cred dir missing");
        assert!(cred_dir.join("project.toml").exists(), "project.toml missing");
        assert!(cred_dir.join("vault.json").exists(), "vault.json missing");
        
        // 3. Verify .gitignore
        let gitignore = root_path.join(".gitignore");
        assert!(gitignore.exists());
        let content = fs::read_to_string(gitignore).unwrap();
        assert!(content.contains(".cred/"));
    }

    #[test]
    fn test_global_config_creation() {
        let dir = tempdir().unwrap();
        let config_dir = dir.path().join("cred_config_test");

        // Run logic (using the testable internal function)
        let path = config::ensure_config_at(&config_dir).unwrap();

        assert!(path.exists());
        assert!(path.ends_with("global.toml"));
        
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("[providers]"));
    }

    // --- VAULT TESTS (MATRIX SUPPORT) ---

    #[test]
    fn test_vault_matrix_logic() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.json");

        // 1. Create and populate vault
        let mut v = vault::Vault::load(&vault_path).unwrap();
        
        // Set secrets in different environments
        v.set("development", "API_URL", "http://localhost:3000");
        v.set("production", "API_URL", "https://api.prod.com");
        v.set("production", "DB_PASS", "secret_prod_pass");

        // 2. Save to disk
        v.save().unwrap();

        // 3. Load from disk (New instance)
        let v2 = vault::Vault::load(&vault_path).unwrap();

        // 4. Verify separation of environments
        assert_eq!(v2.get("development", "API_URL"), Some(&"http://localhost:3000".to_string()));
        assert_eq!(v2.get("production", "API_URL"), Some(&"https://api.prod.com".to_string()));
        
        // 5. Verify missing keys
        assert_eq!(v2.get("development", "DB_PASS"), None); // Should not exist in dev
    }

    // --- SCOPE TESTS (PROJECT.TOML) ---

    #[test]
    fn test_project_scopes() {
        let dir = tempdir().unwrap();
        let root_path = dir.path();
        
        // 1. Init project
        project::init_at(root_path).unwrap();

        // 2. Manual Project struct construction (since Project::find uses CWD)
        let cred_dir = root_path.join(".cred");
        let proj = project::Project {
            root: root_path.to_path_buf(),
            vault_path: cred_dir.join("vault.json"),
            config_path: cred_dir.join("project.toml"),
        };

        // 3. Add keys to scopes
        // Add "DB_URL" to "backend" scope
        proj.add_key_to_scopes(&["backend".to_string()], "DB_URL").unwrap();
        
        // Add "API_KEY" to "backend" AND "worker" scopes
        proj.add_key_to_scopes(&["backend".to_string(), "worker".to_string()], "API_KEY").unwrap();

        // 4. Load config and verify
        let config = proj.load_config().unwrap();
        let scopes = config.scopes.unwrap();

        // Check Backend Scope
        let backend = scopes.get("backend").expect("backend scope missing");
        assert!(backend.contains(&"DB_URL".to_string()));
        assert!(backend.contains(&"API_KEY".to_string()));

        // Check Worker Scope
        let worker = scopes.get("worker").expect("worker scope missing");
        assert!(worker.contains(&"API_KEY".to_string()));
        assert!(!worker.contains(&"DB_URL".to_string()));
    }
}