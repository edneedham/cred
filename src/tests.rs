#[cfg(test)]
mod tests {
    use crate::{project, config};
    use tempfile::tempdir;
    use std::fs;

    #[test]
    fn test_project_initialization() {
        let dir = tempdir().unwrap();
        let root_path = dir.path();

        // Run init logic
        let result = project::init_at(root_path);
        assert!(result.is_ok(), "Project init failed: {:?}", result.err());

        // Verify files
        let cred_dir = root_path.join(".cred");
        assert!(cred_dir.exists(), ".cred dir missing");
        assert!(cred_dir.join("project.toml").exists(), "project.toml missing");
        assert!(cred_dir.join("vault.json").exists(), "vault.json missing");
        
        // Verify .gitignore
        let gitignore = root_path.join(".gitignore");
        assert!(gitignore.exists());
        let content = fs::read_to_string(gitignore).unwrap();
        assert!(content.contains(".cred/"));
    }

    #[test]
    fn test_global_config_creation() {
        let dir = tempdir().unwrap();
        let config_dir = dir.path().join("cred_config_test");

        // Run config logic
        let path = config::ensure_config_at(&config_dir).unwrap();

        // Verify
        assert!(path.exists());
        assert!(path.ends_with("global.toml"));
        
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("[providers]"));
    }
}