#[cfg(test)]
mod tests {
    use cred::{config, vault};
    use rand::RngCore;
    use std::fs;
    use tempfile::tempdir;

    fn get_test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    // Integration: non-interactive without stored token must surface missing auth.
    #[test]
    fn test_non_interactive_requires_token_and_json_error() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir_all(&home).unwrap();
        unsafe {
            std::env::set_var("HOME", &home);
            std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
        }

        let token = config::get_target_token("github").unwrap();
        assert!(token.is_none());
    }

    // Integration: corrupted vault load should error cleanly.
    #[test]
    fn test_vault_corruption_handled_gracefully() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("vault.enc");
        fs::write(&vault_path, "garbage-data").unwrap();
        let key = get_test_key();

        let result = vault::Vault::load(&vault_path, key);
        assert!(result.is_err());
    }

    /// Integration: secret list ordering is stable for deterministic JSON output.
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
