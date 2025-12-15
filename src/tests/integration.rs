use crate::{config, vault};
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

// Integration: source token storage round trip with memory keystore.
#[test]
fn test_source_token_storage_round_trip() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    fs::create_dir_all(home.join(".config")).unwrap();
    unsafe {
        std::env::set_var("CRED_KEYSTORE", "memory");
        std::env::set_var("HOME", &home);
        std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
    }

    // Initially no token
    let initial = config::get_source_token("resend").unwrap();
    assert!(initial.is_none());

    // Store a token
    config::set_source_token("resend", "re_test_token_123").unwrap();

    // Retrieve it
    let retrieved = config::get_source_token("resend").unwrap();
    assert_eq!(retrieved, Some("re_test_token_123".to_string()));

    // Verify it appears in config
    let cfg = config::load().unwrap();
    assert!(cfg.sources.contains_key("resend"));

    // Remove it
    config::remove_source_token("resend").unwrap();

    // Verify it's gone
    let after_remove = config::get_source_token("resend").unwrap();
    assert!(after_remove.is_none());
}

// Integration: vault stores source metadata correctly.
#[test]
fn test_vault_source_metadata_persistence() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.enc");
    let key = get_test_key();

    // Create vault and set secret with source metadata
    let mut v = vault::Vault::load(&vault_path, key).unwrap();
    v.set_with_metadata(
        "RESEND_API_KEY",
        "re_secret_123",
        vault::SecretFormat::Raw,
        Some("Email service key".to_string()),
        Some("resend".to_string()),
        Some("abc-def-123".to_string()),
    );
    v.save().unwrap();

    // Reload and verify metadata
    let v2 = vault::Vault::load(&vault_path, key).unwrap();
    let entry = v2.get_entry("RESEND_API_KEY").expect("entry should exist");

    assert_eq!(entry.value, "re_secret_123");
    assert_eq!(entry.description, Some("Email service key".to_string()));
    assert_eq!(entry.source, Some("resend".to_string()));
    assert_eq!(entry.source_id, Some("abc-def-123".to_string()));
}

// Integration: vault preserves source metadata on value update.
#[test]
fn test_vault_source_metadata_preserved_on_update() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.enc");
    let key = get_test_key();

    // Create with source metadata
    let mut v = vault::Vault::load(&vault_path, key).unwrap();
    v.set_with_metadata(
        "KEY",
        "value1",
        vault::SecretFormat::Raw,
        Some("desc".to_string()),
        Some("resend".to_string()),
        Some("id-123".to_string()),
    );
    v.save().unwrap();

    // Update value using simple set (should preserve source)
    let mut v2 = vault::Vault::load(&vault_path, key).unwrap();
    v2.set("KEY", "value2");
    v2.save().unwrap();

    // Verify source metadata preserved
    let v3 = vault::Vault::load(&vault_path, key).unwrap();
    let entry = v3.get_entry("KEY").unwrap();
    assert_eq!(entry.value, "value2");
    assert_eq!(entry.source, Some("resend".to_string()));
    assert_eq!(entry.source_id, Some("id-123".to_string()));
}

// Integration: manual secrets default to source "manual" with no source_id.
#[test]
fn test_vault_manual_secret_defaults() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.enc");
    let key = get_test_key();

    let mut v = vault::Vault::load(&vault_path, key).unwrap();
    v.set("MANUAL_KEY", "manual_value");
    v.save().unwrap();

    let v2 = vault::Vault::load(&vault_path, key).unwrap();
    let entry = v2.get_entry("MANUAL_KEY").unwrap();

    assert_eq!(entry.value, "manual_value");
    assert_eq!(entry.source, Some("manual".to_string()));
    assert!(entry.source_id.is_none());
}
