//! Global configuration and keystore utilities for cred.
//! Handles `~/.config/cred/global.toml` plus pluggable secret storage backends.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use toml::Value;
use keyring::Entry;
use rand::RngCore;
use std::sync::OnceLock;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
use rand::Rng;

/// Versioning information for the global config.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CredMeta {
    pub version: String,
    pub config_version: u32,
}

/// Machine identity hints (optional).
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Machine {
    pub id: Option<String>,
    pub hostname: Option<String>,
}

/// User-facing CLI preferences.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Preferences {
    pub default_target: Option<String>,
    pub confirm_destructive: Option<bool>,
    pub color_output: Option<bool>,
}

/// Target-specific configuration (auth reference, default flag).
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct TargetConfig {
    pub auth_ref: Option<String>,
    pub default: Option<bool>,
}

/// Root of the global configuration file.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct GlobalConfig {
    pub cred: CredMeta,
    pub machine: Option<Machine>,
    pub preferences: Preferences,
    pub targets: HashMap<String, TargetConfig>,
}

/// Get the config directory depending on the operating system.
fn resolve_config_dir() -> Result<PathBuf> {
    if cfg!(target_os = "macos") {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        return Ok(home.join(".config").join("cred"));
    }
    let config = dirs::config_dir().context("Could not determine config directory")?;
    Ok(config.join("cred"))
}

/// Ensure the global config file exists (creating default if missing) and return its path.
pub fn ensure_global_config_exists() -> Result<PathBuf> {
    let config_dir = resolve_config_dir()?;
    ensure_config_at(&config_dir)
}

/// Ensure a config exists at the given directory, writing defaults on first run.
pub fn ensure_config_at(config_dir: &Path) -> Result<PathBuf> {
    if !config_dir.exists() {
        fs::create_dir_all(config_dir).context("Failed to create config dir")?;
    }
    let file_path = config_dir.join("global.toml");
    if !file_path.exists() {
        let default_config = default_config();
        let content = toml::to_string_pretty(&default_config)?;
        fs::write(&file_path, content)?;
    }
    Ok(file_path)
}

/// Load the typed global config, backfilling required fields if absent.
pub fn load() -> Result<GlobalConfig> {
    let config_path = ensure_global_config_exists()?;
    let content = fs::read_to_string(&config_path).context("Failed to read global config")?;
    let mut config: GlobalConfig = toml::from_str(&content).unwrap_or_else(|_| default_config());
    // Backfill cred if missing
    if config.cred.version.is_empty() {
        config.cred.version = "0.1.0".to_string();
    }
    if config.cred.config_version == 0 {
        config.cred.config_version = 1;
    }
    Ok(config)
}

/// Load the raw TOML as a `Value` (used for arbitrary path edits).
fn load_raw() -> Result<Value> {
    let config_path = ensure_global_config_exists()?;
    let content = fs::read_to_string(&config_path).unwrap_or_default();
    let val: Value = toml::from_str(&content).unwrap_or_else(|_| Value::Table(toml::map::Map::new()));
    Ok(val)
}

/// Persist a raw TOML `Value` to disk.
fn save_raw(val: &Value) -> Result<()> {
    let config_path = ensure_global_config_exists()?;
    let toml_string = toml::to_string_pretty(val)?;
    fs::write(&config_path, toml_string)?;
    Ok(())
}

/// Coerce string input into TOML types (bool, int, float, or string).
fn parse_value(input: &str) -> Value {
    if input.eq_ignore_ascii_case("true") {
        return Value::Boolean(true);
    }
    if input.eq_ignore_ascii_case("false") {
        return Value::Boolean(false);
    }
    if let Ok(i) = input.parse::<i64>() {
        return Value::Integer(i);
    }
    if let Ok(f) = input.parse::<f64>() {
        return Value::Float(f);
    }
    Value::String(input.to_string())
}

/// Set a dotted path in a TOML `Value`, creating tables as needed.
fn set_path(root: &mut Value, path: &[&str], value: Value) {
    if path.is_empty() { return; }
    let mut current = root;
    for seg in path[..path.len()-1].iter() {
        // ensure table
        if !current.is_table() {
            *current = Value::Table(toml::map::Map::new());
        }
        let tbl = current.as_table_mut().unwrap();
        current = tbl.entry(seg.to_string()).or_insert(Value::Table(toml::map::Map::new()));
    }
    if let Some(last) = path.last() {
        if !current.is_table() {
            *current = Value::Table(toml::map::Map::new());
        }
        let tbl = current.as_table_mut().unwrap();
        tbl.insert(last.to_string(), value);
    }
}

/// Remove a dotted path from a TOML `Value` if it exists.
fn unset_path(root: &mut Value, path: &[&str]) {
    if path.is_empty() { return; }
    let mut current = root;
    for seg in path[..path.len()-1].iter() {
        if let Some(tbl) = current.as_table_mut() {
            if let Some(next) = tbl.get_mut(*seg) {
                current = next;
            } else {
                return;
            }
        } else {
            return;
        }
    }
    if let Some(last) = path.last() {
        if let Some(tbl) = current.as_table_mut() {
            tbl.remove(*last);
        }
    }
}

/// Fetch a dotted path from a TOML `Value`.
fn get_path<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = root;
    for seg in path {
        match current {
            Value::Table(t) => {
                current = t.get(*seg)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

/// Set a config value at a dotted path, coercing primitive types.
pub fn config_set(key_path: &str, val: &str) -> Result<()> {
    let mut root = load_raw()?;
    let parts: Vec<&str> = key_path.split('.').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        anyhow::bail!("Invalid key path");
    }
    let value = parse_value(val);
    set_path(&mut root, &parts, value);
    save_raw(&root)
}

/// Get a config value at a dotted path.
pub fn config_get(key_path: &str) -> Result<Option<Value>> {
    let root = load_raw()?;
    let parts: Vec<&str> = key_path.split('.').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(get_path(&root, &parts).cloned())
}

/// Remove a config value at a dotted path.
pub fn config_unset(key_path: &str) -> Result<()> {
    let mut root = load_raw()?;
    let parts: Vec<&str> = key_path.split('.').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Ok(());
    }
    unset_path(&mut root, &parts);
    save_raw(&root)
}

/// Dump the entire config as pretty TOML.
pub fn config_list() -> Result<String> {
    let root = load_raw()?;
    let toml_string = toml::to_string_pretty(&root)?;
    Ok(toml_string)
}

/// Generate a default config with a random machine ID and safe defaults.
fn default_config() -> GlobalConfig {
    let mut id = [0u8; 8];
    rand::rng().fill_bytes(&mut id);
    let machine_id = format!("m_{:02x?}", id);
    let hostname = std::env::var("HOSTNAME").ok();

    GlobalConfig {
        cred: CredMeta { version: "0.1.0".to_string(), config_version: 1 },
        machine: Some(Machine { id: Some(machine_id), hostname }),
        preferences: Preferences { default_target: Some("github".to_string()), confirm_destructive: Some(true), color_output: Some(true) },
        targets: HashMap::new(),
    }
}

/// Persist a target token reference in config and store the token via keystore backend.
pub fn set_target_token(target: &str, token: &str) -> Result<()> {
    let mut config = load()?;
    let auth_ref = format!("cred:target:{}:default", target);
    config.targets.entry(target.to_string()).or_default().auth_ref = Some(auth_ref.clone());

    let config_path = ensure_global_config_exists()?;
    let toml_string = toml::to_string_pretty(&config)?;
    fs::write(&config_path, toml_string)?;

    keystore_set(&auth_ref, token)?;
    Ok(())
}

/// Retrieve a target token from the configured keystore backend.
pub fn get_target_token(target: &str) -> Result<Option<String>> {
    let config = load()?;
    let auth_ref = match config.targets.get(target).and_then(|t| t.auth_ref.as_ref()) {
        Some(r) => r.clone(),
        None => return Ok(None),
    };
    keystore_get(&auth_ref)
}

/// Remove a target token reference and delete the stored secret if present.
pub fn remove_target_token(target: &str) -> Result<()> {
    let mut config = load()?;
    if let Some(tcfg) = config.targets.remove(target) {
        if let Some(auth_ref) = tcfg.auth_ref {
            keystore_remove(&auth_ref)?;
        }
        let config_path = ensure_global_config_exists()?;
        let toml_string = toml::to_string_pretty(&config)?;
        fs::write(&config_path, toml_string)?;
        println!("✓ Removed authentication for '{}'", target);
    } else {
        println!("Target '{}' was not configured.", target);
    }
    Ok(())
}

// ---------- Keystore backends ----------

/// Pluggable secret storage backend for target tokens.
enum KeystoreBackend {
    Memory,
    File { path: PathBuf, key: [u8; 32] },
    Keyring,
}

/// Select keystore backend via env vars (memory, file, or platform keyring).
fn resolve_keystore() -> KeystoreBackend {
    match std::env::var("CRED_KEYSTORE").as_deref() {
        Ok("memory") => KeystoreBackend::Memory,
        Ok("file") => {
            let path = std::env::var("CRED_KEYSTORE_FILE")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    resolve_config_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join("keystore.enc")
                });
            let key_b64 = std::env::var("CRED_KEYSTORE_FILE_KEY")
                .expect("CRED_KEYSTORE_FILE_KEY (base64 32 bytes) required for file keystore");
            let key_raw = BASE64.decode(key_b64).expect("Invalid base64 in CRED_KEYSTORE_FILE_KEY");
            assert!(key_raw.len() == 32, "CRED_KEYSTORE_FILE_KEY must be 32 bytes");
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_raw);
            KeystoreBackend::File { path, key }
        }
        _ => KeystoreBackend::Keyring,
    }
}

static MEMORY_KEYSTORE: OnceLock<std::sync::Mutex<HashMap<String, String>>> = OnceLock::new();

/// Store a token in the active keystore backend.
fn keystore_set(auth_ref: &str, token: &str) -> Result<()> {
    match resolve_keystore() {
        KeystoreBackend::Memory => {
            let store = MEMORY_KEYSTORE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
            let mut guard = store.lock().unwrap();
            guard.insert(auth_ref.to_string(), token.to_string());
            Ok(())
        }
        KeystoreBackend::File { path, key } => keystore_file_write(&path, &key, auth_ref, token),
        KeystoreBackend::Keyring => {
            let entry = Entry::new("cred-target", auth_ref)?;
            entry.set_password(token)?;
            Ok(())
        }
    }
}

/// Fetch a token from the active keystore backend.
fn keystore_get(auth_ref: &str) -> Result<Option<String>> {
    match resolve_keystore() {
        KeystoreBackend::Memory => {
            let store = MEMORY_KEYSTORE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
            let guard = store.lock().unwrap();
            Ok(guard.get(auth_ref).cloned())
        }
        KeystoreBackend::File { path, key } => keystore_file_read(&path, &key, auth_ref),
        KeystoreBackend::Keyring => {
            let entry = Entry::new("cred-target", auth_ref)?;
            match entry.get_password() {
                Ok(pw) => Ok(Some(pw)),
                Err(_) => Ok(None),
            }
        }
    }
}

/// Remove a token from the active keystore backend.
fn keystore_remove(auth_ref: &str) -> Result<()> {
    match resolve_keystore() {
        KeystoreBackend::Memory => {
            let store = MEMORY_KEYSTORE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
            let mut guard = store.lock().unwrap();
            guard.remove(auth_ref);
            Ok(())
        }
        KeystoreBackend::File { path, key } => {
            keystore_file_delete(&path, &key, auth_ref)?;
            Ok(())
        }
        KeystoreBackend::Keyring => {
            let entry = Entry::new("cred-target", auth_ref)?;
            let _ = entry.set_password("");
            Ok(())
        }
    }
}

/// On-disk encrypted keystore blob.
#[derive(Serialize, Deserialize)]
struct EncKeystore {
    nonce: String,
    ciphertext: String,
}

/// Read a token from the file-based keystore.
fn keystore_file_read(path: &Path, key: &[u8; 32], auth_ref: &str) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(path)?;
    let enc: EncKeystore = serde_json::from_slice(&raw)?;
    let nonce_bytes = BASE64.decode(enc.nonce)?;
    let cipher_bytes = BASE64.decode(enc.ciphertext)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    if nonce_bytes.len() != 12 {
        anyhow::bail!("Invalid nonce length in keystore");
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, cipher_bytes.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to decrypt keystore: {}", e))?;
    let mut map: HashMap<String, String> = serde_json::from_slice(&plaintext)?;
    Ok(map.remove(auth_ref))
}

/// Write/update a token in the file-based keystore.
fn keystore_file_write(path: &Path, key: &[u8; 32], auth_ref: &str, token: &str) -> Result<()> {
    let mut map = if path.exists() {
        keystore_file_load_all(path, key)?
    } else {
        HashMap::new()
    };
    map.insert(auth_ref.to_string(), token.to_string());
    keystore_file_save_all(path, key, &map)
}

/// Delete a token from the file-based keystore.
fn keystore_file_delete(path: &Path, key: &[u8; 32], auth_ref: &str) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut map = keystore_file_load_all(path, key)?;
    map.remove(auth_ref);
    keystore_file_save_all(path, key, &map)
}

/// Load the full file-based keystore into memory.
fn keystore_file_load_all(path: &Path, key: &[u8; 32]) -> Result<HashMap<String, String>> {
    let raw = fs::read(path)?;
    let enc: EncKeystore = serde_json::from_slice(&raw)?;
    let nonce_bytes = BASE64.decode(enc.nonce)?;
    let cipher_bytes = BASE64.decode(enc.ciphertext)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    if nonce_bytes.len() != 12 {
        anyhow::bail!("Invalid nonce length in keystore");
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, cipher_bytes.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to decrypt keystore: {}", e))?;
    let map: HashMap<String, String> = serde_json::from_slice(&plaintext)?;
    Ok(map)
}

/// Save the full file-based keystore map back to disk.
fn keystore_file_save_all(path: &Path, key: &[u8; 32], map: &HashMap<String, String>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let plaintext = serde_json::to_vec(map)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 12];
    rand::rng().fill(&mut nonce);
    let nonce_ga = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_ga, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to encrypt keystore: {}", e))?;
    let enc = EncKeystore {
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    };
    let data = serde_json::to_vec_pretty(&enc)?;
    fs::write(path, data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_value_coercion() {
        assert_eq!(parse_value("true"), Value::Boolean(true));
        assert_eq!(parse_value("false"), Value::Boolean(false));
        assert_eq!(parse_value("42"), Value::Integer(42));
        assert_eq!(parse_value("3.14"), Value::Float(3.14));
        assert_eq!(parse_value("text"), Value::String("text".to_string()));
    }

    #[test]
    fn test_set_get_unset_path() {
        let mut root = Value::Table(toml::map::Map::new());
        set_path(&mut root, &["preferences", "default_target"], Value::String("github".into()));
        let got = get_path(&root, &["preferences", "default_target"]);
        assert_eq!(got, Some(&Value::String("github".into())));

        unset_path(&mut root, &["preferences", "default_target"]);
        let got = get_path(&root, &["preferences", "default_target"]);
        assert!(got.is_none());
    }

    #[test]
    fn test_default_config_shape() {
        let cfg = default_config();
        assert_eq!(cfg.cred.config_version, 1);
        assert_eq!(cfg.cred.version, "0.1.0");
        assert!(cfg.preferences.default_target.is_some());
    }
}