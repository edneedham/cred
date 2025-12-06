use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use toml::Value;
use keyring::Entry;
use rand::RngCore;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct CredMeta {
    pub version: String,
    pub config_version: u32,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Machine {
    pub id: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Preferences {
    pub default_target: Option<String>,
    pub confirm_destructive: Option<bool>,
    pub color_output: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct TargetConfig {
    pub auth_ref: Option<String>,
    pub default: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct GlobalConfig {
    pub cred: CredMeta,
    pub machine: Option<Machine>,
    pub preferences: Preferences,
    pub targets: HashMap<String, TargetConfig>,
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

fn resolve_config_dir() -> Result<PathBuf> {
    if cfg!(target_os = "macos") {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        return Ok(home.join(".config").join("cred"));
    }
    let config = dirs::config_dir().context("Could not determine config directory")?;
    Ok(config.join("cred"))
}

pub fn ensure_global_config_exists() -> Result<PathBuf> {
    let config_dir = resolve_config_dir()?;
    ensure_config_at(&config_dir)
}

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

fn load_raw() -> Result<Value> {
    let config_path = ensure_global_config_exists()?;
    let content = fs::read_to_string(&config_path).unwrap_or_default();
    let val: Value = toml::from_str(&content).unwrap_or_else(|_| Value::Table(toml::map::Map::new()));
    Ok(val)
}

fn save_raw(val: &Value) -> Result<()> {
    let config_path = ensure_global_config_exists()?;
    let toml_string = toml::to_string_pretty(val)?;
    fs::write(&config_path, toml_string)?;
    Ok(())
}

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

pub fn config_get(key_path: &str) -> Result<Option<Value>> {
    let root = load_raw()?;
    let parts: Vec<&str> = key_path.split('.').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(get_path(&root, &parts).cloned())
}

pub fn config_unset(key_path: &str) -> Result<()> {
    let mut root = load_raw()?;
    let parts: Vec<&str> = key_path.split('.').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Ok(());
    }
    unset_path(&mut root, &parts);
    save_raw(&root)
}

pub fn config_list() -> Result<String> {
    let root = load_raw()?;
    let toml_string = toml::to_string_pretty(&root)?;
    Ok(toml_string)
}

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

pub fn set_target_token(target: &str, token: &str) -> Result<()> {
    let mut config = load()?;
    let auth_ref = format!("cred:target:{}:default", target);
    config.targets.entry(target.to_string()).or_default().auth_ref = Some(auth_ref.clone());

    let config_path = ensure_global_config_exists()?;
    let toml_string = toml::to_string_pretty(&config)?;
    fs::write(&config_path, toml_string)?;

    let entry = Entry::new("cred-target", &auth_ref)?;
    entry.set_password(token)?;
    Ok(())
}

pub fn get_target_token(target: &str) -> Result<Option<String>> {
    let config = load()?;
    let auth_ref = match config.targets.get(target).and_then(|t| t.auth_ref.as_ref()) {
        Some(r) => r.clone(),
        None => return Ok(None),
    };
    let entry = Entry::new("cred-target", &auth_ref)?;
    match entry.get_password() {
        Ok(pw) => Ok(Some(pw)),
        Err(_) => Ok(None),
    }
}

pub fn remove_target_token(target: &str) -> Result<()> {
    let mut config = load()?;
    if let Some(tcfg) = config.targets.remove(target) {
        if let Some(auth_ref) = tcfg.auth_ref {
            let entry = Entry::new("cred-target", &auth_ref)?;
            let _ = entry.set_password("");
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