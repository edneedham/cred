use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct GlobalConfig {
    pub providers: HashMap<String, String>,
}

/// Determines the configuration root based on the OS.
/// - macOS: ~/.config/cred (Forced override)
/// - Others: Standard OS paths (AppData or ~/.config)
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
    if !config_dir.exists() {
        fs::create_dir_all(&config_dir).context("Failed to create config dir")?;
    }
    
    let file_path = config_dir.join("global.toml");
    if !file_path.exists() {
        let default_config = GlobalConfig::default();
        let content = toml::to_string_pretty(&default_config)?;
        fs::write(&file_path, content)?;
    }
    Ok(file_path)
}

pub fn load() -> Result<GlobalConfig> {
    let config_path = ensure_global_config_exists()?;
    let content = fs::read_to_string(&config_path).context("Failed to read global config")?;
    let config: GlobalConfig = toml::from_str(&content).unwrap_or_default();
    Ok(config)
}

pub fn set_provider_token(provider: &str, token: &str) -> Result<()> {
    let mut config = load()?;
    config.providers.insert(provider.to_string(), token.to_string());
    
    let config_path = ensure_global_config_exists()?;
    let toml_string = toml::to_string_pretty(&config)?;
    fs::write(&config_path, toml_string)?;
    Ok(())
}