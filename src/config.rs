use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

/// Determines the configuration root based on the OS.
/// - Windows: %APPDATA%/cred
/// - Linux:   ~/.config/cred
/// - macOS:   ~/.config/cred (Forced override)
fn resolve_config_dir() -> Result<PathBuf> {
    if cfg!(target_os = "macos") {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        return Ok(home.join(".config").join("cred"));
    }

    let config = dirs::config_dir().context("Could not determine config directory")?;
    Ok(config.join("cred"))
}

/// Public entry point: Ensures ~/.config/cred/global.toml exists.
pub fn ensure_global_config_exists() -> Result<PathBuf> {
    let config_dir = resolve_config_dir()?;
    ensure_config_at(&config_dir)
}

/// Internal testable logic
pub fn ensure_config_at(config_dir: &Path) -> Result<PathBuf> {
    // 1. Create directory if missing
    if !config_dir.exists() {
        fs::create_dir_all(config_dir)
            .with_context(|| format!("Failed to create config dir at {}", config_dir.display()))?;
    }

    // 2. Check for global.toml
    let file_path = config_dir.join("global.toml");
    if !file_path.exists() {
        let default_content = r#"# Cred Global Configuration
# This file stores authentication tokens for providers.
# DO NOT commit this file to version control.

[providers]
# github = "ghp_..."
"#;
        fs::write(&file_path, default_content)
            .context("Failed to write default global.toml")?;
        println!("Created global config at: {}", file_path.display());
    } else {
        // Optional: Notify user it was found (useful for debugging)
        println!("Global config found at: {}", file_path.display());
    }

    Ok(file_path)
}