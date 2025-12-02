use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Vault {
    #[serde(skip)]
    path: PathBuf,
    // Matrix: Environment -> { Key -> Value }
    secrets: HashMap<String, HashMap<String, String>>,
}

impl Vault {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self { path: path.to_path_buf(), secrets: HashMap::new() });
        }
        let content = fs::read_to_string(path).context("Failed to read vault")?;
        let mut vault: Vault = if content.trim().is_empty() {
             Vault::default()
        } else {
            let secrets: HashMap<String, HashMap<String, String>> = serde_json::from_str(&content)
                .context("Failed to parse vault JSON")?;
            Vault { path: path.to_path_buf(), secrets }
        };
        vault.path = path.to_path_buf();
        Ok(vault)
    }

    pub fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.secrets)?;
        fs::write(&self.path, json).context("Failed to write vault")?;
        Ok(())
    }

    pub fn set(&mut self, env: &str, key: &str, value: &str) {
        let env_map = self.secrets.entry(env.to_string()).or_default();
        env_map.insert(key.to_string(), value.to_string());
    }

    pub fn get(&self, env: &str, key: &str) -> Option<&String> {
        self.secrets.get(env).and_then(|map| map.get(key))
    }

    pub fn remove(&mut self, env: &str, key: &str) -> Option<String> {
        if let Some(env_map) = self.secrets.get_mut(env) {
            env_map.remove(key)
        } else { None }
    }

    pub fn list(&self, env: &str) -> Option<&HashMap<String, String>> {
        self.secrets.get(env)
    }
    
    pub fn list_all(&self) -> &HashMap<String, HashMap<String, String>> {
        &self.secrets
    }
}