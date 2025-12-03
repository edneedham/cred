use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use keyring::Entry;
use rand::{Rng, RngCore};
use uuid::Uuid;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProjectConfig {
    pub name: Option<String>,
    pub version: Option<String>,
    pub id: Option<Uuid>,
    pub scopes: Option<HashMap<String, Vec<String>>>,
}

pub struct Project {
    pub vault_path: PathBuf,
    pub config_path: PathBuf,
}

impl Project {
    pub fn find() -> Result<Self> {
        let current_dir = env::current_dir().context("Failed to get current directory")?;

        for ancestor in current_dir.ancestors() {
            let cred_dir = ancestor.join(".cred");
            if cred_dir.exists() && cred_dir.is_dir() {
                return Ok(Project {
                    vault_path: cred_dir.join("vault.json"),
                    config_path: cred_dir.join("project.toml"),
                });
            }
        }
        bail!("No .cred directory found. Run 'cred init' to start.")
    }

    pub fn load_config(&self) -> Result<ProjectConfig> {
        if !self.config_path.exists() {
            return Ok(ProjectConfig::default());
        }
        let content = fs::read_to_string(&self.config_path).context("Failed to read project.toml")?;
        let config: ProjectConfig = toml::from_str(&content).context("Failed to parse project.toml")?;
        Ok(config)
    }

    pub fn add_key_to_scopes(&self, scope_names: &[String], key: &str) -> Result<()> {
        if scope_names.is_empty() { return Ok(()); }
        let mut config = self.load_config().unwrap_or_default();
        let scopes = config.scopes.get_or_insert_with(HashMap::new);
        let mut updated = false;

        for scope in scope_names {
            let list = scopes.entry(scope.to_string()).or_default();
            if !list.contains(&key.to_string()) {
                list.push(key.to_string());
                updated = true;
                println!("+ Added '{}' to scope '{}'", key, scope);
            }
        }

        if updated {
            let toml_string = toml::to_string_pretty(&config)?;
            fs::write(&self.config_path, toml_string).context("Failed to update project.toml")?;
        }
        Ok(())
    }
}

pub fn init() -> Result<()> {
    let current_dir = env::current_dir().context("Failed to get current directory")?;
    init_at(&current_dir)
}

pub(crate) fn init_at(root: &Path) -> Result<()> {
    let cred_dir = root.join(".cred");
    if cred_dir.exists() {
        bail!("Cred is already initialized here: {}", cred_dir.display());
    }
    fs::create_dir(&cred_dir).context("Failed to create .cred directory")?;

    let project_id = Uuid::new_v4();

    let project_toml = format!(r#"# Cred Project Configuration
name = "my-project"
version = "0.1.0"
id = "{}"

[scopes]
"#, project_id);
    fs::write(cred_dir.join("project.toml"), project_toml)?;

    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);

    // Service: "cred-cli", User: project_id
    let entry = Entry::new("cred-cli", &project_id.to_string())?;
    
    // Keyring stores strings, so we base64 encode the raw key
    let key_b64 = BASE64.encode(key);
    entry.set_password(&key_b64).context("Failed to save key to OS keychain")?;

    key.fill(0);

    update_gitignore(root)?;

    println!("Initialized new cred project at {}", cred_dir.display());
    println!("🔑 Encryption key generated and stored in System Keychain (ID: {})", project_id);
    Ok(())
}

fn update_gitignore(root: &Path) -> Result<()> {
    let gitignore = root.join(".gitignore");
    let entry = "\n.cred/\n";
    let mut file = fs::OpenOptions::new()
        .write(true).append(true).create(true)
        .open(&gitignore)?;

    if let Ok(content) = fs::read_to_string(&gitignore) {
        if !content.contains(".cred/") {
            writeln!(file, "{}", entry)?;
            println!("Added .cred/ to .gitignore");
        }
    } else {
        writeln!(file, "{}", entry)?;
    }
    Ok(())
}