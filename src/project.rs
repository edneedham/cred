use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use keyring::Entry;
use rand::RngCore;
use uuid::Uuid;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::process::Command;

use crate::vault;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProjectConfig {
    pub name: Option<String>,
    pub version: Option<String>,
    pub id: Option<Uuid>,
    pub git_root: Option<String>,
    pub git_repo: Option<String>,
}

pub struct Project {
    pub vault_path: PathBuf,
    pub config_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct GitInfo {
    pub root: String,
    #[allow(dead_code)]
    pub remote: String,
    pub repo_slug: Option<String>, // owner/name if GitHub-like
}

impl Project {
    pub fn find() -> Result<Self> {
        let current_dir = env::current_dir().context("Failed to get current directory")?;

        for ancestor in current_dir.ancestors() {
            let cred_dir = ancestor.join(".cred");
            if cred_dir.exists() && cred_dir.is_dir() {
                return Ok(Project {
                    vault_path: cred_dir.join("vault.enc"),
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

    pub fn get_master_key(&self) -> Result<[u8; 32]> {
        // Check for key in env for CI and testing
        if let Ok(b64) = std::env::var("CRED_MASTER_KEY_B64") {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .context("Invalid base64 in CRED_MASTER_KEY_B64")?;
            if bytes.len() != 32 {
                anyhow::bail!("CRED_MASTER_KEY_B64 must decode to 32 bytes");
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }
        let config = self.load_config()?;
        let project_id = config.id.ok_or_else(|| anyhow::anyhow!("Project ID missing in project.toml"))?;
        let entry = Entry::new("cred-cli", &project_id.to_string())?;

        let key_b64 = entry.get_password().context("Encryption key not found in System Credential Store.")?;

        let key_vec = BASE64.decode(key_b64).context("Corrupted key in credential store")?;

        let mut key = [0u8; 32];
        if key_vec.len() != 32 {
            anyhow::bail!("Invalid key length in credential store");
        }
        key.copy_from_slice(&key_vec);
        
        Ok(key)
    }

    #[allow(dead_code)]
    // Later feature
    pub fn add_key_to_scopes(&self, _scope_names: &[String], _key: &str) -> Result<()> {
        Ok(())
    }
}

pub fn init() -> Result<()> {
    let current_dir = env::current_dir().context("Failed to get current directory")?;
    init_at(&current_dir)
}

pub fn init_at(root: &Path) -> Result<()> {
    let cred_dir = root.join(".cred");
    if cred_dir.exists() {
        bail!("Cred is already initialized here: {}", cred_dir.display());
    }
    fs::create_dir(&cred_dir).context("Failed to create .cred directory")?;

    let project_id = Uuid::new_v4();

    let git_info = detect_git(Some(root));
    if git_info.is_none() {
        println!("⚠️  This directory is not part of a git repository.");
        println!("   Remote safety checks will be disabled.");
    }
    let git_root = git_info.as_ref().map(|g| g.root.clone());
    let git_repo = git_info.as_ref().and_then(|g| g.repo_slug.clone());

    let git_root_line = git_root
        .as_ref()
        .map(|p| format!("git_root = \"{}\"\n", p))
        .unwrap_or_default();
    let git_repo_line = git_repo
        .as_ref()
        .map(|p| format!("git_repo = \"{}\"\n", p))
        .unwrap_or_default();

    let project_toml = format!(r#"# Cred Project Configuration
name = "my-project"
version = "0.1.0"
id = "{}"
{}{}"#, project_id, git_root_line, git_repo_line);
    fs::write(cred_dir.join("project.toml"), project_toml)?;

    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);

    // Service: "cred-cli", User: project_id
    let entry = Entry::new("cred-cli", &project_id.to_string())?;
    
    // Keyring stores strings, so we base64 encode the raw key
    let key_b64 = BASE64.encode(key);
    entry.set_password(&key_b64).context("Failed to save key to the System Credential Store")?;

    key.fill(0);

    // Create an empty encrypted vault to ensure presence
    {
        let vault_path = cred_dir.join("vault.enc");
        let v = vault::Vault::load(&vault_path, key)?;
        v.save()?;
    }

    update_gitignore(root)?;

    println!("Initialized new cred project at {}", cred_dir.display());
    println!("🔑 Encryption key generated and stored in the System Credential Store (ID: {})", project_id);
    Ok(())
}

fn normalize_github_remote(remote: &str) -> Option<String> {
    let trimmed = remote.trim().trim_end_matches(".git");

    let remainder = if let Some(stripped) = trimmed.strip_prefix("git@github.com:") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("ssh://git@github.com/") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("https://github.com/") {
        stripped
    } else {
        return None;
    };

    let mut parts = remainder.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{}/{}", owner, repo))
}

pub fn detect_git(base: Option<&Path>) -> Option<GitInfo> {
    let base_dir = base.unwrap_or_else(|| Path::new("."));
    let root_raw = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(base_dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        })?;
    // Canonicalize to avoid platform-specific symlink prefixes (e.g., /private on macOS temp dirs)
    let root = PathBuf::from(&root_raw)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(root_raw))
        .to_string_lossy()
        .to_string();

    let remote_opt = Command::new("git")
        .args(["config", "--get", "remote.origin.url"])
        .current_dir(&root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        });

    let repo_slug = remote_opt.as_ref().and_then(|r| normalize_github_remote(r));
    let remote_str = remote_opt.unwrap_or_default();

    Some(GitInfo {
        root,
        remote: remote_str,
        repo_slug,
    })
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