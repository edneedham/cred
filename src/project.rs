//! Project discovery, git detection, repo binding, and project status helpers.
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use anyhow::anyhow;
use keyring::Entry;
use rand::RngCore;
use uuid::Uuid;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::process::Command;

use crate::vault;

/// Project-level metadata stored in `.cred/project.toml`.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProjectConfig {
    pub name: Option<String>,
    pub version: Option<String>,
    pub id: Option<Uuid>,
    pub git_root: Option<String>,
    pub git_repo: Option<String>,
}

/// Holds paths to project resources under `.cred/`.
pub struct Project {
    pub vault_path: PathBuf,
    pub config_path: PathBuf,
}

/// Git context derived from the current working tree.
#[derive(Debug, Clone)]
pub struct GitInfo {
    pub root: String,
    #[allow(dead_code)]
    pub remote: String,
    pub repo_slug: Option<String>, // owner/name if GitHub-like
}

/// High-level project status snapshot used for CLI reporting.
#[derive(Debug, Clone)]
pub struct ProjectStatusData {
    pub is_project: bool,
    pub project_name: Option<String>,
    pub vault_exists: bool,
    pub vault_accessible: bool,
    pub git_detected: bool,
    pub git_root: Option<String>,
    pub git_bound: bool,
    pub git_remote_current: Option<String>,
    pub git_remote_bound: Option<String>,
    pub targets_configured: Vec<String>,
    pub ready_for_push: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum RepoBindingErrorKind {
    User,
    Git,
}

#[derive(Debug)]
pub struct RepoBindingError {
    pub kind: RepoBindingErrorKind,
    pub error: anyhow::Error,
}

impl std::fmt::Display for RepoBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for RepoBindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

impl Project {
    /// Locate the nearest `.cred/` ancestor and return its paths.
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

    /// Load the project configuration from `.cred/project.toml` (defaulting if absent).
    pub fn load_config(&self) -> Result<ProjectConfig> {
        if !self.config_path.exists() {
            return Ok(ProjectConfig::default());
        }
        let content = fs::read_to_string(&self.config_path).context("Failed to read project.toml")?;
        let config: ProjectConfig = toml::from_str(&content).context("Failed to parse project.toml")?;
        Ok(config)
    }

    /// Fetch the 32-byte master key for this project (env override for CI, else OS keyring).
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

/// Initialize a project at the given root, creating `.cred/`, key, vault, and project.toml.
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

/// Resolve repo to use for CLI operations, validating detected/bound/provided combinations.
/// Resolve repo to use for CLI operations, validating detected/bound/provided combinations.
pub fn resolve_repo_binding(
    detected: Option<String>,
    bound: Option<String>,
    provided: Option<String>,
    verb: &str,
) -> Result<Option<String>, RepoBindingError> {
    if let Some(r) = provided.clone() {
        if let Some(live) = detected.as_ref() {
            if live != &r {
                return Err(RepoBindingError {
                    kind: RepoBindingErrorKind::User,
                    error: anyhow!(
                        "Refusing to {}: provided --repo '{}' does not match detected repo '{}'.",
                        verb,
                        r,
                        live
                    ),
                });
            }
        }
        if let Some(bound_repo) = bound.as_ref() {
            if bound_repo != &r {
                return Err(RepoBindingError {
                    kind: RepoBindingErrorKind::Git,
                    error: anyhow!(
                        "Refusing to {}: provided --repo '{}' does not match bound repo '{}'.",
                        verb,
                        r,
                        bound_repo
                    ),
                });
            }
        }
        return Ok(Some(r));
    }

    if let Some(live) = detected.clone() {
        if let Some(bound_repo) = bound.as_ref() {
            if bound_repo != &live {
                return Err(RepoBindingError {
                    kind: RepoBindingErrorKind::Git,
                    error: anyhow!(
                        "Refusing to {}: detected repo '{}' does not match bound repo '{}'.",
                        verb,
                        live,
                        bound_repo
                    ),
                });
            }
        }
        return Ok(Some(live));
    }

    Ok(bound)
}

/// Build the JSON payload for `project status`.
/// Build the JSON payload for `project status`.
pub fn project_status_payload(data: &ProjectStatusData) -> serde_json::Value {
    serde_json::json!({
        "api_version": "1",
        "status": "ok",
        "data": {
            "is_project": data.is_project,
            "project_name": data.project_name,
            "vault_exists": data.vault_exists,
            "vault_accessible": data.vault_accessible,
            "git_detected": data.git_detected,
            "git_root": data.git_root,
            "git_bound": data.git_bound,
            "git_remote_current": data.git_remote_current,
            "git_remote_bound": data.git_remote_bound,
            "targets_configured": data.targets_configured,
            "ready_for_push": data.ready_for_push
        }
    })
}

/// Normalize common GitHub remote forms to `owner/repo`.
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

/// Detect git root, origin URL, and normalized repo slug if GitHub-like.
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

/// Ensure `.cred/` is ignored in the repository.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_repo_binding_matches_detected() {
        let detected = Some("org/repo".to_string());
        let bound = None;
        let provided = None;
        let res = resolve_repo_binding(detected, bound, provided, "push").unwrap();
        assert_eq!(res, Some("org/repo".to_string()));
    }

    #[test]
    fn test_resolve_repo_binding_mismatch_detected() {
        let detected = Some("org/repo".to_string());
        let bound = None;
        let provided = Some("other/repo".to_string());
        let res = resolve_repo_binding(detected, bound, provided, "push");
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err().kind, RepoBindingErrorKind::User));
    }

    #[test]
    fn test_resolve_repo_binding_mismatch_bound() {
        let detected = Some("org/repo".to_string());
        let bound = Some("org/repo".to_string());
        let provided = Some("other/repo".to_string());
        let res = resolve_repo_binding(detected, bound, provided, "push");
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err().kind, RepoBindingErrorKind::Git));
    }

    #[test]
    fn test_resolve_repo_binding_mismatch_detected_vs_bound() {
        let detected = Some("org/repoB".to_string());
        let bound = Some("org/repoA".to_string());
        let provided = None;
        let res = resolve_repo_binding(detected, bound, provided, "push");
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err().kind, RepoBindingErrorKind::Git));
    }

    #[test]
    fn test_project_status_payload_schema() {
        let data = ProjectStatusData {
            is_project: true,
            project_name: Some("myapp".to_string()),
            vault_exists: true,
            vault_accessible: true,
            git_detected: true,
            git_root: Some("/path".to_string()),
            git_bound: true,
            git_remote_current: Some("org/repo".to_string()),
            git_remote_bound: Some("org/repo".to_string()),
            targets_configured: vec!["github".to_string()],
            ready_for_push: true,
        };
        let payload = project_status_payload(&data);
        if let serde_json::Value::Object(map) = payload {
            assert_eq!(map.get("api_version").unwrap(), "1");
            assert_eq!(map.get("status").unwrap(), "ok");
            let data_val = map.get("data").unwrap();
            assert!(data_val.get("is_project").unwrap().as_bool().unwrap());
            assert_eq!(data_val.get("project_name").unwrap(), "myapp");
            assert_eq!(data_val.get("git_remote_current").unwrap(), "org/repo");
        } else {
            panic!("Payload is not an object");
        }
    }
}