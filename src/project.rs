//! Project discovery, git detection, repo binding, and project status helpers.
use crate::config;
use crate::error::{RepoBindingError, RepoBindingErrorKind};
use anyhow::anyhow;
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

use crate::vault;

/// Project-level metadata stored in `.cred/project.toml`.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProjectConfig {
    pub name: Option<String>,
    pub version: Option<String>,
    pub id: Option<Uuid>,
    pub git_root: Option<String>,
    pub git_repo: Option<String>,
    /// Per-target identifiers (e.g., "github" -> "owner/repo", "fly" -> "app-name")
    #[serde(default)]
    pub targets: HashMap<String, String>,
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
        let content =
            fs::read_to_string(&self.config_path).context("Failed to read project.toml")?;
        let config: ProjectConfig =
            toml::from_str(&content).context("Failed to parse project.toml")?;
        Ok(config)
    }

    /// Fetch the 32-byte master key for this project from the keystore.
    pub fn get_master_key(&self) -> Result<[u8; 32]> {
        let cfg = self.load_config()?;
        let project_id = cfg
            .id
            .ok_or_else(|| anyhow::anyhow!("Project ID missing in project.toml"))?;
        let auth_ref = project_id.to_string();

        let key_b64 = config::keystore::get(&auth_ref)?
            .ok_or_else(|| anyhow::anyhow!("Encryption key not found in credential store."))?;

        let key_vec = BASE64
            .decode(key_b64)
            .context("Corrupted key in credential store")?;

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

    /// Save the project configuration to `.cred/project.toml`.
    pub fn save_config(&self, cfg: &ProjectConfig) -> Result<()> {
        let toml_string = toml::to_string_pretty(cfg)?;
        fs::write(&self.config_path, toml_string)?;
        Ok(())
    }

    /// Get a target binding (identifier) from the project config.
    #[allow(dead_code)]
    pub fn get_target_binding(&self, target: &str) -> Result<Option<String>> {
        let cfg = self.load_config()?;
        Ok(cfg.targets.get(target).cloned())
    }

    /// Set a target binding (identifier) in the project config.
    pub fn set_target_binding(&self, target: &str, identifier: &str) -> Result<()> {
        let mut cfg = self.load_config()?;
        cfg.targets
            .insert(target.to_string(), identifier.to_string());
        self.save_config(&cfg)
    }

    /// Get a project-level target token from the keystore.
    pub fn get_target_token(&self, target: &str) -> Result<Option<String>> {
        let cfg = self.load_config()?;
        let project_id = cfg
            .id
            .ok_or_else(|| anyhow::anyhow!("Project ID missing in project.toml"))?;
        let auth_ref = format!("cred:project:{}:target:{}", project_id, target);
        config::keystore::get(&auth_ref)
    }

    /// Set a project-level target token in the keystore.
    pub fn set_target_token(&self, target: &str, token: &str) -> Result<()> {
        let cfg = self.load_config()?;
        let project_id = cfg
            .id
            .ok_or_else(|| anyhow::anyhow!("Project ID missing in project.toml"))?;
        let auth_ref = format!("cred:project:{}:target:{}", project_id, target);
        config::keystore::set(&auth_ref, token)
    }

    /// Remove a project-level target token from the keystore.
    pub fn remove_target_token(&self, target: &str) -> Result<()> {
        let cfg = self.load_config()?;
        let project_id = cfg
            .id
            .ok_or_else(|| anyhow::anyhow!("Project ID missing in project.toml"))?;
        let auth_ref = format!("cred:project:{}:target:{}", project_id, target);
        config::keystore::remove(&auth_ref)
    }

    /// Check if a project-level target token exists.
    pub fn has_target_token(&self, target: &str) -> bool {
        self.get_target_token(target).ok().flatten().is_some()
    }

    /// List all targets configured for this project (with bindings).
    pub fn list_targets(&self) -> Result<Vec<(String, String, bool)>> {
        let cfg = self.load_config()?;
        let mut result = Vec::new();
        for (target, identifier) in &cfg.targets {
            let has_token = self.has_target_token(target);
            result.push((target.clone(), identifier.clone(), has_token));
        }
        result.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(result)
    }
}

pub fn init() -> Result<()> {
    let current_dir = env::current_dir().context("Failed to get current directory")?;
    init_at(&current_dir)
}

/// Detect Fly.io app name from fly.toml if present.
pub fn detect_fly_app(root: &Path) -> Option<String> {
    let fly_toml = root.join("fly.toml");
    if fly_toml.exists() {
        if let Ok(content) = fs::read_to_string(&fly_toml) {
            if let Ok(parsed) = toml::from_str::<toml::Value>(&content) {
                if let Some(app) = parsed.get("app").and_then(|v| v.as_str()) {
                    return Some(app.to_string());
                }
            }
        }
    }
    None
}

/// Detect Vercel project ID from .vercel/project.json or vercel.json if present.
pub fn detect_vercel_project(root: &Path) -> Option<String> {
    // Try .vercel/project.json first (created by `vercel link`)
    let vercel_project_json = root.join(".vercel/project.json");
    if vercel_project_json.exists() {
        if let Ok(content) = fs::read_to_string(&vercel_project_json) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(id) = parsed.get("projectId").and_then(|v| v.as_str()) {
                    return Some(id.to_string());
                }
            }
        }
    }
    // Fall back to vercel.json
    let vercel_json = root.join("vercel.json");
    if vercel_json.exists() {
        if let Ok(content) = fs::read_to_string(&vercel_json) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(id) = parsed.get("projectId").and_then(|v| v.as_str()) {
                    return Some(id.to_string());
                }
            }
        }
    }
    None
}

/// Initialize a project at the given root, creating `.cred/`, key, vault, and project.toml.
pub fn init_at(root: &Path) -> Result<()> {
    let cred_dir = root.join(".cred");
    if cred_dir.exists() {
        bail!("Cred is already initialized here: {}", cred_dir.display());
    }
    fs::create_dir(&cred_dir).context("Failed to create .cred directory")?;

    let project_id = Uuid::new_v4();

    // Use directory name as project name
    let project_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my-project")
        .to_string();

    let git_info = detect_git(Some(root));
    if git_info.is_none() {
        println!("⚠️  This directory is not part of a git repository.");
        println!("   Remote safety checks will be disabled.");
    }
    let git_root = git_info.as_ref().map(|g| g.root.clone());
    let git_repo = git_info.as_ref().and_then(|g| g.repo_slug.clone());

    // Auto-detect target identifiers
    let mut targets: HashMap<String, String> = HashMap::new();
    let mut detected_targets: Vec<String> = Vec::new();

    // GitHub from git remote
    if let Some(ref repo) = git_repo {
        targets.insert("github".to_string(), repo.clone());
        detected_targets.push(format!("github: {}", repo));
    }

    // Fly.io from fly.toml
    if let Some(app) = detect_fly_app(root) {
        targets.insert("fly".to_string(), app.clone());
        detected_targets.push(format!("fly: {}", app));
    }

    // Vercel from .vercel/project.json or vercel.json
    if let Some(project) = detect_vercel_project(root) {
        targets.insert("vercel".to_string(), project.clone());
        detected_targets.push(format!("vercel: {}", project));
    }

    let git_root_line = git_root
        .as_ref()
        .map(|p| format!("git_root = \"{}\"\n", p))
        .unwrap_or_default();
    let git_repo_line = git_repo
        .as_ref()
        .map(|p| format!("git_repo = \"{}\"\n", p))
        .unwrap_or_default();

    // Build targets TOML section
    let targets_section = if targets.is_empty() {
        String::new()
    } else {
        let mut lines = vec!["\n[targets]".to_string()];
        let mut sorted_targets: Vec<_> = targets.iter().collect();
        sorted_targets.sort_by_key(|(k, _)| *k);
        for (k, v) in sorted_targets {
            lines.push(format!("{} = \"{}\"", k, v));
        }
        lines.join("\n")
    };

    let project_toml = format!(
        r#"# Cred Project Configuration
name = "{}"
version = "0.1.0"
id = "{}"
{}{}{}"#,
        project_name, project_id, git_root_line, git_repo_line, targets_section
    );
    fs::write(cred_dir.join("project.toml"), project_toml)?;

    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);

    // Store key in keystore (respects CRED_KEYSTORE env var)
    let auth_ref = project_id.to_string();
    let key_b64 = BASE64.encode(key);
    config::keystore::set(&auth_ref, &key_b64).context("Failed to save key to credential store")?;

    // Create an empty encrypted vault to ensure presence
    {
        let vault_path = cred_dir.join("vault.enc");
        let v = vault::Vault::load(&vault_path, key)?;
        v.save()?;
    }

    key.fill(0); // Zero key after vault is created

    update_gitignore(root)?;

    println!("Initialized new cred project at {}", cred_dir.display());
    println!(
        "🔑 Encryption key generated and stored in the System Credential Store (ID: {})",
        project_id
    );

    if !detected_targets.is_empty() {
        println!("📍 Detected targets:");
        for target in &detected_targets {
            println!("   {}", target);
        }
        println!("\n   Run 'cred target set <target>' to authenticate each target.");
    }

    Ok(())
}

/// Resolve repo to use for CLI operations, validating detected/bound/provided combinations.
#[allow(dead_code)]
pub fn resolve_repo_binding(
    detected: Option<String>,
    bound: Option<String>,
    provided: Option<String>,
    verb: &str,
) -> Result<Option<String>, RepoBindingError> {
    if let Some(r) = provided.clone() {
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
        .write(true)
        .append(true)
        .create(true)
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
}
