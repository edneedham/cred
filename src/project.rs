//! Project discovery, git detection, repo binding, and project status helpers.
use crate::error::{RepoBindingError, RepoBindingErrorKind};
use anyhow::anyhow;
use anyhow::{Context, Result, bail};
use argon2::Argon2;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use keyring::Entry;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

use crate::vault;

/// Key derivation mode for the project.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyMode {
    /// Key stored in OS keyring (default, single-machine)
    #[default]
    Keyring,
    /// Key derived from passphrase using Argon2id (team-shareable)
    Passphrase,
}

impl std::fmt::Display for KeyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyMode::Keyring => write!(f, "keyring"),
            KeyMode::Passphrase => write!(f, "passphrase"),
        }
    }
}

/// Project-level metadata stored in `.cred/project.toml`.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProjectConfig {
    pub name: Option<String>,
    pub version: Option<String>,
    pub id: Option<Uuid>,
    pub git_root: Option<String>,
    pub git_repo: Option<String>,
    /// Key derivation mode: "keyring" (default) or "passphrase"
    #[serde(default)]
    pub key_mode: KeyMode,
    /// Base64-encoded Argon2 salt (only for passphrase mode, safe to commit)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
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

    /// Fetch the 32-byte master key for this project.
    ///
    /// Resolution order:
    /// 1. `CRED_MASTER_KEY_B64` env var (CI/testing)
    /// 2. `CRED_PASSPHRASE` env var (for passphrase mode in CI)
    /// 3. Based on key_mode in project.toml:
    ///    - Keyring mode: Fetch from OS keyring
    ///    - Passphrase mode: Derive from passphrase (prompts if not in env)
    pub fn get_master_key(&self) -> Result<[u8; 32]> {
        // Check for raw key in env for CI and testing (highest priority)
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

        match config.key_mode {
            KeyMode::Passphrase => {
                // Passphrase mode: derive key from passphrase + salt
                let salt = config.salt.ok_or_else(|| {
                    anyhow::anyhow!("Passphrase mode requires salt in project.toml")
                })?;

                // Check for passphrase in env var (for CI)
                let passphrase = if let Ok(pp) = std::env::var("CRED_PASSPHRASE") {
                    pp
                } else {
                    // Prompt for passphrase interactively
                    rpassword::prompt_password("Enter vault passphrase: ")
                        .context("Failed to read passphrase")?
                };

                derive_key_from_passphrase(&passphrase, &salt)
            }
            KeyMode::Keyring => {
                // Keyring mode: fetch from OS credential store
                let project_id = config
                    .id
                    .ok_or_else(|| anyhow::anyhow!("Project ID missing in project.toml"))?;
                let entry = Entry::new("cred-cli", &project_id.to_string())?;

                let key_b64 = entry
                    .get_password()
                    .context("Encryption key not found in System Credential Store.")?;

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
        }
    }

    #[allow(dead_code)]
    // Later feature
    pub fn add_key_to_scopes(&self, _scope_names: &[String], _key: &str) -> Result<()> {
        Ok(())
    }
}

/// Derive a 32-byte key from a passphrase using Argon2id.
/// Uses OWASP-recommended parameters for password hashing.
pub fn derive_key_from_passphrase(passphrase: &str, salt_b64: &str) -> Result<[u8; 32]> {
    let salt_bytes = BASE64.decode(salt_b64).context("Invalid salt base64")?;

    // Use Argon2id with OWASP-recommended parameters
    // m=19456 (19 MiB), t=2 iterations, p=1 parallelism
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(19456, 2, 1, Some(32)).unwrap(),
    );

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut output)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;

    Ok(output)
}

/// Generate a random salt for Argon2 key derivation.
pub fn generate_salt() -> String {
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    BASE64.encode(salt_bytes)
}

pub fn init() -> Result<()> {
    let current_dir = env::current_dir().context("Failed to get current directory")?;
    init_at(&current_dir)
}

/// Initialize a project with passphrase-based key derivation.
pub fn init_with_passphrase(passphrase: &str) -> Result<()> {
    let current_dir = env::current_dir().context("Failed to get current directory")?;
    init_at_with_passphrase(&current_dir, passphrase)
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

    let project_toml = format!(
        r#"# Cred Project Configuration
name = "my-project"
version = "0.1.0"
id = "{}"
{}{}"#,
        project_id, git_root_line, git_repo_line
    );
    fs::write(cred_dir.join("project.toml"), project_toml)?;

    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);

    // Service: "cred-cli", User: project_id
    let entry = Entry::new("cred-cli", &project_id.to_string())?;

    // Keyring stores strings, so we base64 encode the raw key
    let key_b64 = BASE64.encode(key);
    entry
        .set_password(&key_b64)
        .context("Failed to save key to the System Credential Store")?;

    key.fill(0);

    // Create an empty encrypted vault to ensure presence
    {
        let vault_path = cred_dir.join("vault.enc");
        let v = vault::Vault::load(&vault_path, key)?;
        v.save()?;
    }

    update_gitignore(root)?;

    println!("Initialized new cred project at {}", cred_dir.display());
    println!(
        "🔑 Encryption key generated and stored in the System Credential Store (ID: {})",
        project_id
    );
    Ok(())
}

/// Initialize a project with passphrase-based key derivation (for team sharing).
pub fn init_at_with_passphrase(root: &Path, passphrase: &str) -> Result<()> {
    let cred_dir = root.join(".cred");
    if cred_dir.exists() {
        bail!("Cred is already initialized here: {}", cred_dir.display());
    }
    fs::create_dir(&cred_dir).context("Failed to create .cred directory")?;

    let project_id = Uuid::new_v4();
    let salt = generate_salt();

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

    let project_toml = format!(
        r#"# Cred Project Configuration
name = "my-project"
version = "0.1.0"
id = "{}"
key_mode = "passphrase"
salt = "{}"
{}{}"#,
        project_id, salt, git_root_line, git_repo_line
    );
    fs::write(cred_dir.join("project.toml"), project_toml)?;

    // Derive key from passphrase
    let key = derive_key_from_passphrase(passphrase, &salt)?;

    // Create an empty encrypted vault
    {
        let vault_path = cred_dir.join("vault.enc");
        let v = vault::Vault::load(&vault_path, key)?;
        v.save()?;
    }

    update_gitignore(root)?;

    println!("Initialized new cred project at {}", cred_dir.display());
    println!("🔑 Encryption key derived from passphrase (team-shareable)");
    println!("   Share the passphrase out-of-band with your team.");
    println!("   The salt in project.toml is safe to commit.");
    Ok(())
}

/// Convert an existing keyring-based project to passphrase mode.
pub fn convert_to_passphrase(project: &Project, passphrase: &str) -> Result<()> {
    let config = project.load_config()?;

    if config.key_mode == KeyMode::Passphrase {
        bail!("Project is already in passphrase mode");
    }

    // Get the current key from keyring
    let old_key = project.get_master_key()?;

    // Load the vault with the old key
    let vault = vault::Vault::load(&project.vault_path, old_key)?;

    // Generate new salt and derive new key
    let salt = generate_salt();
    let new_key = derive_key_from_passphrase(passphrase, &salt)?;

    // Re-encrypt the vault with the new key by reloading and saving
    // First, we need to save the vault data, then reload with new key
    let vault_data = vault.list_all_entries();
    let envs = vault.list_environments();

    // Create new vault with new key
    let mut new_vault = vault::Vault::load(&project.vault_path, new_key)?;

    // Recreate environments
    for env in envs {
        if env != vault::DEFAULT_ENV {
            new_vault.create_environment(&env);
        }
    }

    // Copy all secrets
    for (env, key, entry) in vault_data {
        new_vault.set_with_metadata_in_env(
            env,
            key,
            &entry.value,
            entry.format.clone(),
            entry.description.clone(),
            entry.source.clone(),
            entry.source_id.clone(),
        );
    }
    new_vault.save()?;

    // Update project.toml
    let project_id = config
        .id
        .ok_or_else(|| anyhow::anyhow!("Project ID missing"))?;
    let git_root_line = config
        .git_root
        .as_ref()
        .map(|p| format!("git_root = \"{}\"\n", p))
        .unwrap_or_default();
    let git_repo_line = config
        .git_repo
        .as_ref()
        .map(|p| format!("git_repo = \"{}\"\n", p))
        .unwrap_or_default();

    let project_toml = format!(
        r#"# Cred Project Configuration
name = "{}"
version = "{}"
id = "{}"
key_mode = "passphrase"
salt = "{}"
{}{}"#,
        config.name.unwrap_or_else(|| "my-project".to_string()),
        config.version.unwrap_or_else(|| "0.1.0".to_string()),
        project_id,
        salt,
        git_root_line,
        git_repo_line
    );
    fs::write(&project.config_path, project_toml)?;

    // Remove key from keyring
    if let Ok(entry) = Entry::new("cred-cli", &project_id.to_string()) {
        let _ = entry.set_password("");
    }

    Ok(())
}

/// Convert a passphrase-based project to keyring mode.
pub fn convert_to_keyring(project: &Project) -> Result<()> {
    let config = project.load_config()?;

    if config.key_mode == KeyMode::Keyring {
        bail!("Project is already in keyring mode");
    }

    // Get the current key from passphrase
    let old_key = project.get_master_key()?;

    // Load the vault with the old key
    let vault = vault::Vault::load(&project.vault_path, old_key)?;

    // Generate new random key
    let mut new_key = [0u8; 32];
    rand::rng().fill_bytes(&mut new_key);

    // Get vault data before re-encryption
    let vault_data = vault.list_all_entries();
    let envs = vault.list_environments();

    // Create new vault with new key
    let mut new_vault = vault::Vault::load(&project.vault_path, new_key)?;

    // Recreate environments
    for env in envs {
        if env != vault::DEFAULT_ENV {
            new_vault.create_environment(&env);
        }
    }

    // Copy all secrets
    for (env, key, entry) in vault_data {
        new_vault.set_with_metadata_in_env(
            env,
            key,
            &entry.value,
            entry.format.clone(),
            entry.description.clone(),
            entry.source.clone(),
            entry.source_id.clone(),
        );
    }
    new_vault.save()?;

    // Store key in keyring
    let project_id = config
        .id
        .ok_or_else(|| anyhow::anyhow!("Project ID missing"))?;
    let entry = Entry::new("cred-cli", &project_id.to_string())?;
    let key_b64 = BASE64.encode(new_key);
    entry
        .set_password(&key_b64)
        .context("Failed to save key to the System Credential Store")?;

    // Update project.toml (remove salt and key_mode)
    let git_root_line = config
        .git_root
        .as_ref()
        .map(|p| format!("git_root = \"{}\"\n", p))
        .unwrap_or_default();
    let git_repo_line = config
        .git_repo
        .as_ref()
        .map(|p| format!("git_repo = \"{}\"\n", p))
        .unwrap_or_default();

    let project_toml = format!(
        r#"# Cred Project Configuration
name = "{}"
version = "{}"
id = "{}"
{}{}"#,
        config.name.unwrap_or_else(|| "my-project".to_string()),
        config.version.unwrap_or_else(|| "0.1.0".to_string()),
        project_id,
        git_root_line,
        git_repo_line
    );
    fs::write(&project.config_path, project_toml)?;

    // Clear new_key from memory
    new_key.fill(0);

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
