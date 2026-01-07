//! Helpers for importing/exporting .env-style files to and from the vault.
use crate::error::AppError;
use crate::vault::{DEFAULT_ENV, SecretEntry, Vault};
use anyhow::{Context, anyhow};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};

/// Format version for cred export files.
const EXPORT_VERSION: &str = "v1";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportStats {
    pub added: usize,
    pub skipped: usize,
    pub overwritten: usize,
    pub environments_created: usize,
}

/// Parsed secret with optional metadata from a cred export file.
#[derive(Debug, Clone)]
pub struct ParsedSecret {
    pub key: String,
    pub value: String,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Parsed environment section from a cred export file.
#[derive(Debug, Clone)]
pub struct ParsedEnvironment {
    pub name: String,
    pub secrets: Vec<ParsedSecret>,
}

/// Result of parsing a cred export file.
#[derive(Debug)]
pub struct ParsedExport {
    pub is_cred_format: bool,
    pub environments: Vec<ParsedEnvironment>,
}

/// Parse a .env-style file into key/value pairs. Supports `KEY=VALUE`, skips
/// blank lines and lines starting with `#`. Errors on malformed rows.
///
/// For cred export files, use `parse_cred_export` instead to preserve metadata.
pub fn parse_env_file(path: &Path) -> Result<Vec<(String, String)>, AppError> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;

    let mut entries = Vec::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key_part, value_part) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("Invalid line {}: expected KEY=VALUE", idx + 1))?;

        let key = key_part.trim();
        if key.is_empty() {
            return Err(AppError::user(anyhow!(
                "Invalid line {}: key cannot be empty",
                idx + 1
            )));
        }

        // Preserve value as-is after the first '=' to avoid altering user content.
        let value = value_part.to_string();
        entries.push((key.to_string(), value));
    }

    Ok(entries)
}

/// Parse a cred export file, extracting metadata and environment structure.
/// Falls back to simple parsing if not a cred format file.
pub fn parse_cred_export(path: &Path) -> Result<ParsedExport, AppError> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;

    let lines: Vec<&str> = content.lines().collect();

    // Check if this is a cred export file
    let is_cred_format = lines.first().map(|l| l.trim()) == Some("# cred-export v1");

    if !is_cred_format {
        // Fall back to simple parsing into default environment
        let entries = parse_env_file(path)?;
        let secrets: Vec<ParsedSecret> = entries
            .into_iter()
            .map(|(key, value)| ParsedSecret {
                key,
                value,
                description: None,
                created_at: None,
                updated_at: None,
            })
            .collect();

        return Ok(ParsedExport {
            is_cred_format: false,
            environments: vec![ParsedEnvironment {
                name: DEFAULT_ENV.to_string(),
                secrets,
            }],
        });
    }

    // Parse cred export format
    let mut environments: Vec<ParsedEnvironment> = Vec::new();
    let mut current_env = DEFAULT_ENV.to_string();
    let mut current_secrets: Vec<ParsedSecret> = Vec::new();

    // Metadata accumulator for the next secret
    let mut pending_description: Option<String> = None;
    let mut pending_created: Option<String> = None;
    let mut pending_updated: Option<String> = None;
    let mut pending_key: Option<String> = None;

    // Check for single-environment export header
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.starts_with("# environment:") {
            current_env = trimmed
                .strip_prefix("# environment:")
                .unwrap()
                .trim()
                .to_string();
            break;
        }
    }

    for line in &lines {
        let trimmed = line.trim();

        // Skip header lines
        if trimmed == "# cred-export v1"
            || trimmed.starts_with("# exported:")
            || trimmed.starts_with("# environment:")
            || trimmed.starts_with("# To import:")
            || trimmed == "#"
        {
            continue;
        }

        // Environment marker
        if trimmed.starts_with("# [environment:") && trimmed.ends_with(']') {
            // Save current environment's secrets
            if !current_secrets.is_empty() {
                environments.push(ParsedEnvironment {
                    name: current_env.clone(),
                    secrets: std::mem::take(&mut current_secrets),
                });
            }

            current_env = trimmed
                .strip_prefix("# [environment:")
                .unwrap()
                .strip_suffix(']')
                .unwrap()
                .trim()
                .to_string();
            continue;
        }

        // Secret key marker
        if trimmed.starts_with("# [") && trimmed.ends_with(']') && !trimmed.contains(':') {
            // Flush any pending metadata to previous secret
            pending_key = Some(
                trimmed
                    .strip_prefix("# [")
                    .unwrap()
                    .strip_suffix(']')
                    .unwrap()
                    .to_string(),
            );
            pending_description = None;
            pending_created = None;
            pending_updated = None;
            continue;
        }

        // Metadata comments
        if trimmed.starts_with("# description:") {
            pending_description = Some(
                trimmed
                    .strip_prefix("# description:")
                    .unwrap()
                    .trim()
                    .to_string(),
            );
            continue;
        }
        if trimmed.starts_with("# created:") {
            pending_created = Some(
                trimmed
                    .strip_prefix("# created:")
                    .unwrap()
                    .trim()
                    .to_string(),
            );
            continue;
        }
        if trimmed.starts_with("# updated:") {
            pending_updated = Some(
                trimmed
                    .strip_prefix("# updated:")
                    .unwrap()
                    .trim()
                    .to_string(),
            );
            continue;
        }

        // Skip empty lines and other comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // KEY=VALUE line
        if let Some((key_part, value_part)) = trimmed.split_once('=') {
            let key = key_part.trim().to_string();
            let value = value_part.to_string();

            // Use pending metadata if key matches, otherwise clear it
            let (desc, created, updated) = if pending_key.as_ref() == Some(&key) {
                (
                    pending_description.take(),
                    pending_created.take(),
                    pending_updated.take(),
                )
            } else {
                (None, None, None)
            };
            pending_key = None;

            current_secrets.push(ParsedSecret {
                key,
                value,
                description: desc,
                created_at: created,
                updated_at: updated,
            });
        }
    }

    // Don't forget the last environment
    if !current_secrets.is_empty() {
        environments.push(ParsedEnvironment {
            name: current_env,
            secrets: current_secrets,
        });
    }

    // If no environments were found, create default with empty secrets
    if environments.is_empty() {
        environments.push(ParsedEnvironment {
            name: DEFAULT_ENV.to_string(),
            secrets: Vec::new(),
        });
    }

    Ok(ParsedExport {
        is_cred_format: true,
        environments,
    })
}

/// Import a cred export file into the vault, recreating environments and metadata.
pub fn import_cred_export(
    parsed: &ParsedExport,
    vault: &mut Vault,
    overwrite: bool,
    dry_run: bool,
) -> ImportStats {
    let mut stats = ImportStats::default();

    for env in &parsed.environments {
        // Create environment if needed
        if !vault.list_environments().contains(&env.name) {
            if !dry_run {
                vault.create_environment(&env.name);
            }
            stats.environments_created += 1;
        }

        for secret in &env.secrets {
            let exists = vault.get_in_env(&env.name, &secret.key).is_some();

            if exists {
                if overwrite {
                    stats.overwritten += 1;
                    if !dry_run {
                        vault.set_with_metadata_in_env(
                            &env.name,
                            &secret.key,
                            &secret.value,
                            crate::vault::SecretFormat::Raw,
                            secret.description.clone(),
                            None, // source
                            None, // source_id
                        );
                    }
                } else {
                    stats.skipped += 1;
                }
            } else {
                stats.added += 1;
                if !dry_run {
                    vault.set_with_metadata_in_env(
                        &env.name,
                        &secret.key,
                        &secret.value,
                        crate::vault::SecretFormat::Raw,
                        secret.description.clone(),
                        None, // source
                        None, // source_id
                    );
                }
            }
        }
    }

    stats
}

/// Merge parsed .env entries into the vault (default environment). By default keeps existing keys;
/// set `overwrite` to replace existing values. Honors `dry_run` by not mutating
/// the vault while still returning the counters that would apply.
#[allow(dead_code)]
pub fn import_entries(
    entries: &[(String, String)],
    vault: &mut Vault,
    overwrite: bool,
    dry_run: bool,
) -> ImportStats {
    import_entries_to_env(entries, vault, DEFAULT_ENV, overwrite, dry_run)
}

/// Merge parsed .env entries into a specific environment in the vault.
/// By default keeps existing keys; set `overwrite` to replace existing values.
/// Honors `dry_run` by not mutating the vault while still returning the counters that would apply.
pub fn import_entries_to_env(
    entries: &[(String, String)],
    vault: &mut Vault,
    env: &str,
    overwrite: bool,
    dry_run: bool,
) -> ImportStats {
    let mut stats = ImportStats::default();

    for (key, value) in entries {
        if vault.get_in_env(env, key).is_some() {
            if overwrite {
                stats.overwritten += 1;
                if !dry_run {
                    vault.set_in_env(env, key, value);
                }
            } else {
                stats.skipped += 1;
            }
        } else {
            stats.added += 1;
            if !dry_run {
                vault.set_in_env(env, key, value);
            }
        }
    }

    stats
}

/// Export the full vault (all environments) to a cred export file with metadata.
pub fn export_full_vault(
    vault: &Vault,
    output_path: &Path,
    force: bool,
    dry_run: bool,
) -> Result<usize, AppError> {
    if output_path.exists() && !force {
        return Err(AppError::user(anyhow!(
            "{} exists; rerun with --force to overwrite",
            output_path.display()
        )));
    }

    let mut body = String::new();

    // Header
    body.push_str("# cred-export v1\n");
    body.push_str(&format!("# exported: {}\n", Utc::now().to_rfc3339()));
    body.push_str("#\n");
    body.push_str("# To import: cred import <this-file>\n");

    let environments = vault.list_environments();
    let mut total_secrets = 0;

    for env in &environments {
        body.push_str(&format!("\n# [environment: {}]\n\n", env));

        if let Some(entries) = vault.list_entries_in_env(env) {
            let mut sorted_entries: Vec<_> = entries.iter().collect();
            sorted_entries.sort_by(|a, b| a.0.cmp(b.0));

            for (key, entry) in sorted_entries {
                write_secret_with_metadata(&mut body, key, entry);
                total_secrets += 1;
            }
        }
    }

    if dry_run {
        return Ok(total_secrets);
    }

    write_file(output_path, &body)?;
    Ok(total_secrets)
}

/// Export a single environment to a cred export file with metadata.
pub fn export_env_with_metadata(
    vault: &Vault,
    env: &str,
    output_path: &Path,
    force: bool,
    dry_run: bool,
) -> Result<usize, AppError> {
    if output_path.exists() && !force {
        return Err(AppError::user(anyhow!(
            "{} exists; rerun with --force to overwrite",
            output_path.display()
        )));
    }

    let mut body = String::new();

    // Header
    body.push_str("# cred-export v1\n");
    body.push_str(&format!("# environment: {}\n", env));
    body.push_str(&format!("# exported: {}\n", Utc::now().to_rfc3339()));
    body.push_str("#\n");
    body.push_str("# To import: cred import <this-file>\n\n");

    let entries = vault.list_entries_in_env(env).cloned().unwrap_or_default();
    let mut sorted_entries: Vec<_> = entries.iter().collect();
    sorted_entries.sort_by(|a, b| a.0.cmp(b.0));

    for (key, entry) in &sorted_entries {
        write_secret_with_metadata(&mut body, key, entry);
    }

    if dry_run {
        return Ok(sorted_entries.len());
    }

    write_file(output_path, &body)?;
    Ok(sorted_entries.len())
}

/// Write a secret with its metadata comments.
fn write_secret_with_metadata(body: &mut String, key: &str, entry: &SecretEntry) {
    body.push_str(&format!("# [{}]\n", key));

    if let Some(ref desc) = entry.description {
        body.push_str(&format!("# description: {}\n", desc));
    }

    body.push_str(&format!("# created: {}\n", entry.created_at.to_rfc3339()));

    if entry.updated_at != entry.created_at {
        body.push_str(&format!("# updated: {}\n", entry.updated_at.to_rfc3339()));
    }

    body.push_str(&format!("{}={}\n", key, entry.value));
}

/// Export vault contents (default environment) to a .env-style file. Keys are sorted for stability.
/// Refuses to overwrite unless `force` is true. If `dry_run`, no file is
/// created but overwrite checks still apply.
#[allow(dead_code)]
pub fn export_env_file(
    vault: &Vault,
    output_path: &Path,
    force: bool,
    dry_run: bool,
) -> Result<usize, AppError> {
    export_env_file_from_env(vault, DEFAULT_ENV, output_path, force, dry_run)
}

/// Export vault contents from a specific environment to a plain .env-style file.
/// No metadata, just KEY=VALUE. Keys are sorted for stability.
/// Refuses to overwrite unless `force` is true. If `dry_run`, no file is
/// created but overwrite checks still apply.
pub fn export_env_file_from_env(
    vault: &Vault,
    env: &str,
    output_path: &Path,
    force: bool,
    dry_run: bool,
) -> Result<usize, AppError> {
    if output_path.exists() && !force {
        return Err(AppError::user(anyhow!(
            "{} exists; rerun with --force to overwrite",
            output_path.display()
        )));
    }

    let secrets = vault.list_in_env(env);
    let mut entries: Vec<_> = secrets.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut body = String::new();
    for (key, value) in entries {
        body.push_str(key);
        body.push('=');
        body.push_str(value);
        body.push('\n');
    }
    let line_count = body.lines().count();

    if dry_run {
        return Ok(line_count);
    }

    write_file(output_path, &body)?;
    Ok(line_count)
}

/// Write content to a file atomically via temp file.
fn write_file(output_path: &Path, content: &str) -> Result<(), AppError> {
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
    }

    let tmp_path = tmp_path(output_path);
    fs::write(&tmp_path, content)
        .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, output_path)
        .with_context(|| format!("Failed to persist to {}", output_path.display()))?;

    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "env".to_string());
    tmp.set_file_name(format!("{}.tmp", file_name));
    tmp
}
