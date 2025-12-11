//! Helpers for importing/exporting .env-style files to and from the vault.
use crate::error::AppError;
use crate::vault::Vault;
use anyhow::{anyhow, Context};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportStats {
    pub added: usize,
    pub skipped: usize,
    pub overwritten: usize,
}

/// Parse a .env-style file into key/value pairs. Supports `KEY=VALUE`, skips
/// blank lines and lines starting with `#`. Errors on malformed rows.
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

/// Merge parsed .env entries into the vault. By default keeps existing keys;
/// set `overwrite` to replace existing values. Honors `dry_run` by not mutating
/// the vault while still returning the counters that would apply.
pub fn import_entries(
    entries: &[(String, String)],
    vault: &mut Vault,
    overwrite: bool,
    dry_run: bool,
) -> ImportStats {
    let mut stats = ImportStats::default();

    for (key, value) in entries {
        if vault.get(key).is_some() {
            if overwrite {
                stats.overwritten += 1;
                if !dry_run {
                    vault.set(key, value);
                }
            } else {
                stats.skipped += 1;
            }
        } else {
            stats.added += 1;
            if !dry_run {
                vault.set(key, value);
            }
        }
    }

    stats
}

/// Export vault contents to a .env-style file. Keys are sorted for stability.
/// Refuses to overwrite unless `force` is true. If `dry_run`, no file is
/// created but overwrite checks still apply.
pub fn export_env_file(
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

    let mut entries: Vec<_> = vault.list().iter().collect();
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

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
    }

    let tmp_path = tmp_path(output_path);
    fs::write(&tmp_path, &body)
        .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, output_path)
        .with_context(|| format!("Failed to persist to {}", output_path.display()))?;

    Ok(line_count)
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

