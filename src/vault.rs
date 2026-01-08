//! Encrypted local vault (secrets at rest) using ChaCha20-Poly1305 and base64 serialization.
//!
//! # Vault Schema Versions
//! - **v1**: Legacy format where decrypted payload is `HashMap<String, String>`
//! - **v2**: Flat format with `SecretEntry` containing value, format, hash, timestamps, description
//! - **v3**: Current format with environments: `HashMap<String, HashMap<String, SecretEntry>>`
//!
//! Migration from v1/v2 to v3 is automatic on load; v3 is always written on save.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Current vault schema version.
const CURRENT_VERSION: u8 = 3;

/// Default environment name for backward compatibility.
pub const DEFAULT_ENV: &str = "default";

/// On-disk representation of the vault file (envelope).
#[derive(Serialize, Deserialize)]
struct EncryptedVaultFile {
    version: u8,
    nonce: String,
    ciphertext: String,
}

/// Format hint for secret values.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SecretFormat {
    /// Single-line text (default)
    #[default]
    Raw,
    /// Multi-line content (generic)
    Multiline,
    /// PEM-encoded keys, certificates, etc.
    Pem,
    /// Base64-encoded binary data
    Base64,
    /// JSON structured data
    Json,
}

impl std::fmt::Display for SecretFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretFormat::Raw => write!(f, "raw"),
            SecretFormat::Multiline => write!(f, "multiline"),
            SecretFormat::Pem => write!(f, "pem"),
            SecretFormat::Base64 => write!(f, "base64"),
            SecretFormat::Json => write!(f, "json"),
        }
    }
}

impl std::str::FromStr for SecretFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "raw" => Ok(SecretFormat::Raw),
            "multiline" => Ok(SecretFormat::Multiline),
            "pem" => Ok(SecretFormat::Pem),
            "base64" => Ok(SecretFormat::Base64),
            "json" => Ok(SecretFormat::Json),
            _ => Err(format!(
                "Invalid format '{}'. Valid options: raw, multiline, pem, base64, json",
                s
            )),
        }
    }
}

/// A historical version of a secret value.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HistoricalValue {
    pub value: String,
    pub format: SecretFormat,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl Zeroize for HistoricalValue {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.source.zeroize();
    }
}

/// Maximum number of historical versions to keep per secret.
const MAX_HISTORY_SIZE: usize = 10;

/// A single secret with metadata (v2+).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretEntry {
    pub value: String,
    #[serde(default)]
    pub format: SecretFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Origin source of the secret (e.g., "resend", "manual")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Remote ID at the source (for revocation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    /// Previous versions of this secret (newest first, max 10)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoricalValue>,
}

impl Zeroize for SecretEntry {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.hash.zeroize();
        self.description.zeroize();
        self.source.zeroize();
        self.source_id.zeroize();
        for h in &mut self.history {
            h.zeroize();
        }
    }
}

/// V2 decrypted payload structure (legacy, for migration).
#[derive(Serialize, Deserialize, Debug)]
struct VaultPayloadV2 {
    version: u8,
    secrets: HashMap<String, SecretEntry>,
}

/// V3 decrypted payload structure with environment support.
#[derive(Serialize, Deserialize, Debug)]
struct VaultPayloadV3 {
    version: u8,
    environments: HashMap<String, HashMap<String, SecretEntry>>,
}

/// In-memory vault plus file/key context.
/// Secrets are organized by environment.
#[derive(Debug, Default)]
pub struct Vault {
    path: PathBuf,
    key: [u8; 32],
    /// Secrets organized by environment: env_name -> (key -> entry)
    environments: HashMap<String, HashMap<String, SecretEntry>>,
}

impl Zeroize for Vault {
    fn zeroize(&mut self) {
        for (mut env_name, mut secrets) in self.environments.drain() {
            env_name.zeroize();
            for (mut k, mut v) in secrets.drain() {
                k.zeroize();
                v.zeroize();
            }
        }
        self.key.zeroize();
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Vault {
    /// Load or initialize a vault from disk, decrypting with the provided 32-byte key.
    /// Automatically migrates v1/v2 vaults to v3 format in memory.
    pub fn load(vault_path: &Path, key: [u8; 32]) -> Result<Self> {
        let mut vault = Vault {
            path: vault_path.to_path_buf(),
            key,
            environments: HashMap::new(),
        };

        if !vault_path.exists() {
            // Initialize with default environment
            vault
                .environments
                .insert(DEFAULT_ENV.to_string(), HashMap::new());
            return Ok(vault);
        }

        let content = fs::read_to_string(vault_path).context("Failed to read vault.enc")?;
        let file_data: EncryptedVaultFile =
            serde_json::from_str(&content).context("Failed to parse vault structure")?;

        let cipher = ChaCha20Poly1305::new(&key.into());

        let nonce_bytes = BASE64
            .decode(&file_data.nonce)
            .context("Invalid nonce base64")?;
        let ciphertext = BASE64
            .decode(&file_data.ciphertext)
            .context("Invalid ciphertext base64")?;

        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| anyhow::anyhow!("Decryption failed. Data corrupted or wrong key."))?;

        let environments = match file_data.version {
            1 => Self::migrate_v1_to_v3(&plaintext)?,
            2 => Self::migrate_v2_to_v3(&plaintext)?,
            3 => Self::parse_v3(&plaintext)?,
            v => bail!("Unsupported vault version: {}. Please upgrade cred.", v),
        };

        vault.environments = environments;
        Ok(vault)
    }

    /// Migrate v1 (bare strings) to v3 (environments).
    fn migrate_v1_to_v3(plaintext: &[u8]) -> Result<HashMap<String, HashMap<String, SecretEntry>>> {
        let old_secrets: HashMap<String, String> =
            serde_json::from_slice(plaintext).context("Failed to parse v1 secrets")?;

        let now = Utc::now();
        let migrated: HashMap<String, SecretEntry> = old_secrets
            .into_iter()
            .map(|(k, v)| {
                let format = Self::detect_format(&v);
                let entry = SecretEntry {
                    value: v,
                    format,
                    hash: None,
                    created_at: now,
                    updated_at: now,
                    description: None,
                    source: None, // Unknown origin for migrated secrets
                    source_id: None,
                    history: Vec::new(),
                };
                (k, entry)
            })
            .collect();

        let mut environments = HashMap::new();
        environments.insert(DEFAULT_ENV.to_string(), migrated);
        Ok(environments)
    }

    /// Migrate v2 (flat secrets) to v3 (environments).
    fn migrate_v2_to_v3(plaintext: &[u8]) -> Result<HashMap<String, HashMap<String, SecretEntry>>> {
        let payload: VaultPayloadV2 =
            serde_json::from_slice(plaintext).context("Failed to parse v2 payload")?;

        let mut environments = HashMap::new();
        environments.insert(DEFAULT_ENV.to_string(), payload.secrets);
        Ok(environments)
    }

    /// Parse v3 payload directly.
    fn parse_v3(plaintext: &[u8]) -> Result<HashMap<String, HashMap<String, SecretEntry>>> {
        let payload: VaultPayloadV3 =
            serde_json::from_slice(plaintext).context("Failed to parse v3 payload")?;
        Ok(payload.environments)
    }

    /// Auto-detect format based on value content.
    ///
    /// Guiding principles:
    /// - Never guess aggressively; if in doubt → Raw or Multiline
    /// - PEM wins over everything (explicit structure)
    /// - JSON must actually parse
    /// - Base64 must be strictly valid (not just valid alphabet)
    /// - Multiline means literal newlines only
    /// - Structural detection only, no semantic inference
    ///
    /// Detection priority:
    /// 1. PEM — starts with `-----BEGIN ` (highest certainty)
    /// 2. JSON — must successfully parse as JSON
    /// 3. Base64 — must be strictly valid base64
    /// 4. Multiline — contains literal newlines
    /// 5. Raw — default (safe fallback)
    pub fn detect_format(value: &str) -> SecretFormat {
        let trimmed = value.trim();

        // PEM detection — explicit structural marker, highest priority
        if trimmed.starts_with("-----BEGIN ") {
            return SecretFormat::Pem;
        }

        // JSON detection — must actually parse, not just look like JSON
        if (trimmed.starts_with('{') && trimmed.ends_with('}'))
            || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        {
            if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
                return SecretFormat::Json;
            }
        }

        // Base64 detection — strict validation only
        if !trimmed.contains('\n') && Self::is_valid_base64(trimmed) {
            return SecretFormat::Base64;
        }

        // Multiline — literal newlines only (not escaped \n)
        if value.contains('\n') {
            return SecretFormat::Multiline;
        }

        // Default: Raw (safe fallback)
        SecretFormat::Raw
    }

    /// Strict base64 validation.
    ///
    /// Requirements:
    /// - Minimum length (avoid false positives on short strings)
    /// - Length divisible by 4 (base64 requirement)
    /// - Valid padding (0-2 `=` chars at end only)
    /// - Actually decodes successfully
    fn is_valid_base64(s: &str) -> bool {
        // Too short — likely not base64
        if s.len() < 24 {
            return false;
        }

        // Base64 output length must be divisible by 4
        if s.len() % 4 != 0 {
            return false;
        }

        // Check character validity (base64 alphabet only)
        let valid_chars = s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');

        if !valid_chars {
            return false;
        }

        // Padding must be at the end only, max 2 chars
        let padding_count = s.chars().rev().take_while(|&c| c == '=').count();
        if padding_count > 2 {
            return false;
        }

        // No padding in the middle
        if s.trim_end_matches('=').contains('=') {
            return false;
        }

        // Final check: must actually decode
        BASE64.decode(s).is_ok()
    }

    fn compute_hash(value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Encrypt and persist the current secrets to `vault.enc` (always as v3).
    /// Computes and stores value hashes for change detection.
    pub fn save(&self) -> Result<()> {
        // Clone environments and compute hashes before persisting
        let mut environments = self.environments.clone();
        for secrets in environments.values_mut() {
            for entry in secrets.values_mut() {
                entry.hash = Some(Self::compute_hash(&entry.value));
            }
        }
        let payload = VaultPayloadV3 {
            version: CURRENT_VERSION,
            environments,
        };
        let plaintext = serde_json::to_vec(&payload)?;

        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        let file_data = EncryptedVaultFile {
            version: CURRENT_VERSION,
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        };

        let json = serde_json::to_string_pretty(&file_data)?;
        fs::write(&self.path, json).context("Failed to write to vault.enc")?;
        Ok(())
    }

    // ========== Environment Management ==========

    /// List all environment names in the vault.
    pub fn list_environments(&self) -> Vec<String> {
        let mut envs: Vec<_> = self.environments.keys().cloned().collect();
        envs.sort();
        envs
    }

    /// Create a new empty environment. Returns false if it already exists.
    pub fn create_environment(&mut self, env: &str) -> bool {
        if self.environments.contains_key(env) {
            false
        } else {
            self.environments.insert(env.to_string(), HashMap::new());
            true
        }
    }

    /// Delete an environment and all its secrets. Returns false if it doesn't exist.
    pub fn delete_environment(&mut self, env: &str) -> bool {
        self.environments.remove(env).is_some()
    }

    /// Check if an environment exists.
    #[allow(dead_code)] // Public API for future use
    pub fn has_environment(&self, env: &str) -> bool {
        self.environments.contains_key(env)
    }

    /// Get the number of secrets in a specific environment.
    pub fn count_in_env(&self, env: &str) -> usize {
        self.environments.get(env).map(|s| s.len()).unwrap_or(0)
    }

    // ========== Secret Operations (Environment-Aware) ==========

    /// Insert or overwrite a secret in a specific environment.
    /// Automatically detects format and updates timestamps. Source defaults to "manual".
    pub fn set_in_env(&mut self, env: &str, key: &str, value: &str) {
        let now = Utc::now();
        let format = Self::detect_format(value);

        let secrets = self.environments.entry(env.to_string()).or_default();

        match secrets.get_mut(key) {
            Some(entry) => {
                entry.value = value.to_string();
                entry.format = format;
                entry.updated_at = now;
                entry.hash = None;
            }
            None => {
                secrets.insert(
                    key.to_string(),
                    SecretEntry {
                        value: value.to_string(),
                        format,
                        hash: None,
                        created_at: now,
                        updated_at: now,
                        description: None,
                        source: Some("manual".to_string()),
                        source_id: None,
                        history: Vec::new(),
                    },
                );
            }
        }
    }

    /// Insert or overwrite a secret with explicit metadata in a specific environment.
    pub fn set_with_metadata_in_env(
        &mut self,
        env: &str,
        key: &str,
        value: &str,
        format: SecretFormat,
        description: Option<String>,
        source: Option<String>,
        source_id: Option<String>,
    ) {
        let now = Utc::now();
        let secrets = self.environments.entry(env.to_string()).or_default();

        match secrets.get_mut(key) {
            Some(entry) => {
                // Save current value to history before updating (only if value changed)
                if entry.value != value {
                    let historical = HistoricalValue {
                        value: entry.value.clone(),
                        format: entry.format.clone(),
                        updated_at: entry.updated_at,
                        source: entry.source.clone(),
                    };
                    entry.history.insert(0, historical);
                    // Keep only the last MAX_HISTORY_SIZE entries
                    entry.history.truncate(MAX_HISTORY_SIZE);
                }

                entry.value = value.to_string();
                entry.format = format;
                entry.description = description;
                entry.updated_at = now;
                entry.hash = None;
                if source.is_some() {
                    entry.source = source;
                }
                if source_id.is_some() {
                    entry.source_id = source_id;
                }
            }
            None => {
                secrets.insert(
                    key.to_string(),
                    SecretEntry {
                        value: value.to_string(),
                        format,
                        hash: None,
                        created_at: now,
                        updated_at: now,
                        description,
                        source: source.or_else(|| Some("manual".to_string())),
                        source_id,
                        history: Vec::new(),
                    },
                );
            }
        }
    }

    /// Fetch a secret value by key from a specific environment.
    pub fn get_in_env(&self, env: &str, key: &str) -> Option<&String> {
        self.environments
            .get(env)
            .and_then(|secrets| secrets.get(key))
            .map(|e| &e.value)
    }

    /// Fetch the full secret entry by key from a specific environment.
    pub fn get_entry_in_env(&self, env: &str, key: &str) -> Option<&SecretEntry> {
        self.environments
            .get(env)
            .and_then(|secrets| secrets.get(key))
    }

    /// Remove a secret from a specific environment, returning the prior value if present.
    pub fn remove_in_env(&mut self, env: &str, key: &str) -> Option<String> {
        self.environments
            .get_mut(env)
            .and_then(|secrets| secrets.remove(key))
            .map(|e| e.value)
    }

    /// Remove a secret from a specific environment, returning the full entry if present.
    pub fn remove_entry_in_env(&mut self, env: &str, key: &str) -> Option<SecretEntry> {
        self.environments
            .get_mut(env)
            .and_then(|secrets| secrets.remove(key))
    }

    /// List secrets in a specific environment (key → value only).
    pub fn list_in_env(&self, env: &str) -> HashMap<String, String> {
        self.environments
            .get(env)
            .map(|secrets| {
                secrets
                    .iter()
                    .map(|(k, e)| (k.clone(), e.value.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// List full secret entries in a specific environment.
    pub fn list_entries_in_env(&self, env: &str) -> Option<&HashMap<String, SecretEntry>> {
        self.environments.get(env)
    }

    /// Update the description for an existing secret in a specific environment.
    pub fn set_description_in_env(
        &mut self,
        env: &str,
        key: &str,
        description: Option<String>,
    ) -> bool {
        if let Some(secrets) = self.environments.get_mut(env) {
            if let Some(entry) = secrets.get_mut(key) {
                entry.description = description;
                entry.updated_at = Utc::now();
                return true;
            }
        }
        false
    }

    /// Get the history of a secret in a specific environment.
    #[allow(dead_code)] // Public API for future use
    pub fn get_history_in_env(&self, env: &str, key: &str) -> Option<&Vec<HistoricalValue>> {
        self.environments
            .get(env)
            .and_then(|secrets| secrets.get(key))
            .map(|e| &e.history)
    }

    /// Rollback a secret to a previous version by index (0 = most recent previous value).
    /// Returns the value that was rolled back to, or None if the key or version doesn't exist.
    pub fn rollback_in_env(
        &mut self,
        env: &str,
        key: &str,
        version_index: usize,
    ) -> Option<String> {
        let secrets = self.environments.get_mut(env)?;
        let entry = secrets.get_mut(key)?;

        if version_index >= entry.history.len() {
            return None;
        }

        // Get the historical value to restore
        let historical = entry.history.remove(version_index);

        // Save current value to history first
        let current_historical = HistoricalValue {
            value: entry.value.clone(),
            format: entry.format.clone(),
            updated_at: entry.updated_at,
            source: entry.source.clone(),
        };
        entry.history.insert(0, current_historical);
        entry.history.truncate(MAX_HISTORY_SIZE);

        // Restore the historical value
        let restored_value = historical.value.clone();
        entry.value = historical.value;
        entry.format = historical.format;
        entry.source = historical.source;
        entry.updated_at = Utc::now();
        entry.hash = None; // Clear hash since value changed

        Some(restored_value)
    }

    // ========== Backward-Compatible Methods (Default Environment) ==========

    /// Insert or overwrite a secret in the default environment.
    /// Automatically detects format and updates timestamps. Source defaults to "manual".
    pub fn set(&mut self, key: &str, value: &str) {
        self.set_in_env(DEFAULT_ENV, key, value)
    }

    /// Insert or overwrite a secret with explicit metadata in the default environment.
    pub fn set_with_metadata(
        &mut self,
        key: &str,
        value: &str,
        format: SecretFormat,
        description: Option<String>,
        source: Option<String>,
        source_id: Option<String>,
    ) {
        self.set_with_metadata_in_env(
            DEFAULT_ENV,
            key,
            value,
            format,
            description,
            source,
            source_id,
        )
    }

    /// Fetch a secret value by key from the default environment.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.get_in_env(DEFAULT_ENV, key)
    }

    /// Fetch the full secret entry by key from the default environment.
    pub fn get_entry(&self, key: &str) -> Option<&SecretEntry> {
        self.get_entry_in_env(DEFAULT_ENV, key)
    }

    /// Remove a secret from the default environment, returning the prior value if present.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.remove_in_env(DEFAULT_ENV, key)
    }

    /// Remove a secret from the default environment, returning the full entry if present.
    pub fn remove_entry(&mut self, key: &str) -> Option<SecretEntry> {
        self.remove_entry_in_env(DEFAULT_ENV, key)
    }

    /// List secrets in the default environment (key → value only, for backward compatibility).
    pub fn list(&self) -> HashMap<String, String> {
        self.list_in_env(DEFAULT_ENV)
    }

    /// List full secret entries in the default environment.
    pub fn list_entries(&self) -> &HashMap<String, SecretEntry> {
        self.environments.get(DEFAULT_ENV).unwrap_or_else(|| {
            // This should never happen after load(), but provide empty fallback
            static EMPTY: std::sync::OnceLock<HashMap<String, SecretEntry>> =
                std::sync::OnceLock::new();
            EMPTY.get_or_init(HashMap::new)
        })
    }

    /// Update the description for an existing secret in the default environment.
    pub fn set_description(&mut self, key: &str, description: Option<String>) -> bool {
        self.set_description_in_env(DEFAULT_ENV, key, description)
    }

    /// Update the hash for an existing secret in the default environment.
    #[allow(dead_code)]
    pub fn set_hash(&mut self, key: &str, hash: Option<String>) -> bool {
        self.set_hash_in_env(DEFAULT_ENV, key, hash)
    }

    /// Update the hash for an existing secret in a specific environment.
    #[allow(dead_code)]
    pub fn set_hash_in_env(&mut self, env: &str, key: &str, hash: Option<String>) -> bool {
        if let Some(secrets) = self.environments.get_mut(env) {
            if let Some(entry) = secrets.get_mut(key) {
                entry.hash = hash;
                return true;
            }
        }
        false
    }

    // ========== Cross-Environment Helpers ==========

    /// List all secrets across all environments with their environment names.
    pub fn list_all_entries(&self) -> Vec<(&str, &str, &SecretEntry)> {
        let mut result = Vec::new();
        for (env, secrets) in &self.environments {
            for (key, entry) in secrets {
                result.push((env.as_str(), key.as_str(), entry));
            }
        }
        result.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(b.1)));
        result
    }

    /// Get the total number of secrets across all environments.
    pub fn total_count(&self) -> usize {
        self.environments.values().map(|s| s.len()).sum()
    }
}
