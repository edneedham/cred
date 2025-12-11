//! Encrypted local vault (secrets at rest) using ChaCha20-Poly1305 and base64 serialization.
//!
//! # Vault Schema Versions
//! - **v1**: Legacy format where decrypted payload is `HashMap<String, String>`
//! - **v2**: Current format with `SecretEntry` containing value, format, hash, timestamps, description
//!
//! Migration from v1 to v2 is automatic on load; v2 is always written on save.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Current vault schema version.
const CURRENT_VERSION: u8 = 2;

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
}

impl Zeroize for SecretEntry {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.hash.zeroize();
        self.description.zeroize();
    }
}

/// V2 decrypted payload structure.
#[derive(Serialize, Deserialize, Debug)]
struct VaultPayloadV2 {
    version: u8,
    secrets: HashMap<String, SecretEntry>,
}

/// In-memory vault plus file/key context.
#[derive(Debug, Default)]
pub struct Vault {
    path: PathBuf,
    key: [u8; 32],
    secrets: HashMap<String, SecretEntry>,
}

impl Zeroize for Vault {
    fn zeroize(&mut self) {
        self.secrets.drain().for_each(|(mut k, mut v)| {
            k.zeroize();
            v.zeroize();
        });
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
    /// Automatically migrates v1 vaults to v2 format in memory.
    pub fn load(vault_path: &Path, key: [u8; 32]) -> Result<Self> {
        let mut vault = Vault {
            path: vault_path.to_path_buf(),
            key,
            secrets: HashMap::new(),
        };

        if !vault_path.exists() {
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

        let secrets = match file_data.version {
            1 => Self::migrate_v1_to_v2(&plaintext)?,
            2 => Self::parse_v2(&plaintext)?,
            v => bail!("Unsupported vault version: {}. Please upgrade cred.", v),
        };

        vault.secrets = secrets;
        Ok(vault)
    }

    /// Migrate v1 (bare strings) to v2 (SecretEntry).
    fn migrate_v1_to_v2(plaintext: &[u8]) -> Result<HashMap<String, SecretEntry>> {
        let old_secrets: HashMap<String, String> =
            serde_json::from_slice(plaintext).context("Failed to parse v1 secrets")?;

        let now = Utc::now();
        let migrated = old_secrets
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
                };
                (k, entry)
            })
            .collect();

        Ok(migrated)
    }

    /// Parse v2 payload directly.
    fn parse_v2(plaintext: &[u8]) -> Result<HashMap<String, SecretEntry>> {
        let payload: VaultPayloadV2 =
            serde_json::from_slice(plaintext).context("Failed to parse v2 payload")?;
        Ok(payload.secrets)
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

    /// Encrypt and persist the current secrets to `vault.enc` (always as v2).
    pub fn save(&self) -> Result<()> {
        let payload = VaultPayloadV2 {
            version: CURRENT_VERSION,
            secrets: self.secrets.clone(),
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

    /// Insert or overwrite a secret key/value in memory (not persisted until `save`).
    /// Automatically detects format and updates timestamps.
    pub fn set(&mut self, key: &str, value: &str) {
        let now = Utc::now();
        let format = Self::detect_format(value);

        match self.secrets.get_mut(key) {
            Some(entry) => {
                entry.value = value.to_string();
                entry.format = format;
                entry.updated_at = now;
                // Clear hash since value changed; will be recomputed if needed
                entry.hash = None;
            }
            None => {
                self.secrets.insert(
                    key.to_string(),
                    SecretEntry {
                        value: value.to_string(),
                        format,
                        hash: None,
                        created_at: now,
                        updated_at: now,
                        description: None,
                    },
                );
            }
        }
    }

    /// Insert or overwrite a secret with explicit metadata.
    pub fn set_with_metadata(
        &mut self,
        key: &str,
        value: &str,
        format: SecretFormat,
        description: Option<String>,
    ) {
        let now = Utc::now();

        match self.secrets.get_mut(key) {
            Some(entry) => {
                entry.value = value.to_string();
                entry.format = format;
                entry.description = description;
                entry.updated_at = now;
                entry.hash = None;
            }
            None => {
                self.secrets.insert(
                    key.to_string(),
                    SecretEntry {
                        value: value.to_string(),
                        format,
                        hash: None,
                        created_at: now,
                        updated_at: now,
                        description,
                    },
                );
            }
        }
    }

    /// Fetch a secret value by key from memory.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.secrets.get(key).map(|e| &e.value)
    }

    /// Fetch the full secret entry by key from memory.
    pub fn get_entry(&self, key: &str) -> Option<&SecretEntry> {
        self.secrets.get(key)
    }

    /// Remove a secret, returning the prior value if present (not persisted until `save`).
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.secrets.remove(key).map(|e| e.value)
    }

    /// Remove a secret, returning the full entry if present.
    pub fn remove_entry(&mut self, key: &str) -> Option<SecretEntry> {
        self.secrets.remove(key)
    }

    /// Borrow the in-memory secrets map (key → value only, for backward compatibility).
    pub fn list(&self) -> HashMap<String, String> {
        self.secrets
            .iter()
            .map(|(k, e)| (k.clone(), e.value.clone()))
            .collect()
    }

    /// Borrow the full in-memory secrets map with all metadata.
    pub fn list_entries(&self) -> &HashMap<String, SecretEntry> {
        &self.secrets
    }

    /// Update the description for an existing secret.
    pub fn set_description(&mut self, key: &str, description: Option<String>) -> bool {
        if let Some(entry) = self.secrets.get_mut(key) {
            entry.description = description;
            entry.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    /// Update the hash for an existing secret.
    #[allow(dead_code)]
    pub fn set_hash(&mut self, key: &str, hash: Option<String>) -> bool {
        if let Some(entry) = self.secrets.get_mut(key) {
            entry.hash = hash;
            true
        } else {
            false
        }
    }
}
