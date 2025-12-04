use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};
use keyring::Entry;
use zeroize::{Zeroize};

#[derive(Serialize, Deserialize)]
struct EncryptedVaultFile {
    version: u8,
    nonce: String,
    ciphertext: String
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Vault {
    #[serde(skip)]
    path: PathBuf,

    #[serde(skip)]
    key: [u8; 32],
    // Matrix: Environment -> { Key -> Value }
    secrets: HashMap<String, HashMap<String, String>>,
}

impl Zeroize for Vault {
    fn zeroize(&mut self) {
        // Recursively drain and zeroize the map contents
        self.secrets.drain().for_each(|(mut k, mut v)| {
            k.zeroize();
            v.drain().for_each(|(mut inner_k, mut inner_v)| {
                inner_k.zeroize();
                inner_v.zeroize();
            });
        });
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Vault {
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
        let file_data: EncryptedVaultFile = serde_json::from_str(&content)
            .context("Failed to parse vault structure")?;

        let cipher = ChaCha20Poly1305::new(&key.into());

        let nonce_bytes = BASE64.decode(&file_data.nonce).context("Invalid nonce base64")?;
        let ciphertext = BASE64.decode(&file_data.ciphertext).context("Invalid ciphertext base64")?;

        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| anyhow::anyhow!("Decryption failed. Data corrupted or wrong key."))?;

        let secrets: HashMap<String, HashMap<String, String>> = serde_json::from_slice(&plaintext)
            .context("Failed to parse decrypted secrets JSON")?;

        vault.secrets = secrets;
        Ok(vault)
    }

    pub fn save(&self) -> Result<()> {
        let plaintext = serde_json::to_vec(&self.secrets)?;
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
        let file_data = EncryptedVaultFile {
            version: 1,
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        };
        let json = serde_json::to_string_pretty(&file_data)?;
        fs::write(&self.path, json).context("Failed to write to vault.enc")?;
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