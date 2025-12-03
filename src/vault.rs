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
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize)]
struct EncryptedVaultFile {
    version: u8,
    nonce: String,
    ciphertext: String
}

#[derive(Serialize, Deserialize, Debug, Default, Zeroize, ZeroizeOnDrop)]
pub struct Vault {
    #[serde(skip)]
    #[zeroize(skip)]
    path: PathBuf,

    #[serde(skip)]
    #[zeroize(skip)]
    project_id: String,
    // Matrix: Environment -> { Key -> Value }
    secrets: HashMap<String, HashMap<String, String>>,
}

impl Vault {
    pub fn load(vault_path: &Path, project_id: &str) -> Result<Self> {
        let mut vault = Vault {
            path: vault_path.to_path_buf(),
            project_id: project_id.to_string(),
            secrets: HashMap::new(),
        };

        if !vault_path.exists() {
            return Ok(vault);
        }
        let content = fs::read_to_string(vault_path).context("Failed to read vault.enc")?;
        let file_data: EncryptedVaultFile = serde_json::from_str(&content)
            .context("Failed to parse vault structure")?;

        let entry = Entry::new("cred", project_id)?;
        let key_b64 = entry.get_password().context("Could not find encryption key in OS Keychain. Did you init?")?;
        let key_bytes = BASE64.decode(key_b64).context("Invalid key format in keychain")?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?;

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
        let entry = Entry::new("cred", &self.project_id)?;
        let key_b64 = entry.get_password().context("Key missing from keychain")?;
        let key_bytes = BASE64.decode(key_b64)?;

        let plaintext = serde_json::to_vec(&self.secrets)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
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