use super::{TargetAdapter, PushOptions};
use std::collections::HashMap;
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

// NEW IMPORTS for sodiumoxide
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use sodiumoxide::crypto::sealedbox;

pub struct Github;

#[derive(Deserialize)]
struct PublicKeyResponse {
    key_id: String,
    key: String,
}

struct GitHubTarget(String);

impl Github {
    fn encrypt_secret(&self, public_key_b64: &str, value: &str) -> Result<String> {
        // 1. Initialize Sodium (Important!)
        // It returns Ok(()) if successful or if already initialized.
        sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

        // 2. Decode the Base64 Public Key
        let public_key_bytes = BASE64.decode(public_key_b64)
            .context("Failed to decode GitHub public key")?;

        // 3. Create a PublicKey object
        // PublicKey::from_slice returns Option<PublicKey> if length is correct (32 bytes)
        let pk = PublicKey::from_slice(&public_key_bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid public key length from GitHub"))?;

        // 4. Encrypt using SealedBox
        // This handles ephemeral key generation and nonce management internally
        let encrypted_bytes = sealedbox::seal(value.as_bytes(), &pk);

        // 5. Encode result to Base64
        Ok(BASE64.encode(encrypted_bytes))
    }

    fn get_repo_from_git(&self) -> Result<String> {
        use std::process::Command;
        
        let output = Command::new("git")
            .args(["remote", "get-url", "origin"])
            .output()
            .context("Failed to run git command")?;
            
        if !output.status.success() {
            anyhow::bail!("Could not detect git remote 'origin'. Please ensure you are in a git repository.");
        }
        
        let remote = String::from_utf8(output.stdout)?.trim().to_string();
        
        // Naive parsing
        // remove .git suffix
        let clean = remote.trim_end_matches(".git");
        
        // Split by / or :
        // https://github.com/OWNER/REPO
        // git@github.com:OWNER/REPO
        
        let parts: Vec<&str> = clean.split(|c| c == '/' || c == ':').collect();
        if parts.len() < 2 {
             anyhow::bail!("Invalid git remote format: {}", remote);
        }
        
        let repo = parts.last().unwrap();
        let owner = parts[parts.len() - 2];
        
        Ok(format!("{}/{}", owner, repo))
    }

    // ... resolve_target remains the same ...
    async fn resolve_target(&self, _client: &Client, _token: &str, repo: &str) -> Result<GitHubTarget> {
        Ok(GitHubTarget(repo.to_string()))
    }
}

impl TargetAdapter for Github {
    fn name(&self) -> &str { "github" }

    async fn push(&self, secrets: &HashMap<String, String>, auth_token: &str, _options: &PushOptions) -> Result<()> {
        let repo_name = match &_options.repo {
            Some(r) => r.clone(),
            None => self.get_repo_from_git()?,
        };

        let client = Client::new();
        let target = self.resolve_target(&client, auth_token, &repo_name).await?;

        let api_base = format!("https://api.github.com/repos/{}/actions/secrets", target.0);
        let human_name = format!("Repository: {}", target.0);

        println!("🚀 Pushing to GitHub [{}]", human_name);

        let pub_key_url = format!("{}/public-key", api_base);

        let key_resp: PublicKeyResponse = client.get(&pub_key_url)
            .header("User-Agent", "cred-cli")
            .header("Authorization", format!("Bearer {}", auth_token))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send().await?
            .error_for_status()
            .context("Failed to get GitHub public key")?
            .json().await?;

        for (key, value) in secrets {
            let encrypted_val = self.encrypt_secret(&key_resp.key, value)?;
            
            let put_url = format!("{}/{}", api_base, key);
            let body = serde_json::json!({
                "encrypted_value": encrypted_val,
                "key_id": key_resp.key_id
            });

            let resp = client.put(&put_url)
                .header("User-Agent", "cred-cli")
                .header("Authorization", format!("Bearer {}", auth_token))
                .header("X-GitHub-Api-Version", "2022-11-28")
                .json(&body)
                .send().await?;

            if resp.status().is_success() {
                println!("  ✓ Set: {}", key);
            } else {
                eprintln!("  x Failed: {} (Status: {})", key, resp.status());
            }
        }
        Ok(())
    }

    async fn delete(&self, keys: &[String], auth_token: &str, _options: &PushOptions) -> Result<()> {
        let repo_name = match &_options.repo {
            Some(r) => r.clone(),
            None => self.get_repo_from_git()?,
        };

        let client = Client::new();
        let target = self.resolve_target(&client, auth_token, &repo_name).await?;

        let api_base = format!("https://api.github.com/repos/{}/actions/secrets", target.0);
        let human_name = format!("Repository: {}", target.0);

        println!("🗑️  Pruning {} secrets from GitHub [{}]", keys.len(), human_name);

        for key in keys {
            let url = format!("{}/{}", api_base, key);
            let resp = client.delete(&url)
                .header("User-Agent", "cred-cli")
                .header("Authorization", format!("Bearer {}", auth_token))
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send().await?;

            let status = resp.status();
            if status.is_success() {
                println!("  ✓ Deleted: {}", key);
            } else if status.as_u16() == 404 {
                println!("  ~ Skipped: {} (Not found)", key);
            } else {
                anyhow::bail!("Failed to delete {}. Status: {}", key, status);
            }
        }
        Ok(())
    }

    async fn revoke_auth_token(&self, _auth_token: &str) -> Result<()> {
        println!("ℹ️  GitHub PATs cannot be revoked via API.");
        Ok(())
    }
}