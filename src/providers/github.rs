use super::{Provider, PushOptions};
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
struct RepoDetails {
    id: u64,
}

#[derive(Deserialize)]
struct PublicKeyResponse {
    key_id: String,
    key: String,
}

enum GitHubTarget {
    Repository(String),
    Environment(u64, String),
}

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
    async fn resolve_target(&self, client: &Client, token: &str, repo: &str, env: Option<&String>) -> Result<GitHubTarget> {
        if let Some(env_name) = env {
            let url = format!("https://api.github.com/repos/{}", repo);
            let resp = client.get(&url)
                .header("User-Agent", "cred-cli")
                .header("Authorization", format!("Bearer {}", token))
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send().await?
                .error_for_status()
                .context("Failed to fetch repository details")?;
            
            let details: RepoDetails = resp.json().await?;
            Ok(GitHubTarget::Environment(details.id, env_name.clone()))
        } else {
            Ok(GitHubTarget::Repository(repo.to_string()))
        }
    }
}

impl Provider for Github {
    fn name(&self) -> &str { "github" }

    async fn push(&self, secrets: &HashMap<String, String>, auth_token: &str, options: &PushOptions) -> Result<()> {
        let repo_name = self.get_repo_from_git()?;

        let client = Client::new();
        let target = self.resolve_target(&client, auth_token, &repo_name, options.env.as_ref()).await?;

        let (api_base, human_name) = match &target {
            GitHubTarget::Repository(name) => (
                format!("https://api.github.com/repos/{}/actions/secrets", name),
                format!("Repository: {}", name)
            ),
            GitHubTarget::Environment(id, env) => (
                format!("https://api.github.com/repositories/{}/environments/{}/secrets", id, env),
                format!("Environment: {}", env)
            )
        };

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

    async fn delete(&self, keys: &[String], auth_token: &str, options: &PushOptions) -> Result<()> {
        let repo_name = self.get_repo_from_git()?;

        let client = Client::new();
        let target = self.resolve_target(&client, auth_token, &repo_name, options.env.as_ref()).await?;

        let (api_base, human_name) = match &target {
            GitHubTarget::Repository(name) => (
                format!("https://api.github.com/repos/{}/actions/secrets", name),
                format!("Repository: {}", name)
            ),
            GitHubTarget::Environment(id, env) => (
                format!("https://api.github.com/repositories/{}/environments/{}/secrets", id, env),
                format!("Environment: {}", env)
            )
        };

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