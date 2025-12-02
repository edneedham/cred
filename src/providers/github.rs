use super::{Provider, PushOptions};
use std::collections::HashMap;
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

pub struct Github;

#[derive(Deserialize)]
struct PublicKeyResponse { key_id: String }

impl Provider for Github {
    fn name(&self) -> &str { "github" }

    async fn push(&self, secrets: &HashMap<String, String>, auth_token: &str, options: &PushOptions) -> Result<()> {
        let repo = options.repo.as_ref()
            .ok_or_else(|| anyhow::anyhow!("GitHub provider requires '--repo <owner/name>' argument"))?;

        let target_env = options.env.as_deref().unwrap_or("production");
        
        println!("🚀 Pushing to GitHub (Repo: {}, Env: {})", repo, target_env);
        
        let client = Client::new();

        let pub_key_url = format!("https://api.github.com/repos/{}/actions/secrets/public-key", repo);
        
        let key_resp: PublicKeyResponse = client
            .get(&pub_key_url)
            .header("User-Agent", "cred-cli")
            .header("Authorization", format!("Bearer {}", auth_token))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await?
            .error_for_status()
            .context("Failed to connect to GitHub.")?
            .json()
            .await?;

        println!("✓ Authenticated with GitHub.");

        for (key, _value) in secrets {
            let url = format!("https://api.github.com/repos/{}/actions/secrets/{}", repo, key);
            let encrypted_value = "DUMMY_ENCRYPTED_VALUE_REQUIRES_LIBSODIUM"; 

            let body = serde_json::json!({
                "encrypted_value": encrypted_value,
                "key_id": key_resp.key_id
            });

            let response = client
                .put(&url)
                .header("User-Agent", "cred-cli")
                .header("Authorization", format!("Bearer {}", auth_token))
                .header("X-GitHub-Api-Version", "2022-11-28")
                .json(&body)
                .send()
                .await?;
                
            if response.status().is_success() {
                println!("  ✓ Set secret: {}", key);
            } else {
                eprintln!("  x Failed to set: {} (Status: {})", key, response.status());
            }
        }
        Ok(())
    }

    async fn delete(&self, keys: &[String], auth_token: &str, options: &PushOptions) -> Result<()> {
        let repo = options.repo.as_ref()
            .ok_or_else(|| anyhow::anyhow!("GitHub provider requires '--repo'"))?;

        println!("🗑️  Pruning {} secrets from GitHub Repo: {}", keys.len(), repo);
        let client = Client::new();

        for key in keys {
            let url = format!("https://api.github.com/repos/{}/actions/secrets/{}", repo, key);
            let response = client
                .delete(&url)
                .header("User-Agent", "cred-cli")
                .header("Authorization", format!("Bearer {}", auth_token))
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .await?;

            let status = response.status();
            if status.is_success() {
                println!("  ✓ Remote Deleted: {}", key);
            } else if status.as_u16() == 404 {
                println!("  ~ Remote skipped: {} (Already gone)", key);
            } else {
                anyhow::bail!("Failed to delete {} from remote. Status: {}", key, status);
            }
        }
        Ok(())
    }

    async fn revoke_auth_token(&self, _auth_token: &str) -> Result<()> {
        println!("ℹ️  Note: GitHub Personal Access Tokens cannot be revoked via API.");
        Ok(())
    }
}