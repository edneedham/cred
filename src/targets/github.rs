//! GitHub target adapter for cred.
//! Uses the repository public key and GitHub-required sealed boxes (Curve25519 + XSalsa20-Poly1305)
//! when pushing secrets. Each target owns its own encryption format so future providers can diverge.

use super::{PushOptions, TargetAdapter};
use crate::vault::DEFAULT_ENV;
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::Deserialize;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;
use sodiumoxide::crypto::sealedbox;
use std::collections::HashMap;

/// Adapter that pushes secrets to GitHub Actions using a PAT with `actions:write`.
pub struct Github;

/// Shape of the `GET /actions/secrets/public-key` response.
#[derive(Deserialize)]
struct PublicKeyResponse {
    key_id: String,
    key: String,
}

struct GitHubTarget(String);

impl Github {
    const UA: &'static str = "cred-cli";
    const API_VERSION: &'static str = "2022-11-28";

    fn with_headers<'a>(&self, builder: RequestBuilder, token: &'a str) -> RequestBuilder {
        builder
            .header("User-Agent", Self::UA)
            .header("Authorization", format!("Bearer {}", token))
            .header("X-GitHub-Api-Version", Self::API_VERSION)
    }

    /// Encrypts a secret with GitHub's repository public key using NaCl sealed boxes.
    /// Returns base64-encoded ciphertext suitable for `encrypted_value` in the API.
    fn encrypt_secret(&self, public_key_b64: &str, value: &str) -> Result<String> {
        sodiumoxide::init().map_err(|_| anyhow::anyhow!("Failed to initialize sodiumoxide"))?;

        let public_key_bytes = BASE64
            .decode(public_key_b64)
            .context("Failed to decode GitHub public key")?;

        let pk = PublicKey::from_slice(&public_key_bytes)
            .ok_or_else(|| anyhow::anyhow!("Invalid public key length from GitHub"))?;

        let encrypted_bytes = sealedbox::seal(value.as_bytes(), &pk);

        Ok(BASE64.encode(encrypted_bytes))
    }

    fn env_scope<'a>(&self, options: &'a PushOptions) -> Option<&'a str> {
        options.env.as_deref().filter(|env| *env != DEFAULT_ENV)
    }

    fn secrets_api_base(&self, repo: &str, env: Option<&str>) -> String {
        match env {
            Some(name) => format!(
                "https://api.github.com/repos/{}/environments/{}/secrets",
                repo, name
            ),
            None => format!("https://api.github.com/repos/{}/actions/secrets", repo),
        }
    }

    async fn ensure_environment(
        &self,
        client: &Client,
        auth_token: &str,
        repo: &str,
        env: &str,
    ) -> Result<()> {
        let url = format!("https://api.github.com/repos/{}/environments/{}", repo, env);
        let resp = self
            .with_headers(client.put(&url), auth_token)
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            bail!(
                "Failed to create GitHub environment '{}' (status {}). Ensure your token can manage environments.",
                env,
                resp.status()
            )
        }
    }

    /// Derives `owner/repo` from `git remote get-url origin`.
    /// Errors if the remote is missing or not in a recognizable format.
    fn get_repo_from_git(&self) -> Result<String> {
        use std::process::Command;

        let output = Command::new("git")
            .args(["remote", "get-url", "origin"])
            .output()
            .context("Failed to run git command")?;

        if !output.status.success() {
            anyhow::bail!(
                "Could not detect git remote 'origin'. Please ensure you are in a git repository."
            );
        }

        let remote = String::from_utf8(output.stdout)?.trim().to_string();

        let clean = remote.trim_end_matches(".git");

        let parts: Vec<&str> = clean.split(|c| c == '/' || c == ':').collect();
        if parts.len() < 2 {
            anyhow::bail!("Invalid git remote format: {}", remote);
        }

        let repo = parts.last().unwrap();
        let owner = parts[parts.len() - 2];

        Ok(format!("{}/{}", owner, repo))
    }

    /// Resolves a GitHub target from CLI options; kept for parity with other targets.
    async fn resolve_target(
        &self,
        _client: &Client,
        _token: &str,
        repo: &str,
    ) -> Result<GitHubTarget> {
        Ok(GitHubTarget(repo.to_string()))
    }
}

impl TargetAdapter for Github {
    /// Human-readable adapter name.
    fn name(&self) -> &str {
        "github"
    }

    /// Pushes secrets to a repository by fetching its public key, encrypting each value,
    /// and calling `PUT /repos/{owner}/{repo}/actions/secrets/{name}`.
    async fn push(
        &self,
        secrets: &HashMap<String, String>,
        auth_token: &str,
        _options: &PushOptions,
    ) -> Result<()> {
        let repo_name = match &_options.repo {
            Some(r) => r.clone(),
            None => self.get_repo_from_git()?,
        };

        let client = Client::new();
        let target = self.resolve_target(&client, auth_token, &repo_name).await?;

        let env_scope = self.env_scope(_options);
        let api_base = self.secrets_api_base(&target.0, env_scope);
        let human_name = match env_scope {
            Some(env) => format!("Repository: {} (env: {})", target.0, env),
            None => format!("Repository: {}", target.0),
        };

        println!("🚀 Pushing to GitHub [{}]", human_name);

        let pub_key_url = format!("{}/public-key", api_base);

        let mut key_resp = self
            .with_headers(client.get(&pub_key_url), auth_token)
            .send()
            .await?;

        if key_resp.status() == StatusCode::NOT_FOUND {
            if let Some(env) = env_scope {
                self.ensure_environment(&client, auth_token, &target.0, env)
                    .await?;
                key_resp = self
                    .with_headers(client.get(&pub_key_url), auth_token)
                    .send()
                    .await?;
            }
        }

        let key_resp: PublicKeyResponse = key_resp
            .error_for_status()
            .context("Failed to get GitHub public key")?
            .json()
            .await?;

        for (key, value) in secrets {
            let encrypted_val = self.encrypt_secret(&key_resp.key, value)?;

            let put_url = format!("{}/{}", api_base, key);
            let body = serde_json::json!({
                "encrypted_value": encrypted_val,
                "key_id": key_resp.key_id
            });

            let resp = self
                .with_headers(client.put(&put_url), auth_token)
                .json(&body)
                .send()
                .await?;

            if resp.status().is_success() {
                println!("  ✓ Set: {}", key);
            } else {
                eprintln!("  x Failed: {} (Status: {})", key, resp.status());
            }
        }
        Ok(())
    }

    /// Deletes secrets from a repository via `DELETE /repos/{owner}/{repo}/actions/secrets/{name}`.
    /// Treats 404s as no-op skips; other failures abort the operation.
    async fn delete(
        &self,
        keys: &[String],
        auth_token: &str,
        _options: &PushOptions,
    ) -> Result<()> {
        let repo_name = match &_options.repo {
            Some(r) => r.clone(),
            None => self.get_repo_from_git()?,
        };

        let client = Client::new();
        let target = self.resolve_target(&client, auth_token, &repo_name).await?;

        let env_scope = self.env_scope(_options);
        let api_base = self.secrets_api_base(&target.0, env_scope);
        let human_name = match env_scope {
            Some(env) => format!("Repository: {} (env: {})", target.0, env),
            None => format!("Repository: {}", target.0),
        };

        println!(
            "🗑️  Pruning {} secrets from GitHub [{}]",
            keys.len(),
            human_name
        );

        for key in keys {
            let url = format!("{}/{}", api_base, key);
            let resp = self
                .with_headers(client.delete(&url), auth_token)
                .send()
                .await?;

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

    /// GitHub PAT revocation is not supported via API; we only inform the user.
    async fn revoke_auth_token(&self, _auth_token: &str) -> Result<()> {
        println!("ℹ️  GitHub PATs cannot be revoked via API.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_scope_default_and_none() {
        let gh = Github;
        let none_env = PushOptions {
            repo: None,
            project: None,
            app: None,
            env: None,
        };
        assert!(gh.env_scope(&none_env).is_none());

        let default_env = PushOptions {
            repo: None,
            project: None,
            app: None,
            env: Some(DEFAULT_ENV.to_string()),
        };
        assert!(gh.env_scope(&default_env).is_none());
    }

    #[test]
    fn test_env_scope_non_default() {
        let gh = Github;
        let prod_env = PushOptions {
            repo: None,
            project: None,
            app: None,
            env: Some("production".to_string()),
        };
        assert_eq!(gh.env_scope(&prod_env), Some("production"));
    }

    #[test]
    fn test_secrets_api_base() {
        let gh = Github;
        let repo = "owner/repo";
        let repo_base = gh.secrets_api_base(repo, None);
        assert_eq!(
            repo_base,
            "https://api.github.com/repos/owner/repo/actions/secrets"
        );

        let env_base = gh.secrets_api_base(repo, Some("prod"));
        assert_eq!(
            env_base,
            "https://api.github.com/repos/owner/repo/environments/prod/secrets"
        );
    }
}
