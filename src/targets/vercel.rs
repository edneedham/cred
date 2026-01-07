//! Vercel target adapter for cred.
//! Pushes environment variables to Vercel projects using their REST API.
//! No encryption required - Vercel handles this server-side.

use super::{PushOptions, TargetAdapter};
use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

/// Adapter that pushes environment variables to Vercel projects.
pub struct Vercel;

/// Shape of a Vercel environment variable response.
#[derive(Deserialize, Debug)]
struct EnvVar {
    id: String,
    key: String,
    #[allow(dead_code)]
    value: String,
    #[allow(dead_code)]
    target: Vec<String>,
}

/// Response from listing environment variables.
#[derive(Deserialize, Debug)]
struct EnvVarsResponse {
    envs: Vec<EnvVar>,
}

/// Request body for creating/updating an environment variable.
#[derive(Serialize)]
struct CreateEnvVarRequest {
    key: String,
    value: String,
    target: Vec<String>,
    #[serde(rename = "type")]
    env_type: String,
}

/// Minimal vercel.json structure for project ID detection.
#[derive(Deserialize)]
struct VercelJson {
    #[serde(rename = "projectId")]
    project_id: Option<String>,
}

/// Minimal .vercel/project.json structure for project ID detection.
#[derive(Deserialize)]
struct VercelProjectJson {
    #[serde(rename = "projectId")]
    project_id: Option<String>,
}

impl Vercel {
    const UA: &'static str = "cred-cli";

    fn with_headers<'a>(&self, builder: RequestBuilder, token: &'a str) -> RequestBuilder {
        builder
            .header("User-Agent", Self::UA)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
    }

    /// Map cred environment name to Vercel target(s).
    /// - "prod" or "production" -> ["production"]
    /// - "default" or "dev" or "development" -> ["development"]
    /// - anything else -> ["preview"]
    fn map_env_to_target(&self, env: &str) -> Vec<String> {
        match env.to_lowercase().as_str() {
            "prod" | "production" => vec!["production".to_string()],
            "default" | "dev" | "development" => vec!["development".to_string()],
            _ => vec!["preview".to_string()],
        }
    }

    /// Try to detect project ID from vercel.json or .vercel/project.json.
    fn detect_project_id(&self) -> Option<String> {
        // Try .vercel/project.json first (created by `vercel link`)
        if let Ok(content) = fs::read_to_string(".vercel/project.json") {
            if let Ok(parsed) = serde_json::from_str::<VercelProjectJson>(&content) {
                if let Some(id) = parsed.project_id {
                    return Some(id);
                }
            }
        }

        // Fall back to vercel.json
        if let Ok(content) = fs::read_to_string("vercel.json") {
            if let Ok(parsed) = serde_json::from_str::<VercelJson>(&content) {
                if let Some(id) = parsed.project_id {
                    return Some(id);
                }
            }
        }

        None
    }

    /// Resolve project ID from options or auto-detection.
    fn resolve_project(&self, options: &PushOptions) -> Result<String> {
        if let Some(ref project) = options.project {
            return Ok(project.clone());
        }

        self.detect_project_id().ok_or_else(|| {
            anyhow::anyhow!(
                "Could not detect Vercel project. Run `vercel link` or specify --project <id>"
            )
        })
    }

    /// Get existing environment variables for a project.
    async fn list_env_vars(
        &self,
        client: &Client,
        token: &str,
        project_id: &str,
    ) -> Result<Vec<EnvVar>> {
        let url = format!("https://api.vercel.com/v9/projects/{}/env", project_id);

        let resp: EnvVarsResponse = self
            .with_headers(client.get(&url), token)
            .send()
            .await?
            .error_for_status()
            .context("Failed to list Vercel environment variables")?
            .json()
            .await?;

        Ok(resp.envs)
    }
}

impl TargetAdapter for Vercel {
    fn name(&self) -> &str {
        "vercel"
    }

    /// Pushes secrets to a Vercel project as environment variables.
    /// Creates new env vars or updates existing ones.
    async fn push(
        &self,
        secrets: &HashMap<String, String>,
        auth_token: &str,
        options: &PushOptions,
    ) -> Result<()> {
        let project_id = self.resolve_project(options)?;
        let client = Client::new();

        // Determine Vercel target from cred environment
        let vercel_target = self.map_env_to_target(options.env.as_deref().unwrap_or("default"));
        let target_display = vercel_target.join(", ");

        println!(
            "🚀 Pushing to Vercel [project: {}, target: {}]",
            project_id, target_display
        );

        // Get existing env vars to check for updates vs creates
        let existing = self.list_env_vars(&client, auth_token, &project_id).await?;
        let existing_keys: HashMap<String, String> = existing
            .iter()
            .map(|e| (e.key.clone(), e.id.clone()))
            .collect();

        for (key, value) in secrets {
            let api_url = if let Some(env_id) = existing_keys.get(key) {
                // Update existing env var
                format!(
                    "https://api.vercel.com/v9/projects/{}/env/{}",
                    project_id, env_id
                )
            } else {
                // Create new env var
                format!("https://api.vercel.com/v10/projects/{}/env", project_id)
            };

            let body = CreateEnvVarRequest {
                key: key.clone(),
                value: value.clone(),
                target: vercel_target.clone(),
                env_type: "encrypted".to_string(),
            };

            let is_update = existing_keys.contains_key(key);
            let resp = if is_update {
                self.with_headers(client.patch(&api_url), auth_token)
                    .json(&body)
                    .send()
                    .await?
            } else {
                self.with_headers(client.post(&api_url), auth_token)
                    .json(&body)
                    .send()
                    .await?
            };

            if resp.status().is_success() {
                let action = if is_update { "Updated" } else { "Set" };
                println!("  ✓ {}: {}", action, key);
            } else {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                eprintln!("  ✗ Failed: {} (Status: {}, Body: {})", key, status, body);
            }
        }

        Ok(())
    }

    /// Deletes environment variables from a Vercel project.
    async fn delete(&self, keys: &[String], auth_token: &str, options: &PushOptions) -> Result<()> {
        let project_id = self.resolve_project(options)?;
        let client = Client::new();

        println!(
            "🗑️  Pruning {} secrets from Vercel [project: {}]",
            keys.len(),
            project_id
        );

        // Get existing env vars to find IDs
        let existing = self.list_env_vars(&client, auth_token, &project_id).await?;
        let existing_keys: HashMap<String, String> = existing
            .iter()
            .map(|e| (e.key.clone(), e.id.clone()))
            .collect();

        for key in keys {
            if let Some(env_id) = existing_keys.get(key) {
                let url = format!(
                    "https://api.vercel.com/v9/projects/{}/env/{}",
                    project_id, env_id
                );

                let resp = self
                    .with_headers(client.delete(&url), auth_token)
                    .send()
                    .await?;

                let status = resp.status();
                if status.is_success() {
                    println!("  ✓ Deleted: {}", key);
                } else {
                    eprintln!("  ✗ Failed to delete: {} (Status: {})", key, status);
                }
            } else {
                println!("  ~ Skipped: {} (Not found)", key);
            }
        }

        Ok(())
    }

    /// Vercel tokens cannot be revoked via API; we only inform the user.
    async fn revoke_auth_token(&self, _auth_token: &str) -> Result<()> {
        println!("ℹ️  Vercel tokens can be revoked at vercel.com/account/tokens");
        Ok(())
    }
}
