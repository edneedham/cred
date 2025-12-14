//! GitHub source adapter for cred.
//! Implements OAuth device flow for PAT generation and token management.

use super::{GenerateOptions, SourceAdapter};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// GitHub OAuth App client ID for cred.
/// This is a public OAuth App that requests minimal scopes.
/// Users can also provide their own client_id via config.
const DEFAULT_CLIENT_ID: &str = "Ov23liYourClientIdHere"; // TODO: Register actual OAuth App

/// GitHub source adapter for generating and managing PATs via device flow.
pub struct GithubSource;

/// Response from GitHub's device code endpoint.
#[derive(Deserialize, Debug)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

/// Response from GitHub's access token endpoint.
#[derive(Deserialize, Debug)]
struct AccessTokenResponse {
    access_token: Option<String>,
    token_type: Option<String>,
    scope: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Response from GitHub's user endpoint (for validation).
#[derive(Deserialize, Debug)]
struct UserResponse {
    login: String,
}

/// Device flow state for interactive authorization.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceFlowState {
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
}

impl GithubSource {
    const UA: &'static str = "cred-cli";

    /// Initiate the device flow authorization.
    /// Returns the user code and verification URL for the user to complete authorization.
    pub async fn initiate_device_flow(
        client_id: Option<&str>,
        scopes: &[String],
    ) -> Result<(DeviceFlowState, String)> {
        let client = Client::new();
        let cid = client_id.unwrap_or(DEFAULT_CLIENT_ID);

        let scope = if scopes.is_empty() {
            // Default scopes for PAT generation
            "repo,read:org".to_string()
        } else {
            scopes.join(",")
        };

        let resp = client
            .post("https://github.com/login/device/code")
            .header("User-Agent", Self::UA)
            .header("Accept", "application/json")
            .form(&[("client_id", cid), ("scope", &scope)])
            .send()
            .await
            .context("Failed to initiate device flow")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "GitHub device flow initiation failed: {} - {}",
                status,
                body
            );
        }

        let device_resp: DeviceCodeResponse = resp
            .json()
            .await
            .context("Failed to parse device code response")?;

        let state = DeviceFlowState {
            user_code: device_resp.user_code,
            verification_uri: device_resp.verification_uri,
            expires_in: device_resp.expires_in,
        };

        Ok((state, device_resp.device_code))
    }

    /// Poll for the access token after user authorization.
    /// This should be called repeatedly with the device_code until it succeeds or expires.
    pub async fn poll_for_token(
        client_id: Option<&str>,
        device_code: &str,
        interval_secs: u64,
    ) -> Result<Option<String>> {
        let client = Client::new();
        let cid = client_id.unwrap_or(DEFAULT_CLIENT_ID);

        // Wait the required interval before polling
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;

        let resp = client
            .post("https://github.com/login/oauth/access_token")
            .header("User-Agent", Self::UA)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", cid),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await
            .context("Failed to poll for access token")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GitHub token poll failed: {} - {}", status, body);
        }

        let token_resp: AccessTokenResponse = resp
            .json()
            .await
            .context("Failed to parse token response")?;

        // Check for errors
        if let Some(error) = token_resp.error {
            match error.as_str() {
                "authorization_pending" => {
                    // User hasn't authorized yet, keep polling
                    return Ok(None);
                }
                "slow_down" => {
                    // We're polling too fast, caller should increase interval
                    return Ok(None);
                }
                "expired_token" => {
                    anyhow::bail!("Device code expired. Please restart the authorization flow.");
                }
                "access_denied" => {
                    anyhow::bail!("Authorization was denied by the user.");
                }
                _ => {
                    let desc = token_resp.error_description.unwrap_or_default();
                    anyhow::bail!("GitHub authorization failed: {} - {}", error, desc);
                }
            }
        }

        // Success!
        if let Some(token) = token_resp.access_token {
            Ok(Some(token))
        } else {
            anyhow::bail!("No access token in response");
        }
    }

    /// Complete the device flow by polling until authorized or timeout.
    pub async fn complete_device_flow(
        client_id: Option<&str>,
        device_code: &str,
        interval_secs: u64,
        timeout_secs: u64,
    ) -> Result<String> {
        let start = std::time::Instant::now();
        let mut current_interval = interval_secs;

        loop {
            if start.elapsed().as_secs() > timeout_secs {
                anyhow::bail!("Device flow timed out waiting for authorization");
            }

            match Self::poll_for_token(client_id, device_code, current_interval).await? {
                Some(token) => return Ok(token),
                None => {
                    // Still waiting, continue polling
                    // Increase interval slightly to be nice to GitHub
                    current_interval = (current_interval + 1).min(10);
                }
            }
        }
    }
}

impl SourceAdapter for GithubSource {
    fn name(&self) -> &str {
        "github"
    }

    /// Generate a new GitHub PAT via device flow.
    /// Note: This is typically called after the device flow is already complete,
    /// so the auth_token here is the token we just generated.
    /// For actual PAT generation, use the device flow methods directly.
    async fn generate(
        &self,
        _key_name: &str,
        _auth_token: &str,
        _options: &GenerateOptions,
    ) -> Result<String> {
        // GitHub doesn't have a programmatic way to generate PATs.
        // The device flow IS the generation mechanism.
        // This method is a placeholder for the flow completion.
        anyhow::bail!(
            "GitHub PAT generation uses the device flow. Use 'cred source add github' to authenticate."
        );
    }

    /// Revoke a GitHub token.
    /// Note: GitHub OAuth tokens can be revoked, but PATs cannot be revoked via API.
    async fn revoke(&self, _key_value: &str, _auth_token: &str) -> Result<()> {
        // GitHub doesn't support programmatic PAT revocation
        println!(
            "ℹ️  GitHub tokens must be revoked manually at https://github.com/settings/tokens"
        );
        Ok(())
    }

    /// Validate that the auth token is still valid by checking the user endpoint.
    async fn validate_auth(&self, auth_token: &str) -> Result<bool> {
        let client = Client::new();

        let resp = client
            .get("https://api.github.com/user")
            .header("User-Agent", Self::UA)
            .header("Authorization", format!("Bearer {}", auth_token))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                let user: UserResponse = r.json().await.context("Failed to parse user response")?;
                println!("✓ Authenticated as: {}", user.login);
                Ok(true)
            }
            Ok(r) if r.status().as_u16() == 401 => Ok(false),
            Ok(r) => {
                let status = r.status();
                anyhow::bail!("Unexpected response from GitHub: {}", status);
            }
            Err(e) => {
                anyhow::bail!("Failed to validate GitHub token: {}", e);
            }
        }
    }

    /// List is not directly supported for GitHub tokens.
    async fn list(&self, _auth_token: &str) -> Result<Vec<String>> {
        anyhow::bail!(
            "GitHub does not support listing tokens via API. Visit https://github.com/settings/tokens"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_source_name() {
        let source = GithubSource;
        assert_eq!(source.name(), "github");
    }

    #[tokio::test]
    async fn test_generate_returns_helpful_error() {
        let source = GithubSource;
        let result = source
            .generate("key", "token", &GenerateOptions::default())
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("device flow"));
    }

    #[tokio::test]
    async fn test_list_returns_helpful_error() {
        let source = GithubSource;
        let result = source.list("token").await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("does not support listing")
        );
    }
}
