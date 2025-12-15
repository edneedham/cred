//! Resend source adapter for cred.
//! Uses Bearer token authentication against the Resend API.
//! Supports programmatic API key generation, listing, and deletion.

use super::{GenerateOptions, GeneratedCredential, SourceAdapter};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Resend source adapter for generating and managing API keys.
pub struct ResendSource;

const USER_AGENT: &str = "cred-cli";
const RESEND_API_BASE: &str = "https://api.resend.com";

/// Request body for creating an API key.
#[derive(Serialize)]
struct CreateApiKeyRequest {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    permission: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_id: Option<String>,
}

/// Response from creating an API key.
#[derive(Deserialize, Debug)]
struct CreateApiKeyResponse {
    id: String,
    token: String,
}

/// A single API key in the list response.
#[derive(Deserialize, Debug)]
struct ApiKeyInfo {
    id: String,
    name: String,
    #[allow(dead_code)]
    created_at: String,
}

/// Response from listing API keys.
#[derive(Deserialize, Debug)]
struct ListApiKeysResponse {
    data: Vec<ApiKeyInfo>,
}

impl SourceAdapter for ResendSource {
    fn name(&self) -> &str {
        "resend"
    }

    /// Generate a new Resend API key.
    /// The key is only returned once, so we store it immediately in the vault.
    ///
    /// Options:
    /// - scopes[0]: permission level - "full_access" or "sending_access" (default: full_access)
    /// - description: used as the API key name in Resend
    async fn generate(
        &self,
        key_name: &str,
        auth_token: &str,
        options: &GenerateOptions,
    ) -> Result<GeneratedCredential> {
        let client = Client::new();

        // Use description as the API key name, or fall back to the vault key name
        let api_key_name = options
            .description
            .clone()
            .unwrap_or_else(|| key_name.to_string());

        // Permission from scopes (first scope determines permission level)
        let permission = options.scopes.first().cloned();

        let request_body = CreateApiKeyRequest {
            name: api_key_name,
            permission,
            domain_id: None, // Could be exposed via options in the future
        };

        let resp = client
            .post(format!("{}/api-keys", RESEND_API_BASE))
            .header("User-Agent", USER_AGENT)
            .header("Authorization", format!("Bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .context("Failed to connect to Resend API")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Resend API error ({}): {}", status, body);
        }

        let result: CreateApiKeyResponse = resp
            .json()
            .await
            .context("Failed to parse Resend API response")?;

        // Return both the token (secret value) and the ID (for revocation)
        Ok(GeneratedCredential {
            value: result.token,
            id: Some(result.id),
        })
    }

    /// Delete a Resend API key by its ID.
    /// Note: key_value here should be the API key ID, not the token itself.
    async fn revoke(&self, key_id: &str, auth_token: &str) -> Result<()> {
        let client = Client::new();

        let resp = client
            .delete(format!("{}/api-keys/{}", RESEND_API_BASE, key_id))
            .header("User-Agent", USER_AGENT)
            .header("Authorization", format!("Bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .send()
            .await
            .context("Failed to connect to Resend API")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Resend API error ({}): {}", status, body);
        }

        Ok(())
    }

    /// List all API keys for the authenticated account.
    /// Returns key names (not the actual tokens, which aren't retrievable).
    async fn list(&self, auth_token: &str) -> Result<Vec<String>> {
        let client = Client::new();

        let resp = client
            .get(format!("{}/api-keys", RESEND_API_BASE))
            .header("User-Agent", USER_AGENT)
            .header("Authorization", format!("Bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .send()
            .await
            .context("Failed to connect to Resend API")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Resend API error ({}): {}", status, body);
        }

        let result: ListApiKeysResponse = resp
            .json()
            .await
            .context("Failed to parse Resend API response")?;

        // Return formatted list with id and name for identification
        Ok(result
            .data
            .into_iter()
            .map(|k| format!("{} ({})", k.name, k.id))
            .collect())
    }

    /// Validate the auth token by attempting to list API keys.
    async fn validate_auth(&self, auth_token: &str) -> Result<bool> {
        let client = Client::new();

        let resp = client
            .get(format!("{}/api-keys", RESEND_API_BASE))
            .header("User-Agent", USER_AGENT)
            .header("Authorization", format!("Bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                println!("✓ Resend authentication valid");
                Ok(true)
            }
            Ok(r) if r.status().as_u16() == 401 => Ok(false),
            Ok(r) => {
                let status = r.status();
                anyhow::bail!("Unexpected response from Resend: {}", status);
            }
            Err(e) => {
                anyhow::bail!("Failed to validate Resend token: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resend_source_name() {
        let source = ResendSource;
        assert_eq!(source.name(), "resend");
    }

    #[test]
    fn test_create_request_serialization() {
        let req = CreateApiKeyRequest {
            name: "Production".to_string(),
            permission: Some("sending_access".to_string()),
            domain_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"name\":\"Production\""));
        assert!(json.contains("\"permission\":\"sending_access\""));
        assert!(!json.contains("domain_id")); // Should be skipped when None
    }

    #[test]
    fn test_create_request_minimal() {
        let req = CreateApiKeyRequest {
            name: "Test".to_string(),
            permission: None,
            domain_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"name":"Test"}"#);
    }
}
