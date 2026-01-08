//! Fly.io target adapter for cred.
//! Pushes secrets to Fly.io apps using their GraphQL API.

use super::{PushOptions, TargetAdapter};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

/// Adapter that pushes secrets to Fly.io apps.
pub struct Fly;

/// GraphQL request wrapper.
#[derive(Serialize)]
struct GraphQLRequest<T: Serialize> {
    query: String,
    variables: T,
}

/// Variables for SetSecrets mutation.
#[derive(Serialize)]
struct SetSecretsVars {
    input: SetSecretsInput,
}

#[derive(Serialize)]
struct SetSecretsInput {
    #[serde(rename = "appId")]
    app_id: String,
    secrets: Vec<SecretInput>,
    #[serde(rename = "replaceAll")]
    replace_all: bool,
}

#[derive(Serialize)]
struct SecretInput {
    key: String,
    value: String,
}

/// Variables for UnsetSecrets mutation.
#[derive(Serialize)]
struct UnsetSecretsVars {
    input: UnsetSecretsInput,
}

#[derive(Serialize)]
struct UnsetSecretsInput {
    #[serde(rename = "appId")]
    app_id: String,
    keys: Vec<String>,
}

/// GraphQL response wrapper.
#[derive(Deserialize, Debug)]
struct GraphQLResponse<T> {
    data: Option<T>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Deserialize, Debug)]
struct GraphQLError {
    message: String,
}

/// Response data for SetSecrets mutation.
#[derive(Deserialize, Debug)]
struct SetSecretsData {
    #[serde(rename = "setSecrets")]
    #[allow(dead_code)] // Parsed from API response for type safety
    set_secrets: Option<SetSecretsResult>,
}

#[derive(Deserialize, Debug)]
struct SetSecretsResult {
    #[allow(dead_code)] // Parsed from API response for type safety
    app: AppInfo,
}

#[derive(Deserialize, Debug)]
struct AppInfo {
    #[allow(dead_code)] // Parsed from API response for type safety
    name: String,
}

/// Response data for UnsetSecrets mutation.
#[derive(Deserialize, Debug)]
struct UnsetSecretsData {
    #[serde(rename = "unsetSecrets")]
    #[allow(dead_code)] // Parsed from API response for type safety
    unset_secrets: Option<UnsetSecretsResult>,
}

#[derive(Deserialize, Debug)]
struct UnsetSecretsResult {
    #[allow(dead_code)] // Parsed from API response for type safety
    app: AppInfo,
}

/// Minimal fly.toml structure for app name detection.
#[derive(Deserialize)]
struct FlyToml {
    app: Option<String>,
}

impl Fly {
    const API_URL: &'static str = "https://api.fly.io/graphql";
    const UA: &'static str = "cred-cli";

    /// SetSecrets GraphQL mutation.
    const SET_SECRETS_MUTATION: &'static str = r#"
        mutation SetSecrets($input: SetSecretsInput!) {
            setSecrets(input: $input) {
                app {
                    name
                }
            }
        }
    "#;

    /// UnsetSecrets GraphQL mutation.
    const UNSET_SECRETS_MUTATION: &'static str = r#"
        mutation UnsetSecrets($input: UnsetSecretsInput!) {
            unsetSecrets(input: $input) {
                app {
                    name
                }
            }
        }
    "#;

    /// Try to detect app name from fly.toml.
    fn detect_app_name(&self) -> Option<String> {
        if let Ok(content) = fs::read_to_string("fly.toml") {
            if let Ok(parsed) = toml::from_str::<FlyToml>(&content) {
                return parsed.app;
            }
        }
        None
    }

    /// Resolve app name from options or auto-detection.
    fn resolve_app(&self, options: &PushOptions) -> Result<String> {
        if let Some(ref app) = options.app {
            return Ok(app.clone());
        }

        self.detect_app_name().ok_or_else(|| {
            anyhow::anyhow!(
                "Could not detect Fly.io app. Create fly.toml with `fly launch` or specify --app <name>"
            )
        })
    }

    /// Execute a GraphQL request.
    async fn graphql<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        client: &Client,
        token: &str,
        query: &str,
        variables: T,
    ) -> Result<R> {
        let request = GraphQLRequest {
            query: query.to_string(),
            variables,
        };

        let resp = client
            .post(Self::API_URL)
            .header("User-Agent", Self::UA)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send request to Fly.io API")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Fly.io API error ({}): {}", status, body);
        }

        let gql_resp: GraphQLResponse<R> = resp
            .json()
            .await
            .context("Failed to parse Fly.io API response")?;

        if let Some(errors) = gql_resp.errors {
            let messages: Vec<_> = errors.iter().map(|e| e.message.as_str()).collect();
            anyhow::bail!("Fly.io GraphQL errors: {}", messages.join(", "));
        }

        gql_resp
            .data
            .ok_or_else(|| anyhow::anyhow!("No data in Fly.io response"))
    }
}

impl TargetAdapter for Fly {
    fn name(&self) -> &str {
        "fly"
    }

    /// Pushes secrets to a Fly.io app.
    async fn push(
        &self,
        secrets: &HashMap<String, String>,
        auth_token: &str,
        options: &PushOptions,
    ) -> Result<()> {
        let app_name = self.resolve_app(options)?;
        let client = Client::new();

        println!("🚀 Pushing to Fly.io [app: {}]", app_name);

        let secret_inputs: Vec<SecretInput> = secrets
            .iter()
            .map(|(key, value)| SecretInput {
                key: key.clone(),
                value: value.clone(),
            })
            .collect();

        let variables = SetSecretsVars {
            input: SetSecretsInput {
                app_id: app_name.clone(),
                secrets: secret_inputs,
                replace_all: false, // Only set/update specified secrets, don't remove others
            },
        };

        let _result: SetSecretsData = self
            .graphql(&client, auth_token, Self::SET_SECRETS_MUTATION, variables)
            .await?;

        for key in secrets.keys() {
            println!("  ✓ Set: {}", key);
        }

        println!("\nℹ️  Secrets set. Run `fly deploy` or `fly secrets deploy` to apply changes.");

        Ok(())
    }

    /// Deletes secrets from a Fly.io app.
    async fn delete(&self, keys: &[String], auth_token: &str, options: &PushOptions) -> Result<()> {
        let app_name = self.resolve_app(options)?;
        let client = Client::new();

        println!(
            "🗑️  Pruning {} secrets from Fly.io [app: {}]",
            keys.len(),
            app_name
        );

        let variables = UnsetSecretsVars {
            input: UnsetSecretsInput {
                app_id: app_name.clone(),
                keys: keys.to_vec(),
            },
        };

        let _result: UnsetSecretsData = self
            .graphql(&client, auth_token, Self::UNSET_SECRETS_MUTATION, variables)
            .await?;

        for key in keys {
            println!("  ✓ Deleted: {}", key);
        }

        println!(
            "\nℹ️  Secrets removed. Run `fly deploy` or `fly secrets deploy` to apply changes."
        );

        Ok(())
    }

    /// Fly.io tokens cannot be revoked via API; we only inform the user.
    async fn revoke_auth_token(&self, _auth_token: &str) -> Result<()> {
        println!("ℹ️  Fly.io tokens can be revoked at fly.io/user/personal_access_tokens");
        Ok(())
    }
}
