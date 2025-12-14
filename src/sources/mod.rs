//! Source registry and adapter trait.
//! Each provider implements `SourceAdapter`, and this module dispatches based on CLI-selected source.
//! Sources are where secrets originate from (e.g., GitHub PATs, API keys from services).

#[cfg(feature = "github")]
pub mod github;

use anyhow::Result;
use clap::ValueEnum;
use std::fmt;

/// Supported secret sources (feature-gated).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum Source {
    #[cfg(feature = "github")]
    Github,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            #[cfg(feature = "github")]
            Source::Github => "github",
        };
        write!(f, "{}", s)
    }
}

/// Options for secret generation.
pub struct GenerateOptions {
    /// Scopes/permissions for the generated credential
    pub scopes: Vec<String>,
    /// Optional expiration in days
    pub expires_in_days: Option<u32>,
    /// Optional description for the credential
    pub description: Option<String>,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self {
            scopes: Vec::new(),
            expires_in_days: None,
            description: None,
        }
    }
}

#[allow(async_fn_in_trait)] // Async in trait is crate-internal; we accept the bound
/// Common interface every source must implement.
/// Sources are credential providers that can generate, revoke, and list secrets.
pub trait SourceAdapter {
    /// Human-readable source name.
    fn name(&self) -> &str;

    /// Generate a new secret/credential at this source.
    /// Returns the generated secret value to be stored in the vault.
    async fn generate(
        &self,
        key_name: &str,
        auth_token: &str,
        options: &GenerateOptions,
    ) -> Result<String> {
        let _ = (key_name, auth_token, options);
        anyhow::bail!(
            "Source '{}' does not support credential generation.",
            self.name()
        );
    }

    /// Revoke/delete a secret at the source.
    async fn revoke(&self, key_value: &str, auth_token: &str) -> Result<()> {
        let _ = (key_value, auth_token);
        anyhow::bail!(
            "Source '{}' does not support credential revocation.",
            self.name()
        );
    }

    /// List existing secrets/credentials at this source.
    /// Returns a list of key names/identifiers.
    async fn list(&self, auth_token: &str) -> Result<Vec<String>> {
        let _ = auth_token;
        anyhow::bail!(
            "Source '{}' does not support listing credentials.",
            self.name()
        );
    }

    /// Validate that the auth token is still valid.
    async fn validate_auth(&self, auth_token: &str) -> Result<bool> {
        let _ = auth_token;
        // Default: assume valid if no validation is implemented
        Ok(true)
    }
}

/// Concrete wrapper to erase source-specific types while dispatching calls.
pub enum SourceWrapper {
    #[cfg(feature = "github")]
    Github(github::GithubSource),
}

impl SourceAdapter for SourceWrapper {
    fn name(&self) -> &str {
        match self {
            #[cfg(feature = "github")]
            Self::Github(s) => s.name(),
        }
    }

    async fn generate(
        &self,
        key_name: &str,
        auth_token: &str,
        options: &GenerateOptions,
    ) -> Result<String> {
        match self {
            #[cfg(feature = "github")]
            Self::Github(s) => s.generate(key_name, auth_token, options).await,
        }
    }

    async fn revoke(&self, key_value: &str, auth_token: &str) -> Result<()> {
        match self {
            #[cfg(feature = "github")]
            Self::Github(s) => s.revoke(key_value, auth_token).await,
        }
    }

    async fn list(&self, auth_token: &str) -> Result<Vec<String>> {
        match self {
            #[cfg(feature = "github")]
            Self::Github(s) => s.list(auth_token).await,
        }
    }

    async fn validate_auth(&self, auth_token: &str) -> Result<bool> {
        match self {
            #[cfg(feature = "github")]
            Self::Github(s) => s.validate_auth(auth_token).await,
        }
    }
}

/// Factory function to get a source adapter by name.
pub fn get(name: Source) -> Option<SourceWrapper> {
    match name {
        #[cfg(feature = "github")]
        Source::Github => Some(SourceWrapper::Github(github::GithubSource)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSource;
    impl SourceAdapter for MockSource {
        fn name(&self) -> &str {
            "mock_source"
        }
    }

    #[test]
    fn test_factory_returns_github() {
        let s = get(Source::Github);
        assert!(s.is_some());
        assert_eq!(s.unwrap().name(), "github");
    }

    #[tokio::test]
    async fn test_trait_defaults_prevent_invalid_usage() {
        let s = MockSource;

        let gen_result = s
            .generate("key", "token", &GenerateOptions::default())
            .await;
        assert!(gen_result.is_err());
        assert!(
            gen_result
                .unwrap_err()
                .to_string()
                .contains("does not support credential generation")
        );

        let revoke_result = s.revoke("value", "token").await;
        assert!(revoke_result.is_err());
        assert!(
            revoke_result
                .unwrap_err()
                .to_string()
                .contains("does not support credential revocation")
        );

        let list_result = s.list("token").await;
        assert!(list_result.is_err());
        assert!(
            list_result
                .unwrap_err()
                .to_string()
                .contains("does not support listing")
        );
    }

    #[tokio::test]
    async fn test_validate_auth_default_returns_true() {
        let s = MockSource;
        assert!(s.validate_auth("token").await.unwrap());
    }
}
