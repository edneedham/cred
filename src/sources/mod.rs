//! Source registry and adapter trait.
//! Each provider implements `SourceAdapter`, and this module dispatches based on CLI-selected source.
//! Sources are where secrets originate from (e.g., Resend API keys, cloud provider credentials).

pub mod resend;

use anyhow::Result;
use clap::ValueEnum;
use std::fmt;

/// Supported secret sources.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum Source {
    Resend,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Source::Resend => "resend",
        };
        write!(f, "{}", s)
    }
}

#[allow(dead_code)]
/// Options for secret generation.
pub struct GenerateOptions {
    /// Scopes/permissions for the generated credential
    /// For Resend: "full_access" or "sending_access"
    pub scopes: Vec<String>,
    /// Optional expiration in days (not used by Resend)
    pub expires_in_days: Option<u32>,
    /// Optional description for the credential (used as API key name in Resend)
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

/// Result from generating a credential at a source.
#[derive(Debug, Clone)]
pub struct GeneratedCredential {
    /// The secret value (e.g., API key token)
    pub value: String,
    /// The remote ID for this credential (for revocation)
    pub id: Option<String>,
}

#[allow(async_fn_in_trait)] // Async in trait is crate-internal; we accept the bound
/// Common interface every source must implement.
/// Sources are credential providers that can generate, revoke, and list secrets.
pub trait SourceAdapter {
    /// Human-readable source name.
    fn name(&self) -> &str;

    /// Generate a new secret/credential at this source.
    /// Returns the generated credential with its value and remote ID.
    async fn generate(
        &self,
        key_name: &str,
        auth_token: &str,
        options: &GenerateOptions,
    ) -> Result<GeneratedCredential> {
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
    Resend(resend::ResendSource),
}

impl SourceAdapter for SourceWrapper {
    fn name(&self) -> &str {
        match self {
            Self::Resend(s) => s.name(),
        }
    }

    async fn generate(
        &self,
        key_name: &str,
        auth_token: &str,
        options: &GenerateOptions,
    ) -> Result<GeneratedCredential> {
        match self {
            Self::Resend(s) => s.generate(key_name, auth_token, options).await,
        }
    }

    async fn revoke(&self, key_value: &str, auth_token: &str) -> Result<()> {
        match self {
            Self::Resend(s) => s.revoke(key_value, auth_token).await,
        }
    }

    async fn list(&self, auth_token: &str) -> Result<Vec<String>> {
        match self {
            Self::Resend(s) => s.list(auth_token).await,
        }
    }

    async fn validate_auth(&self, auth_token: &str) -> Result<bool> {
        match self {
            Self::Resend(s) => s.validate_auth(auth_token).await,
        }
    }
}

/// Factory function to get a source adapter by name.
pub fn get(name: Source) -> Option<SourceWrapper> {
    match name {
        Source::Resend => Some(SourceWrapper::Resend(resend::ResendSource)),
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
    fn test_factory_returns_resend() {
        let s = get(Source::Resend);
        assert!(s.is_some());
        assert_eq!(s.unwrap().name(), "resend");
    }

    #[test]
    fn test_source_display() {
        assert_eq!(Source::Resend.to_string(), "resend");
    }

    #[test]
    fn test_source_enum_equality() {
        assert_eq!(Source::Resend, Source::Resend);
    }

    #[test]
    fn test_generated_credential_with_id() {
        let cred = GeneratedCredential {
            value: "re_secret_123".to_string(),
            id: Some("abc-def-123".to_string()),
        };
        assert_eq!(cred.value, "re_secret_123");
        assert_eq!(cred.id, Some("abc-def-123".to_string()));
    }

    #[test]
    fn test_generated_credential_without_id() {
        let cred = GeneratedCredential {
            value: "manual_token".to_string(),
            id: None,
        };
        assert_eq!(cred.value, "manual_token");
        assert!(cred.id.is_none());
    }

    #[test]
    fn test_generated_credential_clone() {
        let cred = GeneratedCredential {
            value: "secret".to_string(),
            id: Some("id".to_string()),
        };
        let cloned = cred.clone();
        assert_eq!(cred.value, cloned.value);
        assert_eq!(cred.id, cloned.id);
    }

    #[test]
    fn test_generate_options_default() {
        let opts = GenerateOptions::default();
        assert!(opts.scopes.is_empty());
        assert!(opts.expires_in_days.is_none());
        assert!(opts.description.is_none());
    }

    #[test]
    fn test_generate_options_with_values() {
        let opts = GenerateOptions {
            scopes: vec!["sending_access".to_string()],
            expires_in_days: Some(30),
            description: Some("Test key".to_string()),
        };
        assert_eq!(opts.scopes, vec!["sending_access"]);
        assert_eq!(opts.expires_in_days, Some(30));
        assert_eq!(opts.description, Some("Test key".to_string()));
    }

    #[tokio::test]
    async fn test_trait_defaults_prevent_invalid_usage() {
        let s = MockSource;

        let gen_result: Result<GeneratedCredential> = s
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

    #[test]
    fn test_source_wrapper_dispatch_name() {
        let wrapper = SourceWrapper::Resend(resend::ResendSource);
        assert_eq!(wrapper.name(), "resend");
    }
}
