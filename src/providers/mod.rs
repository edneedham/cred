mod github;

use std::collections::HashMap;
use anyhow::Result;

pub struct PushOptions {
    pub env: Option<String>,
}

pub trait Provider {
    fn name(&self) -> &str;
    
    // --- DESTINATION CAPABILITIES ---
    
    async fn push(&self, _secrets: &HashMap<String, String>, _auth_token: &str, _options: &PushOptions) -> Result<()> {
        anyhow::bail!("Provider '{}' is not a hosting platform; you cannot push secrets to it.", self.name());
    }

    async fn delete(&self, _keys: &[String], _auth_token: &str, _options: &PushOptions) -> Result<()> {
        anyhow::bail!("Provider '{}' is not a hosting platform; you cannot prune secrets from it.", self.name());
    }
    
    // --- SOURCE CAPABILITIES ---

    #[allow(dead_code)]
    async fn generate(&self, _env: &str, _auth_token: &str) -> Result<(String, String)> {
        anyhow::bail!("Provider '{}' does not support API key generation.", self.name());
    }

    async fn revoke_secret(&self, _key_name: &str, _key_value: &str, _auth_token: &str) -> Result<()> {
        anyhow::bail!("Provider '{}' does not support API key revocation.", self.name());
    }

    // --- AUTHENTICATION ---
    
    async fn revoke_auth_token(&self, _auth_token: &str) -> Result<()> { 
        Ok(()) // Default to ok (allows local logout)
    }
}

pub enum ProviderWrapper {
    Github(github::Github),
}

impl Provider for ProviderWrapper {
    fn name(&self) -> &str {
        match self {
            Self::Github(p) => p.name(),
        }
    }

    async fn push(&self, secrets: &HashMap<String, String>, auth_token: &str, options: &PushOptions) -> Result<()> {
        match self {
            Self::Github(p) => p.push(secrets, auth_token, options).await,
        }
    }

    async fn delete(&self, keys: &[String], auth_token: &str, options: &PushOptions) -> Result<()> {
        match self {
            Self::Github(p) => p.delete(keys, auth_token, options).await,
        }
    }

    async fn generate(&self, env: &str, auth_token: &str) -> Result<(String, String)> {
        match self {
            Self::Github(p) => p.generate(env, auth_token).await,
        }
    }

    async fn revoke_secret(&self, key_name: &str, key_value: &str, auth_token: &str) -> Result<()> {
        match self {
            Self::Github(p) => p.revoke_secret(key_name, key_value, auth_token).await,
        }
    }

    async fn revoke_auth_token(&self, auth_token: &str) -> Result<()> {
        match self {
            Self::Github(p) => p.revoke_auth_token(auth_token).await,
        }
    }
}

pub fn get(name: &str) -> Option<ProviderWrapper> {
    match name {
        "github" => Some(ProviderWrapper::Github(github::Github)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock Provider to test Trait Defaults
    struct MockSourceProvider;
    impl Provider for MockSourceProvider {
        fn name(&self) -> &str { "mock_source" }
        // We do NOT implement push/delete (relying on defaults)
        // We only implement generate
        async fn generate(&self, _env: &str, _token: &str) -> Result<(String, String)> {
            Ok(("KEY".to_string(), "VAL".to_string()))
        }
    }

    #[test]
    fn test_factory_returns_github() {
        let p = get("github");
        assert!(p.is_some());
        assert_eq!(p.unwrap().name(), "github");
    }

    #[tokio::test]
    async fn test_trait_defaults_prevent_invalid_usage() {
        let p = MockSourceProvider;
        let secrets = HashMap::new();
        let options = PushOptions { env: None };

        // 1. Should fail to Push (Defaults to error)
        let push_result = p.push(&secrets, "token", &options).await;
        assert!(push_result.is_err());
        assert!(push_result.unwrap_err().to_string().contains("not a hosting platform"));

        // 2. Should fail to Delete (Defaults to error)
        let delete_result = p.delete(&[], "token", &options).await;
        assert!(delete_result.is_err());
        assert!(delete_result.unwrap_err().to_string().contains("not a hosting platform"));
    }

    #[tokio::test]
    async fn test_provider_wrapper_dispatch() {
        // This tests that the Enum Wrapper correctly routes calls
        let p = get("github").unwrap();
        
        // GitHub supports Push
        let secrets = HashMap::new();
        let options = PushOptions { env: None };
        
        // We expect an error here (network fail), but NOT "Method not supported"
        let result = p.push(&secrets, "token", &options).await;
        
        if let Err(e) = result {
            let msg = e.to_string();
            // It might fail on network or repo check, but it should NOT say "not a hosting platform"
            assert!(!msg.contains("not a hosting platform"));
        }
    }
}