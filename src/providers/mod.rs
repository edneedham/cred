mod github;

use std::collections::HashMap;
use anyhow::Result;

pub struct PushOptions {
    pub repo: Option<String>,
    pub env: Option<String>,
}

pub trait Provider {
    fn name(&self) -> &str;
    async fn push(
        &self, 
        secrets: &HashMap<String, String>, 
        auth_token: &str, 
        options: &PushOptions
    ) -> Result<()>;
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

    #[test]
    fn test_factory_returns_correct_provider() {
        let provider = get("github");
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "github");
        
        let missing = get("unknown");
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_provider_dispatch_works() {
        // 1. Get Provider
        let provider = get("github").expect("Should get github");

        // 2. Setup Dummy Data
        let secrets = HashMap::from([
            ("KEY".to_string(), "VALUE".to_string())
        ]);
        let token = "dummy_token";
        
        // 3. Setup Options (New Requirement)
        let options = PushOptions { 
            repo: Some("user/repo".into()), 
            env: Some("production".into()) 
        };

        // 4. Test Push
        // This validates that the Enum Wrapper correctly forwards arguments
        // to the inner Github struct implementation.
        let result = provider.push(&secrets, token, &options).await;
        
        assert!(result.is_ok());
    }
}