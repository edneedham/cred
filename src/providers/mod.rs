mod github;
// mod vercel; // Future...

use std::collections::HashMap;
use anyhow::Result;

// 1. Native Rust 2024 Trait (No macro needed!)
pub trait Provider {
    fn name(&self) -> &str;
    
    // Native async allows us to use `impl Future` implicitly
    async fn push(&self, secrets: &HashMap<String, String>, auth_token: &str) -> Result<()>;
}

// 2. The Enum that holds all variants
pub enum ProviderWrapper {
    Github(github::Github),
    // Vercel(vercel::Vercel),
}

// 3. Implement the Trait for the Enum
// This simply delegates the call to the inner struct.
impl Provider for ProviderWrapper {
    fn name(&self) -> &str {
        match self {
            Self::Github(p) => p.name(),
            // Self::Vercel(p) => p.name(),
        }
    }

    async fn push(&self, secrets: &HashMap<String, String>, auth_token: &str) -> Result<()> {
        match self {
            Self::Github(p) => p.push(secrets, auth_token).await,
            // Self::Vercel(p) => p.push(secrets, auth_token).await,
        }
    }
}

// 4. Update Factory to return the Enum (not Box<dyn>)
pub fn get(name: &str) -> Option<ProviderWrapper> {
    match name {
        "github" => Some(ProviderWrapper::Github(github::Github)),
        // "vercel" => Some(ProviderWrapper::Vercel(vercel::Vercel)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Import everything from the parent module

    #[test]
    fn test_factory_returns_correct_provider() {
        // Test 1: Valid provider
        let provider = get("github");
        assert!(provider.is_some(), "Github provider should exist");
        assert_eq!(provider.unwrap().name(), "github");

        // Test 2: Invalid provider
        let missing = get("fake_provider");
        assert!(missing.is_none(), "Fake provider should return None");
    }

    #[tokio::test] // Requires tokio runtime
    async fn test_provider_dispatch_works() {
        // 1. Get the wrapper
        let provider = get("github").expect("Should get github");

        // 2. Create dummy data
        let secrets = HashMap::new();
        let token = "dummy_token";

        // 3. Call push (This tests that ProviderWrapper::push calls Github::push)
        let result = provider.push(&secrets, token).await;

        // 4. Assert success
        assert!(result.is_ok(), "Push should succeed (stub implementation)");
    }
}