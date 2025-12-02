mod github;

use std::collections::HashMap;
use anyhow::Result;

pub struct PushOptions {
    pub repo: Option<String>,
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