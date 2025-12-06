#[cfg(feature = "github")]
mod github;

#[cfg(not(feature = "github"))]
compile_error!("No targets enabled. Enable feature \"github\".");

use std::collections::HashMap;
use anyhow::Result;
use clap::ValueEnum;
use std::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub(crate) enum Target {
    #[cfg(feature = "github")]
    Github,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            #[cfg(feature = "github")]
            Target::Github => "github",
        };
        write!(f, "{}", s)
    }
}

pub struct PushOptions {
    pub repo: Option<String>,
}

pub trait TargetAdapter {
    fn name(&self) -> &str;
    
    async fn push(&self, _secrets: &HashMap<String, String>, _auth_token: &str, _options: &PushOptions) -> Result<()> {
        anyhow::bail!("Target '{}' is not a hosting platform; you cannot push secrets to it.", self.name());
    }

    async fn delete(&self, _keys: &[String], _auth_token: &str, _options: &PushOptions) -> Result<()> {
        anyhow::bail!("Target '{}' is not a hosting platform; you cannot prune secrets from it.", self.name());
    }
    
    #[allow(dead_code)]
    async fn generate(&self, _env: &str, _auth_token: &str) -> Result<(String, String)> {
        anyhow::bail!("Target '{}' does not support API key generation.", self.name());
    }

    async fn revoke_secret(&self, _key_name: &str, _key_value: &str, _auth_token: &str) -> Result<()> {
        anyhow::bail!("Target '{}' does not support API key revocation.", self.name());
    }

    async fn revoke_auth_token(&self, _auth_token: &str) -> Result<()> { 
        Ok(()) // Default to ok (allows local logout)
    }
}

pub enum TargetWrapper {
    #[cfg(feature = "github")]
    Github(github::Github),
}

impl TargetAdapter for TargetWrapper {
    fn name(&self) -> &str {
        match self {
            #[cfg(feature = "github")]
            Self::Github(p) => p.name(),
        }
    }

    async fn push(&self, secrets: &HashMap<String, String>, auth_token: &str, options: &PushOptions) -> Result<()> {
        match self {
            #[cfg(feature = "github")]
            Self::Github(p) => p.push(secrets, auth_token, options).await,
        }
    }

    async fn delete(&self, keys: &[String], auth_token: &str, options: &PushOptions) -> Result<()> {
        match self {
            #[cfg(feature = "github")]
            Self::Github(p) => p.delete(keys, auth_token, options).await,
        }
    }

    async fn generate(&self, env: &str, auth_token: &str) -> Result<(String, String)> {
        match self {
            #[cfg(feature = "github")]
            Self::Github(p) => p.generate(env, auth_token).await,
        }
    }

    async fn revoke_secret(&self, key_name: &str, key_value: &str, auth_token: &str) -> Result<()> {
        match self {
            #[cfg(feature = "github")]
            Self::Github(p) => p.revoke_secret(key_name, key_value, auth_token).await,
        }
    }

    async fn revoke_auth_token(&self, auth_token: &str) -> Result<()> {
        match self {
            #[cfg(feature = "github")]
            Self::Github(p) => p.revoke_auth_token(auth_token).await,
        }
    }
}

pub(crate) fn get(name: Target) -> Option<TargetWrapper> {
    match name {
        #[cfg(feature = "github")]
        Target::Github => Some(TargetWrapper::Github(github::Github)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTarget;
    impl TargetAdapter for MockTarget {
        fn name(&self) -> &str { "mock_target" }
        async fn generate(&self, _env: &str, _token: &str) -> Result<(String, String)> {
            Ok(("KEY".to_string(), "VAL".to_string()))
        }
    }

    #[test]
    fn test_factory_returns_github() {
        let p = get(Target::Github);
        assert!(p.is_some());
        assert_eq!(p.unwrap().name(), "github");
    }

    #[tokio::test]
    async fn test_trait_defaults_prevent_invalid_usage() {
        let p = MockTarget;
        let secrets = HashMap::new();
        let options = PushOptions { repo: None };

        let push_result = p.push(&secrets, "token", &options).await;
        assert!(push_result.is_err());
        assert!(push_result.unwrap_err().to_string().contains("not a hosting platform"));

        let delete_result = p.delete(&[], "token", &options).await;
        assert!(delete_result.is_err());
        assert!(delete_result.unwrap_err().to_string().contains("not a hosting platform"));
    }

    #[tokio::test]
    async fn test_target_wrapper_dispatch() {
        let p = get(Target::Github).unwrap();
        
        let secrets = HashMap::new();
        let options = PushOptions { repo: None };
        
        let result = p.push(&secrets, "token", &options).await;
        
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(!msg.contains("not a hosting platform"));
        }
    }
}
