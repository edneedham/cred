use super::Provider;
use std::collections::HashMap;
use anyhow::Result;

pub struct Github;

impl Provider for Github {
    fn name(&self) -> &str {
        "github"
    }

    // Native async fn!
    async fn push(&self, secrets: &HashMap<String, String>, auth_token: &str) -> Result<()> {
        println!("🚀 Pushing {} secrets to GitHub...", secrets.len());
        println!("🔑 Using Auth Token: {}...", &auth_token[0..3.min(auth_token.len())]);
        
        Ok(())
    }
}