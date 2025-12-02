mod cli;
mod config;
mod project;
mod providers;
#[cfg(test)]
mod tests;

use clap::Parser;
use cli::{Cli, Commands};
use anyhow::Result;
use providers::Provider;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("Error: {:?}", e);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Init => {
            // 1. Ensure global config exists
            let global_path = config::ensure_global_config_exists()?;
            println!("Global config verified at: {}", global_path.display());

            // 2. Initialize local project
            project::init()?;
        }
        Commands::Provider { action } => match action {
            cli::ProviderAction::Set { name, token } => {
                config::set_provider_token(&name, &token)?;
                println!("✓ Auth token set for provider '{}'", name);
            }
            cli::ProviderAction::List => {
                let cfg = config::load()?;
                if cfg.providers.is_empty() {
                    println!("No providers configured.");
                } else {
                    println!("Configured Providers:");
                    for (name, _) in cfg.providers {
                        println!("- {}", name);
                    }
                }
            }
        }
        Commands::Push { provider, repo } => {
            // 1. Resolve the provider from the string
            let provider_impl = match providers::get(&provider) {
                Some(p) => p,
                None => {
                    eprintln!("Error: Provider '{}' not supported.", provider);
                    return Ok(());
                }
            };
            
            println!("Targeting provider: {}", provider_impl.name());
            if let Some(r) = repo {
                println!("Targeting repo: {}", r);
            }

            // 2. Load the Auth Token from Global Config
            let global_config = config::load()?;
            let token = global_config.providers.get(&provider)
                .ok_or_else(|| anyhow::anyhow!("No token found for {}. Run 'cred provider set {} <TOKEN>'", provider, provider))?;

            // 3. Load Secrets (Stub for now - we will implement vault loading next)
            let dummy_secrets = std::collections::HashMap::new();

            // 4. Perform the Push
            provider_impl.push(&dummy_secrets, token).await?;
            println!("✓ Push complete!");
        }
        Commands::Secret { action } => {
            // Example usage of recursive find
            let proj = project::Project::find()?;
            println!("Found project root at: {}", proj.root.display());
            
            // Handle secret actions here...
            println!("Secret action: {:?}", action); // Needs Debug on SecretAction
        }
        _ => {
            println!("Command not implemented yet.");
        }
    }

    Ok(())
}