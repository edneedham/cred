mod cli;
mod config;
mod project;
mod providers;
#[cfg(test)]
mod tests;

use clap::Parser;
use cli::{Cli, Commands};
use anyhow::Result;

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