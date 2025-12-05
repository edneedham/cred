mod cli;
mod config;
mod project;
mod targets;
mod vault;
#[cfg(test)]
mod tests;

use clap::Parser;
use cli::{Cli, Commands, SecretAction, SetTargetArgs};
use anyhow::{Context, Result, bail};
use targets::TargetAdapter;
use rpassword::prompt_password;
use zeroize::Zeroize;

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
            config::ensure_global_config_exists()?;
            project::init()?;
        }
        
        Commands::Target { action } => match action {
             cli::TargetAction::Set(args) => {
                handle_target_set(args)?;
            }
            cli::TargetAction::List => {
                let cfg = config::load()?;
                println!("Configured Targets:");
                for (name, _) in cfg.targets { println!("- {}", name); }
            }
            cli::TargetAction::Revoke { name } => {
                println!("🔌 Attempting to revoke token for target '{}'...", name);
                let global_config = config::load()?;
                if let Some(token) = global_config.targets.get(&name.to_string()) {
                    if let Some(p) = targets::get(name) {
                        // Atomic Revoke
                        if let Err(e) = p.revoke_auth_token(token).await {
                            eprintln!("x Remote revocation failed: {}", e);
                            return Ok(());
                        }
                    }
                    config::remove_target_token(&name.to_string())?;
                } else {
                    println!("Target '{}' was not configured.", name);
                }
            }
        },

        Commands::Secret { action } => {
            let proj = project::Project::find()?;
            let master_key = proj.get_master_key()?;
            let mut vault = vault::Vault::load(&proj.vault_path, master_key)?;

            match action {
                SecretAction::Set { key, value } => {
                    vault.set(&key, &value);
                    vault.save()?;
                    println!("✓ Set {} = *****", key);
                }
                SecretAction::Get { key } => {
                    match vault.get(&key) {
                        Some(val) => println!("{}", val),
                        None => eprintln!("Secret '{}' not found", key),
                    }
                }
                SecretAction::Remove { key } => {
                    if vault.remove(&key).is_some() {
                        vault.save()?;
                        println!("✓ Removed '{}' from local vault.", key);
                    } else {
                        println!("Secret '{}' did not exist locally.", key);
                    }
                }
                SecretAction::List {} => {
                    println!("Vault content:");
                    for (k, _) in vault.list() { println!("  {} = *****", k); }
                }
                SecretAction::Revoke { key, target } => {
                     // 1. Get Source Token
                    let global_config = config::load()?;
                    let source_token = match global_config.targets.get(&target.to_string()) {
                        Some(t) => t,
                        None => { eprintln!("No token for source {}", target); return Ok(()); }
                    };

                    // 2. Get Value for Revocation
                    let secret_value = match vault.get(&key) {
                        Some(v) => v.clone(),
                        None => { eprintln!("Secret '{}' not found locally.", key); return Ok(()); }
                    };

                    // 3. Remote Revoke
                    let source_impl = match targets::get(target) {
                        Some(p) => p,
                        None => { eprintln!("Unknown target {}", target); return Ok(()); }
                    };
                    
                    println!("🔌 Contacting {} to revoke '{}'...", target, key);
                    // Note: This will fail if target doesn't support revoke (like GitHub)
                    if let Err(e) = source_impl.revoke_secret(&key, &secret_value, source_token).await {
                         eprintln!("x Failed to revoke at source: {}", e);
                         return Ok(());
                    }
                    println!("✓ Remote key destroyed.");

                    // 4. Local Remove
                    vault.remove(&key);
                    vault.save()?;
                    println!("✓ Removed from local vault.");
                }
            }
        }
        
        Commands::Push(args) => {
            let target_impl = match targets::get(args.target) {
                Some(p) => p,
                None => { eprintln!("Error: Target '{}' not supported.", args.target); return Ok(()); }
            };

            let global_config = config::load()?;
            let token = global_config.targets.get(&args.target.to_string())
                .ok_or_else(|| anyhow::anyhow!("No token found for {}.", args.target))?;

            let proj = project::Project::find()?;
            let project_config = proj.load_config()?;

            let master_key = proj.get_master_key()?;
            let vault = vault::Vault::load(&proj.vault_path, master_key)?;

            let repo = match args.repo.clone() {
                Some(r) => {
                    if let Some(stored) = project_config.git_repo.clone() {
                        if stored != r {
                            bail!("Refusing to push: provided --repo '{}' does not match recorded repo '{}'.", r, stored);
                        }
                    }
                    Some(r)
                }
                None => project_config.git_repo.clone(),
            };

            if matches!(args.target, targets::Target::Github) && repo.is_none() {
                bail!("GitHub push requires a repository. Provide --repo owner/name or initialize inside a git repo so it can be recorded.");
            }

            let keys_to_push: Vec<String> = if !args.keys.is_empty() {
                args.keys.clone()
            } else {
                vault.list().keys().cloned().collect()
            };

            let mut filtered = std::collections::HashMap::new();
            for k in keys_to_push {
                if let Some(val) = vault.get(&k) {
                    filtered.insert(k, val.clone());
                }
            }

            if filtered.is_empty() {
                println!("No secrets to push.");
                return Ok(());
            }

            println!("📦 Pushing {} secrets...", filtered.len());
            let options = targets::PushOptions { repo };
            if let Err(e) = target_impl.push(&filtered, token, &options).await {
                eprintln!("x Failed to push: {}", e);
            } else {
                println!("✓ Operations complete.");
            }
        }

        Commands::Prune(args) => {
            let target_impl = match targets::get(args.target) {
                Some(p) => p,
                None => { eprintln!("Error: Unknown target"); return Ok(()); }
            };

            let global_config = config::load()?;
            let token = global_config.targets.get(&args.target.to_string())
                .ok_or_else(|| anyhow::anyhow!("No token for {}", args.target))?;

            let keys_to_prune: Vec<String> = if !args.keys.is_empty() {
                args.keys
            } else {
                eprintln!("Error: Specify keys to prune.");
                return Ok(());
            };

            if keys_to_prune.is_empty() { return Ok(()); }

            let proj = project::Project::find()?;
            let project_config = proj.load_config()?;
            let repo = match args.repo.clone() {
                Some(r) => {
                    if let Some(stored) = project_config.git_repo.clone() {
                        if stored != r {
                            bail!("Refusing to prune: provided --repo '{}' does not match recorded repo '{}'.", r, stored);
                        }
                    }
                    Some(r)
                }
                None => project_config.git_repo.clone(),
            };

            if matches!(args.target, targets::Target::Github) && repo.is_none() {
                bail!("GitHub prune requires a repository. Provide --repo owner/name or initialize inside a git repo so it can be recorded.");
            }

            println!("🔌 Deleting from Remote ({}) first...", args.target);
            let options = targets::PushOptions { repo };
            
            // ATOMIC: Remote fail stops local delete
            target_impl.delete(&keys_to_prune, token, &options).await?;

            println!("✓ Remote delete successful. Cleaning local vault...");
            let proj = project::Project::find()?;
            let master_key = proj.get_master_key()?;
            let mut vault = vault::Vault::load(&proj.vault_path, master_key)?;

            for key in keys_to_prune {
                if vault.remove(&key).is_some() {
                    println!("  ✓ Removed local: {}", key);
                }
            }
            vault.save()?;
            println!("✓ Prune complete (Atomic).");
        }
    }
    Ok(())
}

fn read_token_securely(maybe_token: Option<String>) -> Result<String> {
    match maybe_token {
        Some(token) => Ok(token),
        None => {
            let token = prompt_password("Enter target token: ")
                .context("Failed to read token securely")?;

            if token.trim().is_empty() {
                anyhow::bail!("Token cannot be empty");
            }

            Ok(token)
        }
    }
}

fn handle_target_set(args: SetTargetArgs) -> Result<()> {
    let mut token = read_token_securely(args.token)?;

    config::set_target_token(&args.name.to_string(), &token)?;
    println!("Target '{}' authenticated successfully.", args.name);

    token.zeroize();
    Ok(())
}