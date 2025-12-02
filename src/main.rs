mod cli;
mod config;
mod project;
mod providers;
mod vault;

use clap::Parser;
use cli::{Cli, Commands, SecretAction};
use anyhow::Result;
use std::collections::HashSet;
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
            config::ensure_global_config_exists()?;
            project::init()?;
        }
        
        Commands::Provider { action } => match action {
             cli::ProviderAction::Set { name, token } => {
                config::set_provider_token(&name, &token)?;
                println!("✓ Auth token set for provider '{}'", name);
            }
            cli::ProviderAction::List => {
                let cfg = config::load()?;
                println!("Configured Providers:");
                for (name, _) in cfg.providers {
                    println!("- {}", name);
                }
            }
        },

        Commands::Secret { action } => {
            let proj = project::Project::find()?;
            let mut vault = vault::Vault::load(&proj.vault_path)?;

            match action {
                SecretAction::Set { key, value, env, scope } => {
                    vault.set(&env, &key, &value);
                    vault.save()?;
                    println!("✓ Set {} = ***** in [{}]", key, env);
                    
                    if !scope.is_empty() {
                        proj.add_key_to_scopes(&scope, &key)?;
                    }
                }
                SecretAction::Get { key, env } => {
                    match vault.get(&env, &key) {
                        Some(val) => println!("{}", val),
                        None => eprintln!("Secret '{}' not found in [{}]", key, env),
                    }
                }
                SecretAction::Remove { key, env } => {
                    if vault.remove(&env, &key).is_some() {
                        vault.save()?;
                        println!("✓ Removed secret '{}' from [{}]", key, env);
                    } else {
                        println!("Secret '{}' did not exist in [{}]", key, env);
                    }
                }
                SecretAction::List { env } => {
                    if let Some(e) = env {
                        println!("Secrets for [{}]:", e);
                        if let Some(map) = vault.list(&e) {
                            for (k, _) in map { println!("  {} = *****", k); }
                        } else { println!("  (empty)"); }
                    } else {
                        println!("Vault content:");
                        for (env_name, secrets) in vault.list_all() {
                            println!("[{}]", env_name);
                            for (k, _) in secrets { println!("  {} = *****", k); }
                        }
                    }
                }
                SecretAction::Generate { .. } => {
                    println!("Generate not implemented yet.");
                }
            }
        }
        
        Commands::Push { provider, repo, env, keys, scope } => {
            let provider_impl = match providers::get(&provider) {
                Some(p) => p,
                None => {
                    eprintln!("Error: Provider '{}' not supported.", provider);
                    return Ok(());
                }
            };

            let global_config = config::load()?;
            let token = global_config.providers.get(&provider)
                .ok_or_else(|| anyhow::anyhow!("No token found for {}.", provider))?;

            let proj = project::Project::find()?;
            let project_config = proj.load_config()?;
            let vault = vault::Vault::load(&proj.vault_path)?;

            // Environments to push logic
            let environments_to_push: Vec<String> = if let Some(e) = env {
                vec![e]
            } else {
                vault.list_all().keys().cloned().collect()
            };

            if environments_to_push.is_empty() {
                println!("No populated environments found to push.");
                return Ok(());
            }

            println!("Targeting provider: {}", provider);

            for current_env in environments_to_push {
                let secrets_map = match vault.list(&current_env) {
                    Some(m) if !m.is_empty() => m,
                    _ => continue,
                };

                // Filtering Logic (Keys vs Scope vs All)
                let keys_to_push: Vec<String> = if !keys.is_empty() {
                    keys.clone()
                } else if !scope.is_empty() {
                    let mut key_set = HashSet::new();
                    if let Some(defined_scopes) = &project_config.scopes {
                        for s in &scope {
                            if let Some(scope_keys) = defined_scopes.get(s) {
                                for k in scope_keys { key_set.insert(k.clone()); }
                            } else {
                                eprintln!("⚠️ Warning: Scope '{}' not defined in project.toml", s);
                            }
                        }
                    } else {
                        eprintln!("Error: No [scopes] defined in project.toml");
                        continue;
                    }
                    if key_set.is_empty() { continue; }
                    println!("🔎 Using scopes {:?} ({} keys) for [{}]", scope, key_set.len(), current_env);
                    key_set.into_iter().collect()
                } else {
                    secrets_map.keys().cloned().collect()
                };

                let mut filtered = std::collections::HashMap::new();
                for k in keys_to_push {
                    if let Some(val) = secrets_map.get(&k) {
                        filtered.insert(k, val.clone());
                    }
                }

                if filtered.is_empty() { continue; }

                println!("📦 Pushing [{}] ({} secrets)...", current_env, filtered.len());

                let options = providers::PushOptions {
                    repo: repo.clone(),
                    env: Some(current_env.clone()),
                };

                if let Err(e) = provider_impl.push(&filtered, token, &options).await {
                    eprintln!("x Failed to push [{}]: {}", current_env, e);
                }
            }
            println!("✓ Operations complete.");
        }
    }
    Ok(())
}