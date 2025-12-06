mod cli;
mod config;
mod project;
mod targets;
mod vault;
#[cfg(test)]
mod tests;

use clap::Parser;
use cli::{Cli, Commands, SecretAction, SetTargetArgs};
use anyhow::Context;
use targets::TargetAdapter;
use rpassword::prompt_password;
use zeroize::Zeroize;
use std::process;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => process::exit(ExitCode::Ok as i32),
        Err(err) => {
            eprintln!("Error: {}", err.error);
            process::exit(err.code as i32);
        }
    }
}

fn require_yes(flags: &CliFlags, action: &str) -> Result<(), AppError> {
    if !flags.yes {
        return Err(AppError::user(anyhow::anyhow!(
            "{} is destructive; rerun with --yes",
            action
        )));
    }
    Ok(())
}

#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
#[repr(i32)]
enum ExitCode {
    Ok = 0,
    UserError = 1,
    NotAuthenticated = 2,
    NetworkError = 3,
    TargetRejected = 4,
    VaultError = 5,
    GitError = 6,
}

#[derive(Debug)]
struct AppError {
    code: ExitCode,
    error: anyhow::Error,
}

#[derive(Debug, Clone, Copy)]
struct CliFlags {
    json: bool,
    non_interactive: bool,
    dry_run: bool,
    yes: bool,
}

impl AppError {
    fn new(code: ExitCode, error: anyhow::Error) -> Self { Self { code, error } }
    fn user(error: anyhow::Error) -> Self { Self::new(ExitCode::UserError, error) }
    fn auth(error: anyhow::Error) -> Self { Self::new(ExitCode::NotAuthenticated, error) }
    #[allow(dead_code)]
    fn git(error: anyhow::Error) -> Self { Self::new(ExitCode::GitError, error) }
    #[allow(dead_code)]
    fn vault(error: anyhow::Error) -> Self { Self::new(ExitCode::VaultError, error) }
    #[allow(dead_code)]
    fn target(error: anyhow::Error) -> Self { Self::new(ExitCode::TargetRejected, error) }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        AppError::user(error)
    }
}

async fn run(cli: Cli) -> Result<(), AppError> {
    let flags = CliFlags {
        json: cli.json,
        non_interactive: cli.non_interactive,
        dry_run: cli.dry_run,
        yes: cli.yes,
    };

    if flags.json {
        // Not implemented yet; avoid mixing prose
        return Err(AppError::user(anyhow::anyhow!(
            "--json output is not yet implemented"
        )));
    }

    match cli.command {
        Commands::Init => {
            config::ensure_global_config_exists()?;
            project::init()?;
        }
        
        Commands::Target { action } => match action {
             cli::TargetAction::Set(args) => {
                if flags.dry_run {
                    println!("(dry-run) Target set skipped");
                    return Ok(());
                }
                handle_target_set(args, &flags)?;
            }
            cli::TargetAction::List => {
                let cfg = config::load()?;
                println!("Configured Targets:");
                for (name, _) in cfg.targets { println!("- {}", name); }
            }
            cli::TargetAction::Revoke { name } => {
                require_yes(&flags, "target revoke")?;
                if flags.dry_run {
                    println!("(dry-run) Target revoke skipped");
                    return Ok(());
                }
                println!("🔌 Attempting to revoke token for target '{}'...", name);
                if let Some(token) = config::get_target_token(&name.to_string())? {
                    if let Some(p) = targets::get(name) {
                        // Atomic Revoke
                        if let Err(e) = p.revoke_auth_token(&token).await {
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
                    if flags.dry_run {
                        println!("(dry-run) Would set {}", key);
                        return Ok(());
                    }
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
                    require_yes(&flags, "secret remove")?;
                    if flags.dry_run {
                        println!("(dry-run) Would remove {}", key);
                        return Ok(());
                    }
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
                    require_yes(&flags, "secret revoke")?;
                    if flags.dry_run {
                        println!("(dry-run) Would revoke '{}' from {}", key, target);
                        return Ok(());
                    }
                     // 1. Get Source Token
                    let source_token = match config::get_target_token(&target.to_string())? {
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
                    if let Err(e) = source_impl.revoke_secret(&key, &secret_value, &source_token).await {
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
            if flags.dry_run {
                println!("(dry-run) Push skipped (no remote mutation).");
                return Ok(());
            }
            let target_impl = match targets::get(args.target) {
                Some(p) => p,
                None => { eprintln!("Error: Target '{}' not supported.", args.target); return Ok(()); }
            };

            let token = config::get_target_token(&args.target.to_string())?
                .ok_or_else(|| anyhow::anyhow!("No token found for {}.", args.target))?;

            let proj = project::Project::find()?;
            let git_info = project::detect_git(None);

            let master_key = proj.get_master_key()?;
            let vault = vault::Vault::load(&proj.vault_path, master_key)?;

            let repo = match args.repo.clone() {
                Some(r) => {
                    if let Some(live) = git_info.as_ref().and_then(|g| g.repo_slug.clone()) {
                        if live != r {
                            return Err(AppError::user(anyhow::anyhow!(
                                "Refusing to push: provided --repo '{}' does not match detected repo '{}'.",
                                r, live
                            )));
                        }
                    }
                    Some(r)
                }
                None => git_info.and_then(|g| g.repo_slug),
            };

            if matches!(args.target, targets::Target::Github) && repo.is_none() {
                return Err(AppError::git(anyhow::anyhow!(
                    "GitHub push requires a repository. Provide --repo owner/name or initialize inside a git repo so it can be recorded."
                )));
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
            if let Err(e) = target_impl.push(&filtered, &token, &options).await {
                eprintln!("x Failed to push: {}", e);
            } else {
                println!("✓ Operations complete.");
            }
        }

        Commands::Prune(args) => {
            require_yes(&flags, "prune")?;
            if flags.dry_run {
                println!("(dry-run) Prune skipped (no remote mutation).");
                return Ok(());
            }
            let target_impl = match targets::get(args.target) {
                Some(p) => p,
                None => { eprintln!("Error: Unknown target"); return Ok(()); }
            };

            let token = config::get_target_token(&args.target.to_string())?
                .ok_or_else(|| anyhow::anyhow!("No token for {}", args.target))?;

            let keys_to_prune: Vec<String> = if !args.keys.is_empty() {
                args.keys
            } else {
                eprintln!("Error: Specify keys to prune.");
                return Ok(());
            };

            if keys_to_prune.is_empty() { return Ok(()); }

            let git_info = project::detect_git(None);
            let repo = match args.repo.clone() {
                Some(r) => {
                    if let Some(live) = git_info.as_ref().and_then(|g| g.repo_slug.clone()) {
                        if live != r {
                            return Err(AppError::user(anyhow::anyhow!(
                                "Refusing to prune: provided --repo '{}' does not match detected repo '{}'.",
                                r, live
                            )));
                        }
                    }
                    Some(r)
                }
                None => git_info.and_then(|g| g.repo_slug),
            };

            if matches!(args.target, targets::Target::Github) && repo.is_none() {
                return Err(AppError::git(anyhow::anyhow!(
                    "GitHub prune requires a repository. Provide --repo owner/name or initialize inside a git repo so it can be recorded."
                )));
            }

            println!("🔌 Deleting from Remote ({}) first...", args.target);
            let options = targets::PushOptions { repo };
            
            // ATOMIC: Remote fail stops local delete
            target_impl.delete(&keys_to_prune, &token, &options).await?;

            println!("✓ Remote delete successful (local vault unchanged).");
        }

        Commands::Config { action } => {
            match action {
                cli::ConfigAction::Get { key } => {
                    match config::config_get(&key)? {
                        Some(v) => println!("{}", v),
                        None => println!("(not set)"),
                    }
                }
                cli::ConfigAction::Set { key, value } => {
                    if flags.dry_run {
                        println!("(dry-run) Would set {}", key);
                        return Ok(());
                    }
                    config::config_set(&key, &value)?;
                    println!("Set {}.", key);
                }
                cli::ConfigAction::Unset { key } => {
                    require_yes(&flags, "config unset")?;
                    if flags.dry_run {
                        println!("(dry-run) Would unset {}", key);
                        return Ok(());
                    }
                    config::config_unset(&key)?;
                    println!("Unset {}.", key);
                }
                cli::ConfigAction::List => {
                    let s = config::config_list()?;
                    println!("{}", s);
                }
            }
        }
    }
    Ok(())
}

fn read_token_securely(maybe_token: Option<String>, flags: &CliFlags) -> Result<String, AppError> {
    match maybe_token {
        Some(token) => Ok(token),
        None => {
            if flags.non_interactive {
                return Err(AppError::user(anyhow::anyhow!(
                    "--non-interactive set; token must be provided via --token"
                )));
            }
            let token = prompt_password("Enter target token: ")
                .context("Failed to read token securely")
                .map_err(AppError::user)?;

            if token.trim().is_empty() {
                return Err(AppError::user(anyhow::anyhow!("Token cannot be empty")));
            }

            Ok(token)
        }
    }
}

fn handle_target_set(args: SetTargetArgs, flags: &CliFlags) -> Result<(), AppError> {
    let mut token = read_token_securely(args.token, flags)?;

    config::set_target_token(&args.name.to_string(), &token).map_err(AppError::auth)?;
    println!("Target '{}' authenticated successfully.", args.name);

    token.zeroize();
    Ok(())
}