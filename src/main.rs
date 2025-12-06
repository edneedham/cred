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
use keyring::Entry;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let no_color_env = std::env::var("NO_COLOR").is_ok();
    let flags = CliFlags {
        json: cli.json,
        non_interactive: cli.non_interactive,
        dry_run: cli.dry_run,
        yes: cli.yes,
        no_color: no_color_env || cli.json,
    };
    match run(cli, &flags).await {
        Ok(()) => process::exit(ExitCode::Ok as i32),
        Err(err) => {
            if flags.json {
                let code = match err.code {
                    ExitCode::NotAuthenticated => "NOT_AUTHENTICATED",
                    ExitCode::GitError => "GIT_ERROR",
                    ExitCode::TargetRejected => "TARGET_REJECTED",
                    ExitCode::VaultError => "VAULT_ERROR",
                    ExitCode::NetworkError => "NETWORK_ERROR",
                    ExitCode::UserError | ExitCode::Ok => "USER_ERROR",
                };
                let payload = serde_json::json!({
                    "api_version": "1",
                    "status": "error",
                    "error": {
                        "code": code,
                        "message": err.error.to_string()
                    }
                });
                print_json(&payload);
            } else {
                print_plain_err(&format!("Error: {}", err.error));
            }
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
    no_color: bool,
}

fn print_out(flags: &CliFlags, msg: &str) {
    if !flags.json && !flags.no_color {
        println!("{}", msg);
    } else if !flags.json {
        println!("{}", msg);
    }
}

fn print_plain(msg: &str) {
    println!("{}", msg);
}

fn print_plain_err(msg: &str) {
    eprintln!("{}", msg);
}

fn print_json(payload: &serde_json::Value) {
    print_plain(&serde_json::to_string(payload).unwrap_or_default());
}

fn print_err(flags: &CliFlags, msg: &str) {
    if !flags.json && !flags.no_color {
        eprintln!("{}", msg);
    } else if !flags.json {
        eprintln!("{}", msg);
    }
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

async fn run(cli: Cli, flags: &CliFlags) -> Result<(), AppError> {

    match cli.command {
        Commands::Init => {
            config::ensure_global_config_exists()?;
            project::init()?;
            if flags.json {
                let payload = serde_json::json!({
                    "api_version": "1",
                    "status": "ok",
                    "data": serde_json::Value::Null
                });
                print_json(&payload);
            }
        }
        
        Commands::Target { action } => match action {
             cli::TargetAction::Set(args) => {
                if flags.dry_run {
                    print_out(flags, "(dry-run) Target set skipped");
                    return Ok(());
                }
                handle_target_set(args, &flags)?;
            }
            cli::TargetAction::List => {
                let cfg = config::load()?;
                    let mut names: Vec<String> = cfg.targets.keys().cloned().collect();
                    names.sort();
                    if flags.json {
                    let payload = serde_json::json!({
                        "api_version": "1",
                        "status": "ok",
                        "data": { "targets": names }
                    });
                    println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                } else {
                    println!("Configured Targets:");
                        for name in names {
                            println!("- {}", name);
                        }
                }
            }
            cli::TargetAction::Revoke { name } => {
                require_yes(&flags, "target revoke")?;
                if flags.dry_run {
                    print_out(flags, "(dry-run) Target revoke skipped");
                    return Ok(());
                }
                print_out(flags, &format!("🔌 Attempting to revoke token for target '{}'...", name));
                if let Some(token) = config::get_target_token(&name.to_string())? {
                    if let Some(p) = targets::get(name) {
                        // Atomic Revoke
                        if let Err(e) = p.revoke_auth_token(&token).await {
                            print_err(flags, &format!("x Remote revocation failed: {}", e));
                            return Ok(());
                        }
                    }
                    config::remove_target_token(&name.to_string())?;
                } else {
                    print_out(flags, &format!("Target '{}' was not configured.", name));
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
                    if !flags.dry_run {
                        vault.save()?;
                        print_out(flags, &format!("✓ Set {} = *****", key));
                    } else {
                        print_out(flags, &format!("(dry-run) Would set {}", key));
                    }
                }
                SecretAction::Get { key } => {
                    match vault.get(&key) {
                        Some(val) => {
                            if flags.json {
                                let payload = serde_json::json!({
                                    "api_version": "1",
                                    "status": "ok",
                                    "data": { "key": key, "value": val }
                                });
                                println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                            } else {
                                println!("{}", val)
                            }
                        }
                        None => print_err(flags, &format!("Secret '{}' not found", key)),
                    }
                }
                SecretAction::Remove { key } => {
                    require_yes(&flags, "secret remove")?;
                    if flags.dry_run {
                        print_out(flags, &format!("(dry-run) Would remove {}", key));
                        return Ok(());
                    }
                    if vault.remove(&key).is_some() {
                        vault.save()?;
                        print_out(flags, &format!("✓ Removed '{}' from local vault.", key));
                    } else {
                        print_out(flags, &format!("Secret '{}' did not exist locally.", key));
                    }
                }
                SecretAction::List {} => {
                    let mut keys: Vec<String> = vault.list().keys().cloned().collect();
                    keys.sort();
                    if flags.json {
                        let payload = serde_json::json!({
                            "api_version": "1",
                            "status": "ok",
                            "data": { "keys": keys }
                        });
                        println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                    } else {
                        println!("Vault content:");
                        for k in keys {
                            println!("  {} = *****", k);
                        }
                    }
                }
                SecretAction::Revoke { key, target } => {
                    require_yes(&flags, "secret revoke")?;
                    if flags.dry_run {
                        print_out(flags, &format!("(dry-run) Would revoke '{}' from {}", key, target));
                        return Ok(());
                    }
                     // 1. Get Source Token
                    let source_token = match config::get_target_token(&target.to_string())? {
                        Some(t) => t,
                        None => { print_err(flags, &format!("No token for source {}", target)); return Ok(()); }
                    };

                    // 2. Get Value for Revocation
                    let secret_value = match vault.get(&key) {
                        Some(v) => v.clone(),
                        None => { print_err(flags, &format!("Secret '{}' not found locally.", key)); return Ok(()); }
                    };

                    // 3. Remote Revoke
                    let source_impl = match targets::get(target) {
                        Some(p) => p,
                        None => { print_err(flags, &format!("Unknown target {}", target)); return Ok(()); }
                    };
                    
                    print_out(flags, &format!("🔌 Contacting {} to revoke '{}'...", target, key));
                    // Note: This will fail if target doesn't support revoke (like GitHub)
                    if let Err(e) = source_impl.revoke_secret(&key, &secret_value, &source_token).await {
                         print_err(flags, &format!("x Failed to revoke at source: {}", e));
                         return Ok(());
                    }
                    print_out(flags, "✓ Remote key destroyed.");

                    // 4. Local Remove
                    vault.remove(&key);
                    if !flags.dry_run {
                        vault.save()?;
                        print_out(flags, "✓ Removed from local vault.");
                    }
                }
            }
        }
        
        Commands::Push(args) => {
            let target_impl = match targets::get(args.target) {
                Some(p) => p,
                None => { print_err(flags, &format!("Error: Target '{}' not supported.", args.target)); return Ok(()); }
            };

            let token = config::get_target_token(&args.target.to_string())?
                .ok_or_else(|| anyhow::anyhow!("No token found for {}.", args.target))?;

            let proj = project::Project::find()?;
            let git_info = project::detect_git(None);
            let bound_repo = proj.load_config().ok().and_then(|c| c.git_repo);

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
                    if let Some(bound) = bound_repo {
                        if bound != r {
                            return Err(AppError::git(anyhow::anyhow!(
                                "Refusing to push: provided --repo '{}' does not match bound repo '{}'.",
                                r, bound
                            )));
                        }
                    }
                    Some(r)
                }
                None => {
                    if let Some(live) = git_info.and_then(|g| g.repo_slug) {
                        if let Some(bound) = bound_repo.clone() {
                            if bound != live {
                                return Err(AppError::git(anyhow::anyhow!(
                                    "Refusing to push: detected repo '{}' does not match bound repo '{}'.",
                                    live, bound
                                )));
                            }
                        }
                        Some(live)
                    } else if let Some(bound) = bound_repo {
                        Some(bound)
                    } else {
                        None
                    }
                },
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
                if flags.json {
                    let payload = serde_json::json!({
                        "api_version": "1",
                        "status": "ok",
                        "data": {
                            "target": format!("{}", args.target),
                            "repo": repo,
                            "will_create": [],
                            "will_update": [],
                            "will_delete": []
                        }
                    });
                    println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                } else {
                    print_out(flags, "No secrets to push.");
                }
                return Ok(());
            }

            if flags.dry_run {
                let creates: Vec<String> = Vec::new();
                let mut updates: Vec<String> = Vec::new();
                // With no remote read, we conservatively treat all as updates (or creates)
                // Deterministic ordering: sort keys
                let mut keys: Vec<String> = filtered.keys().cloned().collect();
                keys.sort();
                // If we had a way to diff remote, we could split create/update; here we label as updates
                updates.extend(keys);

                if flags.json {
                    let payload = serde_json::json!({
                        "api_version": "1",
                        "status": "ok",
                        "data": {
                            "target": format!("{}", args.target),
                            "repo": repo,
                            "will_create": creates,
                            "will_update": updates,
                            "will_delete": Vec::<String>::new()
                        }
                    });
                    println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                } else {
                    print_out(flags, "(dry-run) Push skipped (no remote mutation).");
                    print_out(flags, &format!("Target: {}", args.target));
                    if let Some(r) = repo.as_ref() {
                        print_out(flags, &format!("Repo: {}", r));
                    }
                    print_out(flags, &format!("Will update: {:?}", updates));
                }
                return Ok(());
            }

            print_out(flags, &format!("📦 Pushing {} secrets...", filtered.len()));
            let options = targets::PushOptions { repo };
            if let Err(e) = target_impl.push(&filtered, &token, &options).await {
                print_err(flags, &format!("x Failed to push: {}", e));
            } else {
                print_out(flags, "✓ Operations complete.");
            }
        }

        Commands::Prune(args) => {
            require_yes(&flags, "prune")?;
            if flags.dry_run {
                print_out(flags, "(dry-run) Prune skipped (no remote mutation).");
                return Ok(());
            }
            let target_impl = match targets::get(args.target) {
                Some(p) => p,
                None => { print_err(flags, "Error: Unknown target"); return Ok(()); }
            };

            let token = config::get_target_token(&args.target.to_string())?
                .ok_or_else(|| anyhow::anyhow!("No token for {}", args.target))?;

            let keys_to_prune: Vec<String> = if !args.keys.is_empty() {
                args.keys
            } else {
                print_err(flags, "Error: Specify keys to prune.");
                return Ok(());
            };

            if keys_to_prune.is_empty() { return Ok(()); }

            let git_info = project::detect_git(None);
            let bound_repo = project::Project::find().ok().and_then(|p| p.load_config().ok()).and_then(|c| c.git_repo);
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
                    if let Some(bound) = bound_repo {
                        if bound != r {
                            return Err(AppError::git(anyhow::anyhow!(
                                "Refusing to prune: provided --repo '{}' does not match bound repo '{}'.",
                                r, bound
                            )));
                        }
                    }
                    Some(r)
                }
                None => {
                    if let Some(live) = git_info.and_then(|g| g.repo_slug) {
                        if let Some(bound) = bound_repo.clone() {
                            if bound != live {
                                return Err(AppError::git(anyhow::anyhow!(
                                    "Refusing to prune: detected repo '{}' does not match bound repo '{}'.",
                                    live, bound
                                )));
                            }
                        }
                        Some(live)
                    } else if let Some(bound) = bound_repo {
                        Some(bound)
                    } else {
                        None
                    }
                },
            };

            if matches!(args.target, targets::Target::Github) && repo.is_none() {
                return Err(AppError::git(anyhow::anyhow!(
                    "GitHub prune requires a repository. Provide --repo owner/name or initialize inside a git repo so it can be recorded."
                )));
            }

            print_out(flags, &format!("🔌 Deleting from Remote ({}) first...", args.target));
            let options = targets::PushOptions { repo };
            
            // ATOMIC: Remote fail stops local delete
            target_impl.delete(&keys_to_prune, &token, &options).await?;

            print_out(flags, "✓ Remote delete successful (local vault unchanged).");
        }

        Commands::Config { action } => {
            match action {
                cli::ConfigAction::Get { key } => {
                    match config::config_get(&key)? {
                        Some(v) => {
                            if flags.json {
                                let payload = serde_json::json!({
                                    "api_version": "1",
                                    "status": "ok",
                                    "data": { "key": key, "value": v }
                                });
                                println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                            } else {
                                println!("{}", v)
                            }
                        }
                        None => print_out(flags, "(not set)"),
                    }
                }
                cli::ConfigAction::Set { key, value } => {
                    if flags.dry_run {
                        print_out(flags, &format!("(dry-run) Would set {}", key));
                        return Ok(());
                    }
                    config::config_set(&key, &value)?;
                    print_out(flags, &format!("Set {}.", key));
                }
                cli::ConfigAction::Unset { key } => {
                    require_yes(&flags, "config unset")?;
                    if flags.dry_run {
                        print_out(flags, &format!("(dry-run) Would unset {}", key));
                        return Ok(());
                    }
                    config::config_unset(&key)?;
                    print_out(flags, &format!("Unset {}.", key));
                }
                cli::ConfigAction::List => {
                    let s = config::config_list()?;
                    if flags.json {
                        let payload = serde_json::json!({
                            "api_version": "1",
                            "status": "ok",
                            "data": { "config": s }
                        });
                        println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                    } else {
                        println!("{}", s);
                    }
                }
            }
        }

        Commands::Project { action } => {
            match action {
                cli::ProjectAction::Status => {
                    let mut is_project = false;
                    let mut project_name: Option<String> = None;
                    let mut vault_exists = false;
                    let mut vault_accessible = false;
                    let mut git_detected = false;
                    let mut git_root: Option<String> = None;
                    let mut git_remote_current: Option<String> = None;
                    let mut git_remote_bound: Option<String> = None;
                    let mut git_bound = false;
            let mut ready_for_push = false;
                    let mut targets_configured: Vec<String> = Vec::new();

                    let proj = project::Project::find();
                    if let Ok(p) = proj {
                        is_project = true;
                        vault_exists = p.vault_path.exists();
                        let cfg = p.load_config().ok();
                        if let Some(c) = cfg.as_ref() {
                            if let Some(n) = c.name.clone() {
                                project_name = Some(n);
                            }
                            git_root = c.git_root.clone();
                            git_remote_bound = c.git_repo.clone();
                            git_bound = c.git_repo.is_some();
                        }

                        if vault_exists {
                            if let Ok(master_key) = p.get_master_key() {
                                if let Ok(v) = vault::Vault::load(&p.vault_path, master_key) {
                                    let _ = v.list(); // access to ensure decrypt succeeded
                                    vault_accessible = true;
                                }
                            }
                        }

                        if let Some(gi) = project::detect_git(None) {
                            git_detected = true;
                            git_root = Some(gi.root);
                            git_remote_current = gi.repo_slug.clone();
                        }

                        if let Ok(gc) = config::load() {
                            targets_configured = gc.targets.keys().cloned().collect();
                            targets_configured.sort();
                        }

                        ready_for_push = is_project
                            && vault_exists
                            && vault_accessible
                            && (!matches!(git_remote_bound.as_ref(), Some(_)) || git_remote_current == git_remote_bound)
                            && !targets_configured.is_empty();
                    }

                    if flags.json {
                        let payload = serde_json::json!({
                            "api_version": "1",
                            "status": "ok",
                            "data": {
                                "is_project": is_project,
                                "project_name": project_name,
                                "vault_exists": vault_exists,
                                "vault_accessible": vault_accessible,
                                "git_detected": git_detected,
                                "git_root": git_root,
                                "git_bound": git_bound,
                                "git_remote_current": git_remote_current,
                                "git_remote_bound": git_remote_bound,
                                "targets_configured": targets_configured,
                                "ready_for_push": ready_for_push
                            }
                        });
                        println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                    } else {
                        println!("Project status:");
                        println!("  is_project: {}", is_project);
                        println!("  project_name: {:?}", project_name);
                        println!("  vault_exists: {}", vault_exists);
                        println!("  vault_accessible: {}", vault_accessible);
                        println!("  git_detected: {}", git_detected);
                        println!("  git_root: {:?}", git_root);
                        println!("  git_bound: {}", git_bound);
                        println!("  git_remote_current: {:?}", git_remote_current);
                        println!("  git_remote_bound: {:?}", git_remote_bound);
                        println!("  targets_configured: {:?}", targets_configured);
                        println!("  ready_for_push: {}", ready_for_push);
                    }
                }
            }
        }

        Commands::Doctor => {
            let version = env!("CARGO_PKG_VERSION").to_string();

            let global_config = config::ensure_global_config_exists().is_ok() && config::load().is_ok();

            let keychain_access = {
                if let Ok(entry) = Entry::new("cred-doctor", "probe") {
                    let set = entry.set_password("ok").is_ok();
                    // Some keyring backends may not support delete; treat missing delete as ok after set
                    let _ = entry.set_password("");
                    set
                } else {
                    false
                }
            };

            let (project_detected, vault_accessible) = match project::Project::find() {
                Ok(p) => {
                    let vault_ok = if p.vault_path.exists() {
                        p.get_master_key()
                            .ok()
                            .and_then(|k| vault::Vault::load(&p.vault_path, k).ok())
                            .is_some()
                    } else {
                        false
                    };
                    (true, vault_ok)
                }
                Err(_) => (false, false),
            };

            let mut targets: Vec<String> = match config::load() {
                Ok(c) => c.targets.keys().cloned().collect(),
                Err(_) => Vec::new(),
            };
            targets.sort();

            let ready_for_push = project_detected && vault_accessible && !targets.is_empty();

            let payload = serde_json::json!({
                "api_version": "1",
                "status": "ok",
                "data": {
                    "cred_installed": true,
                    "version": version,
                    "global_config": global_config,
                    "keychain_access": keychain_access,
                    "project_detected": project_detected,
                    "vault_accessible": vault_accessible,
                    "targets": targets,
                    "ready_for_push": ready_for_push
                }
            });

            if flags.json {
                print_json(&payload);
            } else {
                println!("{}", serde_json::to_string_pretty(&payload).unwrap_or_default());
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