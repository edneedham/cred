//! cred CLI entrypoint and command dispatcher.
//! Parses args, routes to subcommands, and handles uniform error/exit code reporting.
mod cli;
mod config;
mod envfile;
mod error;
mod io;
mod project;
mod sources;
mod targets;
#[cfg(test)]
mod tests;
mod vault;

use clap::Parser;
use cli::{Cli, CliFlags, Commands, EnvAction, SecretAction, SetTargetArgs, SourceAction};
use error::{AppError, ExitCode};
use io::{print_err, print_json, print_out, print_plain_err, read_token_securely, require_yes};
use keyring::Entry;
use project::resolve_repo_binding;
use sources::SourceAdapter;
use std::process;
use targets::TargetAdapter;
use zeroize::Zeroize;

#[tokio::main]
/// Tokio runtime entrypoint; parses CLI and normalizes exit codes/JSON errors.
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

/// Core dispatcher for all subcommands.
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

        Commands::Status => {
            handle_status(flags).await?;
        }

        Commands::Source { action } => {
            handle_source_action(action, flags).await?;
        }

        Commands::Target { action } => match action {
            cli::TargetAction::Set(args) => {
                if flags.dry_run {
                    print_out(flags, "(dry-run) Target set skipped");
                    return Ok(());
                }
                handle_target_set(args, flags)?;
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
                print_out(
                    flags,
                    &format!("🔌 Attempting to revoke token for target '{}'...", name),
                );
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
                SecretAction::Set {
                    key,
                    value,
                    description,
                    format,
                    env,
                } => {
                    if flags.dry_run {
                        println!("(dry-run) Would set {} in env '{}'", key, env);
                        return Ok(());
                    }
                    // Use explicit format if provided, otherwise auto-detect
                    let fmt = format.unwrap_or_else(|| vault::Vault::detect_format(&value));
                    vault.set_with_metadata_in_env(
                        &env,
                        &key,
                        &value,
                        fmt,
                        description,
                        None,
                        None,
                    );
                    vault.save()?;
                    if env == vault::DEFAULT_ENV {
                        print_out(flags, &format!("✓ Set {} = *****", key));
                    } else {
                        print_out(flags, &format!("✓ Set {} = ***** (env: {})", key, env));
                    }
                }
                SecretAction::Get { key, env } => match vault.get_entry_in_env(&env, &key) {
                    Some(entry) => {
                        if flags.json {
                            let payload = serde_json::json!({
                                "api_version": "1",
                                "status": "ok",
                                "data": {
                                    "key": key,
                                    "env": env,
                                    "value": entry.value,
                                    "format": entry.format.to_string(),
                                    "created_at": entry.created_at.to_rfc3339(),
                                    "updated_at": entry.updated_at.to_rfc3339(),
                                    "description": entry.description,
                                }
                            });
                            println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                        } else {
                            println!("{}", entry.value)
                        }
                    }
                    None => print_err(
                        flags,
                        &format!("Secret '{}' not found in env '{}'", key, env),
                    ),
                },
                SecretAction::Remove { key, env } => {
                    require_yes(&flags, "secret remove")?;
                    if flags.dry_run {
                        if let Some(entry) = vault.get_entry_in_env(&env, &key) {
                            if flags.json {
                                let payload = serde_json::json!({
                                    "api_version": "1",
                                    "status": "ok",
                                    "data": {
                                        "action": "remove",
                                        "dry_run": true,
                                        "key": key,
                                        "env": env,
                                        "format": entry.format.to_string(),
                                        "created_at": entry.created_at.to_rfc3339(),
                                        "description": entry.description,
                                    }
                                });
                                println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                            } else {
                                print_out(
                                    flags,
                                    &format!(
                                        "(dry-run) Would remove '{}' from env '{}' (created {})",
                                        key,
                                        env,
                                        entry.created_at.format("%Y-%m-%d")
                                    ),
                                );
                            }
                        } else {
                            print_out(
                                flags,
                                &format!("Secret '{}' did not exist in env '{}'.", key, env),
                            );
                        }
                        return Ok(());
                    }
                    if let Some(entry) = vault.remove_entry_in_env(&env, &key) {
                        vault.save()?;
                        if flags.json {
                            let payload = serde_json::json!({
                                "api_version": "1",
                                "status": "ok",
                                "data": {
                                    "action": "removed",
                                    "key": key,
                                    "env": env,
                                    "format": entry.format.to_string(),
                                    "created_at": entry.created_at.to_rfc3339(),
                                    "updated_at": entry.updated_at.to_rfc3339(),
                                    "description": entry.description,
                                }
                            });
                            println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                        } else {
                            let age = chrono::Utc::now().signed_duration_since(entry.created_at);
                            let age_str = if age.num_days() > 0 {
                                format!("{} days old", age.num_days())
                            } else if age.num_hours() > 0 {
                                format!("{} hours old", age.num_hours())
                            } else {
                                "just created".to_string()
                            };
                            print_out(
                                flags,
                                &format!("✓ Removed '{}' from env '{}' ({})", key, env, age_str),
                            );
                        }
                    } else {
                        print_out(
                            flags,
                            &format!("Secret '{}' did not exist in env '{}'.", key, env),
                        );
                    }
                }
                SecretAction::List { env } => {
                    // Handle special "*" case to list all environments
                    if env == "*" {
                        let all_entries = vault.list_all_entries();
                        if flags.json {
                            let secrets_data: Vec<serde_json::Value> = all_entries
                                .iter()
                                .map(|(e, k, entry)| {
                                    serde_json::json!({
                                        "env": e,
                                        "key": k,
                                        "format": entry.format.to_string(),
                                        "created_at": entry.created_at.to_rfc3339(),
                                        "updated_at": entry.updated_at.to_rfc3339(),
                                        "description": entry.description,
                                    })
                                })
                                .collect();
                            let payload = serde_json::json!({
                                "api_version": "1",
                                "status": "ok",
                                "data": {
                                    "environments": vault.list_environments(),
                                    "secrets": secrets_data
                                }
                            });
                            println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                        } else {
                            let envs = vault.list_environments();
                            println!("Vault content ({} environments):", envs.len());
                            for env_name in envs {
                                if let Some(entries) = vault.list_entries_in_env(&env_name) {
                                    let mut keys: Vec<&String> = entries.keys().collect();
                                    keys.sort();
                                    println!("\n  [{}] ({} secrets)", env_name, keys.len());
                                    for k in keys {
                                        let entry = &entries[k];
                                        if let Some(desc) = &entry.description {
                                            println!("    {} = ***** ({})", k, desc);
                                        } else {
                                            println!("    {} = *****", k);
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // List specific environment
                        let entries = vault.list_entries_in_env(&env);
                        if let Some(entries) = entries {
                            let mut keys: Vec<&String> = entries.keys().collect();
                            keys.sort();
                            if flags.json {
                                let secrets_data: Vec<serde_json::Value> = keys
                                    .iter()
                                    .map(|k| {
                                        let entry = &entries[*k];
                                        serde_json::json!({
                                            "key": k,
                                            "env": env,
                                            "format": entry.format.to_string(),
                                            "created_at": entry.created_at.to_rfc3339(),
                                            "updated_at": entry.updated_at.to_rfc3339(),
                                            "description": entry.description,
                                        })
                                    })
                                    .collect();
                                let payload = serde_json::json!({
                                    "api_version": "1",
                                    "status": "ok",
                                    "data": { "env": env, "secrets": secrets_data }
                                });
                                println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                            } else {
                                if env == vault::DEFAULT_ENV {
                                    println!("Vault content:");
                                } else {
                                    println!("Vault content (env: {}):", env);
                                }
                                for k in keys {
                                    let entry = &entries[k];
                                    if let Some(desc) = &entry.description {
                                        println!("  {} = ***** ({})", k, desc);
                                    } else {
                                        println!("  {} = *****", k);
                                    }
                                }
                            }
                        } else {
                            if flags.json {
                                let payload = serde_json::json!({
                                    "api_version": "1",
                                    "status": "ok",
                                    "data": { "env": env, "secrets": [] }
                                });
                                println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                            } else {
                                println!("Environment '{}' does not exist or is empty.", env);
                            }
                        }
                    }
                }
                SecretAction::Describe {
                    key,
                    description,
                    env,
                } => {
                    if flags.dry_run {
                        match &description {
                            Some(d) => print_out(
                                flags,
                                &format!(
                                    "(dry-run) Would set description for '{}' in env '{}' to: {}",
                                    key, env, d
                                ),
                            ),
                            None => print_out(
                                flags,
                                &format!(
                                    "(dry-run) Would clear description for '{}' in env '{}'",
                                    key, env
                                ),
                            ),
                        }
                        return Ok(());
                    }
                    if vault.set_description_in_env(&env, &key, description.clone()) {
                        vault.save()?;
                        match &description {
                            Some(d) => {
                                print_out(flags, &format!("✓ Set description for '{}': {}", key, d))
                            }
                            None => {
                                print_out(flags, &format!("✓ Cleared description for '{}'", key))
                            }
                        }
                    } else {
                        print_err(
                            flags,
                            &format!("Secret '{}' not found in env '{}'", key, env),
                        );
                    }
                }
                SecretAction::Revoke { key, target, env } => {
                    require_yes(&flags, "secret revoke")?;
                    if flags.dry_run {
                        print_out(
                            flags,
                            &format!(
                                "(dry-run) Would revoke '{}' from {} (env: {})",
                                key, target, env
                            ),
                        );
                        return Ok(());
                    }
                    // 1. Get Source Token
                    let source_token = match config::get_target_token(&target.to_string())? {
                        Some(t) => t,
                        None => {
                            print_err(flags, &format!("No token for source {}", target));
                            return Ok(());
                        }
                    };

                    // 2. Get Value for Revocation
                    let secret_value = match vault.get_in_env(&env, &key) {
                        Some(v) => v.clone(),
                        None => {
                            print_err(
                                flags,
                                &format!("Secret '{}' not found in env '{}'.", key, env),
                            );
                            return Ok(());
                        }
                    };

                    // 3. Remote Revoke
                    let source_impl = match targets::get(target) {
                        Some(p) => p,
                        None => {
                            print_err(flags, &format!("Unknown target {}", target));
                            return Ok(());
                        }
                    };

                    print_out(
                        flags,
                        &format!("🔌 Contacting {} to revoke '{}'...", target, key),
                    );
                    // Note: This will fail if target doesn't support revoke (like GitHub)
                    if let Err(e) = source_impl
                        .revoke_secret(&key, &secret_value, &source_token)
                        .await
                    {
                        print_err(flags, &format!("x Failed to revoke at source: {}", e));
                        return Ok(());
                    }
                    print_out(flags, "✓ Remote key destroyed.");

                    // 4. Local Remove
                    vault.remove_in_env(&env, &key);
                    if !flags.dry_run {
                        vault.save()?;
                        print_out(flags, "✓ Removed from local vault.");
                    }
                }
                SecretAction::History { key, env } => {
                    let entry = vault.get_entry_in_env(&env, &key);
                    match entry {
                        Some(e) => {
                            if flags.json {
                                let history_data: Vec<_> = e
                                    .history
                                    .iter()
                                    .enumerate()
                                    .map(|(i, h)| {
                                        serde_json::json!({
                                            "version": i,
                                            "value": h.value,
                                            "format": h.format.to_string(),
                                            "updated_at": h.updated_at.to_rfc3339(),
                                            "source": h.source,
                                        })
                                    })
                                    .collect();

                                let payload = serde_json::json!({
                                    "api_version": "1",
                                    "status": "ok",
                                    "data": {
                                        "key": key,
                                        "env": env,
                                        "current": {
                                            "value": e.value,
                                            "format": e.format.to_string(),
                                            "updated_at": e.updated_at.to_rfc3339(),
                                            "source": e.source,
                                        },
                                        "history": history_data,
                                    }
                                });
                                print_json(&payload);
                            } else if e.history.is_empty() {
                                print_out(
                                    flags,
                                    &format!("No history for '{}' in env '{}'", key, env),
                                );
                            } else {
                                println!("History for '{}' in env '{}':", key, env);
                                println!();
                                println!(
                                    "  [current] {} ({})",
                                    e.updated_at.format("%Y-%m-%d %H:%M:%S"),
                                    e.source.as_deref().unwrap_or("unknown")
                                );
                                for (i, h) in e.history.iter().enumerate() {
                                    println!(
                                        "  [{}] {} ({})",
                                        i,
                                        h.updated_at.format("%Y-%m-%d %H:%M:%S"),
                                        h.source.as_deref().unwrap_or("unknown")
                                    );
                                }
                                println!();
                                println!(
                                    "Use 'cred secret rollback {} --version <N>' to restore",
                                    key
                                );
                            }
                        }
                        None => {
                            print_err(
                                flags,
                                &format!("Secret '{}' not found in env '{}'", key, env),
                            );
                        }
                    }
                }
                SecretAction::Rollback { key, version, env } => {
                    require_yes(&flags, "secret rollback")?;

                    // Check if secret exists
                    let entry = vault.get_entry_in_env(&env, &key);
                    if entry.is_none() {
                        print_err(
                            flags,
                            &format!("Secret '{}' not found in env '{}'", key, env),
                        );
                        return Ok(());
                    }

                    let history_len = entry.unwrap().history.len();
                    if history_len == 0 {
                        print_err(flags, &format!("No history for '{}' in env '{}'", key, env));
                        return Ok(());
                    }

                    if version >= history_len {
                        print_err(
                            flags,
                            &format!(
                                "Version {} not found. Available versions: 0-{}",
                                version,
                                history_len - 1
                            ),
                        );
                        return Ok(());
                    }

                    if flags.dry_run {
                        print_out(
                            flags,
                            &format!(
                                "(dry-run) Would rollback '{}' to version {} in env '{}'",
                                key, version, env
                            ),
                        );
                        return Ok(());
                    }

                    match vault.rollback_in_env(&env, &key, version) {
                        Some(_) => {
                            vault.save()?;
                            if flags.json {
                                let payload = serde_json::json!({
                                    "api_version": "1",
                                    "status": "ok",
                                    "data": {
                                        "key": key,
                                        "env": env,
                                        "rolled_back_to": version,
                                    }
                                });
                                print_json(&payload);
                            } else {
                                print_out(
                                    flags,
                                    &format!(
                                        "✓ Rolled back '{}' to version {} in env '{}'",
                                        key, version, env
                                    ),
                                );
                            }
                        }
                        None => {
                            print_err(flags, &format!("Failed to rollback '{}'", key));
                        }
                    }
                }
            }
        }

        Commands::Import(args) => {
            let proj = project::Project::find()?;
            let master_key = proj.get_master_key()?;
            let mut vault = vault::Vault::load(&proj.vault_path, master_key)?;

            let path = std::path::Path::new(&args.path);

            // Try to parse as cred export format first
            let parsed = envfile::parse_cred_export(path)?;

            // If user specified --env, override the detected environment(s)
            let stats = if let Some(target_env) = &args.env {
                // Import all secrets to the specified environment
                let mut combined_stats = envfile::ImportStats::default();
                for env_data in &parsed.environments {
                    for secret in &env_data.secrets {
                        let exists = vault.get_in_env(target_env, &secret.key).is_some();
                        if exists {
                            if args.overwrite {
                                combined_stats.overwritten += 1;
                                if !flags.dry_run {
                                    vault.set_with_metadata_in_env(
                                        target_env,
                                        &secret.key,
                                        &secret.value,
                                        vault::SecretFormat::Raw,
                                        secret.description.clone(),
                                        None,
                                        None,
                                    );
                                }
                            } else {
                                combined_stats.skipped += 1;
                            }
                        } else {
                            combined_stats.added += 1;
                            if !flags.dry_run {
                                vault.set_with_metadata_in_env(
                                    target_env,
                                    &secret.key,
                                    &secret.value,
                                    vault::SecretFormat::Raw,
                                    secret.description.clone(),
                                    None,
                                    None,
                                );
                            }
                        }
                    }
                }
                combined_stats
            } else {
                // Use the cred import function which respects environment markers
                envfile::import_cred_export(&parsed, &mut vault, args.overwrite, flags.dry_run)
            };

            if !flags.dry_run {
                vault.save()?;
            }

            let env_display = args.env.as_deref().unwrap_or(if parsed.is_cred_format {
                "(from file)"
            } else {
                vault::DEFAULT_ENV
            });

            if flags.json {
                let payload = serde_json::json!({
                    "api_version": "1",
                    "status": "ok",
                    "data": {
                        "path": args.path,
                        "env": env_display,
                        "added": stats.added,
                        "overwritten": stats.overwritten,
                        "skipped": stats.skipped,
                        "environments_created": stats.environments_created,
                        "cred_format": parsed.is_cred_format,
                        "dry_run": flags.dry_run
                    }
                });
                print_json(&payload);
            } else if flags.dry_run {
                let env_suffix = if stats.environments_created > 0 {
                    format!(
                        " ({} environments)",
                        stats.environments_created + parsed.environments.len()
                            - stats.environments_created
                    )
                } else {
                    String::new()
                };
                print_out(
                    flags,
                    &format!(
                        "(dry-run) Would import from {}{} (add {}, overwrite {}, skip {}).",
                        args.path, env_suffix, stats.added, stats.overwritten, stats.skipped
                    ),
                );
            } else {
                let env_suffix = if stats.environments_created > 0 {
                    format!(" (created {} env(s))", stats.environments_created)
                } else {
                    String::new()
                };
                print_out(
                    flags,
                    &format!(
                        "✓ Imported {}{} (added {}, overwritten {}, skipped {}).",
                        args.path, env_suffix, stats.added, stats.overwritten, stats.skipped
                    ),
                );
            }
        }

        Commands::Export(args) => {
            let proj = project::Project::find()?;
            let master_key = proj.get_master_key()?;
            let vault = vault::Vault::load(&proj.vault_path, master_key)?;

            let path = std::path::Path::new(&args.path);

            let (count, env_description) = if args.plain {
                // Plain .env format (no metadata)
                let env = args.env.as_deref().unwrap_or(vault::DEFAULT_ENV);
                let c = envfile::export_env_file_from_env(
                    &vault,
                    env,
                    path,
                    args.force,
                    flags.dry_run,
                )?;
                let desc = if env == vault::DEFAULT_ENV {
                    "plain format".to_string()
                } else {
                    format!("plain format, env '{}'", env)
                };
                (c, desc)
            } else if let Some(ref env) = args.env {
                // Single environment with metadata
                let c = envfile::export_env_with_metadata(
                    &vault,
                    env,
                    path,
                    args.force,
                    flags.dry_run,
                )?;
                let desc = format!("env '{}'", env);
                (c, desc)
            } else {
                // Full vault with metadata (default)
                let c = envfile::export_full_vault(&vault, path, args.force, flags.dry_run)?;
                let envs = vault.list_environments();
                let desc = format!("{} environment(s)", envs.len());
                (c, desc)
            };

            if flags.json {
                let payload = serde_json::json!({
                    "api_version": "1",
                    "status": "ok",
                    "data": {
                        "path": args.path,
                        "env": args.env,
                        "exported": count,
                        "plain": args.plain,
                        "dry_run": flags.dry_run
                    }
                });
                print_json(&payload);
            } else if flags.dry_run {
                print_out(
                    flags,
                    &format!(
                        "(dry-run) Would export {} secrets ({}) to {}.",
                        count, env_description, args.path
                    ),
                );
            } else {
                print_out(
                    flags,
                    &format!(
                        "✓ Exported {} secrets ({}) to {}.",
                        count, env_description, args.path
                    ),
                );
            }
        }

        Commands::Push(args) => {
            let target_impl = match targets::get(args.target) {
                Some(p) => p,
                None => {
                    print_err(
                        flags,
                        &format!("Error: Target '{}' not supported.", args.target),
                    );
                    return Ok(());
                }
            };

            let token = config::get_target_token(&args.target.to_string())?
                .ok_or_else(|| anyhow::anyhow!("No token found for {}.", args.target))?;

            let proj = project::Project::find()?;
            let git_info = project::detect_git(None);
            let bound_repo = proj.load_config().ok().and_then(|c| c.git_repo);

            let master_key = proj.get_master_key()?;
            let vault = vault::Vault::load(&proj.vault_path, master_key)?;

            let repo = resolve_repo_binding(
                git_info.and_then(|g| g.repo_slug),
                bound_repo,
                args.repo.clone(),
                "push",
            )
            .map_err(AppError::from)?;

            if matches!(args.target, targets::Target::Github) && repo.is_none() {
                return Err(AppError::git(anyhow::anyhow!(
                    "GitHub push requires a repository. Provide --repo owner/name or initialize inside a git repo so it can be recorded."
                )));
            }

            let keys_to_push: Vec<String> = if !args.keys.is_empty() {
                args.keys.clone()
            } else {
                vault.list_in_env(&args.env).keys().cloned().collect()
            };

            let mut filtered = std::collections::HashMap::new();
            for k in keys_to_push {
                if let Some(val) = vault.get_in_env(&args.env, &k) {
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
                            "env": args.env,
                            "repo": repo,
                            "will_create": [],
                            "will_update": [],
                            "will_delete": []
                        }
                    });
                    println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                } else {
                    let env_suffix = if args.env == vault::DEFAULT_ENV {
                        String::new()
                    } else {
                        format!(" in env '{}'", args.env)
                    };
                    print_out(flags, &format!("No secrets to push{}.", env_suffix));
                }
                return Ok(());
            }

            if flags.dry_run {
                let mut keys: Vec<String> = filtered.keys().cloned().collect();
                keys.sort();

                if flags.json {
                    let payload = serde_json::json!({
                        "api_version": "1",
                        "status": "ok",
                        "data": {
                            "target": format!("{}", args.target),
                            "env": args.env,
                            "repo": repo,
                            "will_push": keys,
                            "will_delete": Vec::<String>::new()
                        }
                    });
                    println!("{}", serde_json::to_string(&payload).unwrap_or_default());
                } else {
                    print_out(flags, "(dry-run) Push skipped (no remote mutation).");
                    print_out(flags, &format!("Target: {}", args.target));
                    if args.env != vault::DEFAULT_ENV {
                        print_out(flags, &format!("Env: {}", args.env));
                    }
                    if let Some(r) = repo.as_ref() {
                        print_out(flags, &format!("Repo: {}", r));
                    }
                    if !keys.is_empty() {
                        print_out(flags, &format!("Will push: {:?}", keys));
                    }
                }
                return Ok(());
            }

            let env_suffix = if args.env == vault::DEFAULT_ENV {
                String::new()
            } else {
                format!(" from env '{}'", args.env)
            };
            print_out(
                flags,
                &format!("📦 Pushing {} secrets{}...", filtered.len(), env_suffix),
            );
            let options = targets::PushOptions {
                repo,
                project: args.project.clone(),
                app: args.app.clone(),
                env: Some(args.env.clone()),
            };
            if let Err(e) = target_impl.push(&filtered, &token, &options).await {
                print_err(flags, &format!("x Failed to push: {}", e));
            } else {
                print_out(flags, "✓ Operations complete.");
            }
        }

        Commands::Prune(args) => {
            let ci_force_dry = std::env::var("CI").is_ok() && !flags.yes;
            let effective_dry = flags.dry_run || ci_force_dry;

            if !effective_dry {
                require_yes(&flags, "prune")?;
            } else if ci_force_dry {
                print_out(
                    flags,
                    "CI detected without --yes; forcing dry-run for prune.",
                );
            }

            if effective_dry {
                print_out(flags, "(dry-run) Prune skipped (no remote mutation).");
            }

            let target_impl = match targets::get(args.target) {
                Some(p) => p,
                None => {
                    print_err(flags, "Error: Unknown target");
                    return Ok(());
                }
            };

            let token = config::get_target_token(&args.target.to_string())?
                .ok_or_else(|| anyhow::anyhow!("No token for {}", args.target))?;

            let proj = project::Project::find()?;
            let master_key = proj.get_master_key()?;
            let vault = vault::Vault::load(&proj.vault_path, master_key)?;

            let keys_to_prune: Vec<String> = if args.all {
                let mut ks: Vec<String> = vault.list_in_env(&args.env).keys().cloned().collect();
                ks.sort();
                ks
            } else if !args.keys.is_empty() {
                args.keys
            } else {
                print_err(flags, "Error: Specify keys to prune or use --all.");
                return Ok(());
            };

            if keys_to_prune.is_empty() {
                return Ok(());
            }

            let git_info = project::detect_git(None);
            let bound_repo = project::Project::find()
                .ok()
                .and_then(|p| p.load_config().ok())
                .and_then(|c| c.git_repo);
            let repo = resolve_repo_binding(
                git_info.and_then(|g| g.repo_slug),
                bound_repo,
                args.repo.clone(),
                "prune",
            )
            .map_err(AppError::from)?;

            if matches!(args.target, targets::Target::Github) && repo.is_none() {
                return Err(AppError::git(anyhow::anyhow!(
                    "GitHub prune requires a repository. Provide --repo owner/name or initialize inside a git repo so it can be recorded."
                )));
            }

            if effective_dry {
                if flags.json {
                    let mut keys_sorted = keys_to_prune.clone();
                    keys_sorted.sort();
                    let payload = serde_json::json!({
                        "api_version": "1",
                        "status": "ok",
                        "data": {
                            "target": format!("{}", args.target),
                            "env": args.env,
                            "repo": repo,
                            "will_delete": keys_sorted
                        }
                    });
                    print_json(&payload);
                } else {
                    let mut keys_sorted = keys_to_prune.clone();
                    keys_sorted.sort();
                    print_out(flags, "(dry-run) Prune skipped (no remote mutation).");
                    print_out(flags, &format!("Target: {}", args.target));
                    if args.env != vault::DEFAULT_ENV {
                        print_out(flags, &format!("Env: {}", args.env));
                    }
                    if let Some(r) = repo.as_ref() {
                        print_out(flags, &format!("Repo: {}", r));
                    }
                    print_out(flags, &format!("Will delete: {:?}", keys_sorted));
                }
                return Ok(());
            }

            let env_suffix = if args.env == vault::DEFAULT_ENV {
                String::new()
            } else {
                format!(" (env: {})", args.env)
            };
            print_out(
                flags,
                &format!("Deleting from Remote ({}){}...", args.target, env_suffix),
            );
            let options = targets::PushOptions {
                repo,
                project: args.project.clone(),
                app: args.app.clone(),
                env: Some(args.env.clone()),
            };

            // ATOMIC: Remote fail stops local delete
            target_impl.delete(&keys_to_prune, &token, &options).await?;

            print_out(flags, "✓ Remote delete successful (local vault unchanged).");
        }

        Commands::Config { action } => match action {
            cli::ConfigAction::Get { key } => match config::config_get(&key)? {
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
            },
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
        },

        Commands::Env { action } => {
            let proj = project::Project::find()?;
            let master_key = proj.get_master_key()?;
            let mut vault = vault::Vault::load(&proj.vault_path, master_key)?;

            match action {
                EnvAction::List => {
                    let envs = vault.list_environments();
                    if flags.json {
                        let env_data: Vec<serde_json::Value> = envs
                            .iter()
                            .map(|e| {
                                serde_json::json!({
                                    "name": e,
                                    "count": vault.count_in_env(e),
                                })
                            })
                            .collect();
                        let payload = serde_json::json!({
                            "api_version": "1",
                            "status": "ok",
                            "data": { "environments": env_data }
                        });
                        print_json(&payload);
                    } else {
                        if envs.is_empty() {
                            println!("No environments configured.");
                        } else {
                            println!("Environments:");
                            for env in envs {
                                let count = vault.count_in_env(&env);
                                println!("  {} ({} secrets)", env, count);
                            }
                        }
                    }
                }
                EnvAction::Create { name } => {
                    if flags.dry_run {
                        print_out(
                            flags,
                            &format!("(dry-run) Would create environment '{}'", name),
                        );
                        return Ok(());
                    }
                    if vault.create_environment(&name) {
                        vault.save()?;
                        print_out(flags, &format!("✓ Created environment '{}'", name));
                    } else {
                        print_err(flags, &format!("Environment '{}' already exists", name));
                    }
                }
                EnvAction::Delete { name } => {
                    require_yes(flags, "env delete")?;

                    if name == vault::DEFAULT_ENV {
                        print_err(flags, "Cannot delete the default environment");
                        return Ok(());
                    }

                    let count = vault.count_in_env(&name);
                    if flags.dry_run {
                        print_out(
                            flags,
                            &format!(
                                "(dry-run) Would delete environment '{}' ({} secrets)",
                                name, count
                            ),
                        );
                        return Ok(());
                    }
                    if vault.delete_environment(&name) {
                        vault.save()?;
                        print_out(
                            flags,
                            &format!(
                                "✓ Deleted environment '{}' ({} secrets removed)",
                                name, count
                            ),
                        );
                    } else {
                        print_err(flags, &format!("Environment '{}' does not exist", name));
                    }
                }
            }
        }

        Commands::Doctor => {
            let version = env!("CARGO_PKG_VERSION").to_string();

            let global_config =
                config::ensure_global_config_exists().is_ok() && config::load().is_ok();

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
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            }
        }
    }
    Ok(())
}

/// Handle `target set`, persisting the token securely and zeroizing it afterward.
/// Targets use simple token-based auth (fine-grained PAT via --token or prompt).
fn handle_target_set(args: SetTargetArgs, flags: &CliFlags) -> Result<(), AppError> {
    let target_name = args.name.to_string();

    // If token is provided directly, use it
    if let Some(token) = args.token {
        config::set_target_token(&target_name, &token).map_err(AppError::auth)?;
        print_out(
            flags,
            &format!("Target '{}' authenticated successfully.", args.name),
        );
        return Ok(());
    }

    // Otherwise prompt for token
    let mut token = read_token_securely(None, flags)?;
    config::set_target_token(&target_name, &token).map_err(AppError::auth)?;
    print_out(
        flags,
        &format!("Target '{}' authenticated successfully.", args.name),
    );
    token.zeroize();
    Ok(())
}

/// Handle the top-level `status` command with enhanced output.
async fn handle_status(flags: &CliFlags) -> Result<(), AppError> {
    let mut sources_configured: Vec<String> = Vec::new();
    let mut targets_configured: Vec<String> = Vec::new();
    let mut secrets_info: Vec<serde_json::Value> = Vec::new();
    let mut vault_count: usize = 0;
    let mut environments: Vec<String> = Vec::new();
    let mut is_project = false;

    // Git info
    let mut git_repo: Option<String> = None;

    // Load global config for sources/targets
    if let Ok(gc) = config::load() {
        sources_configured = gc.sources.keys().cloned().collect();
        sources_configured.sort();
        targets_configured = gc.targets.keys().cloned().collect();
        targets_configured.sort();
    }

    // Load project and vault info
    if let Ok(p) = project::Project::find() {
        is_project = true;
        if p.vault_path.exists() {
            if let Ok(master_key) = p.get_master_key() {
                if let Ok(v) = vault::Vault::load(&p.vault_path, master_key) {
                    vault_count = v.total_count();
                    environments = v.list_environments();

                    for (env, key, entry) in v.list_all_entries() {
                        let source = entry.source.as_deref().unwrap_or("unknown");
                        secrets_info.push(serde_json::json!({
                            "env": env,
                            "key": key,
                            "source": source,
                        }));
                    }
                }
            }
        }
    }

    // Detect git repo
    if let Some(gi) = project::detect_git(None) {
        git_repo = gi.repo_slug;
    }

    if flags.json {
        let payload = serde_json::json!({
            "api_version": "1",
            "status": "ok",
            "data": {
                "is_project": is_project,
                "vault_count": vault_count,
                "environments": environments,
                "secrets": secrets_info,
                "sources": sources_configured,
                "targets": targets_configured,
                "git_repo": git_repo,
            }
        });
        print_json(&payload);
    } else {
        if !is_project {
            println!("Not in a cred project. Run 'cred init' to initialize.");
            return Ok(());
        }

        println!(
            "Vault: {} secrets ({} environments)",
            vault_count,
            environments.len()
        );
        println!();

        if secrets_info.is_empty() {
            println!("  (no secrets)");
        } else {
            // Group by environment for display
            let mut current_env = String::new();
            for secret in &secrets_info {
                let env = secret["env"].as_str().unwrap_or("default");
                let key = secret["key"].as_str().unwrap_or("");
                let source = secret["source"].as_str().unwrap_or("unknown");

                if env != current_env {
                    if !current_env.is_empty() {
                        println!();
                    }
                    println!("  [{}]", env);
                    current_env = env.to_string();
                }
                println!("    {:<20} [{}]", key, source);
            }
        }

        println!();
        if sources_configured.is_empty() {
            println!("Sources: (none configured)");
        } else {
            println!(
                "Sources: {}",
                sources_configured
                    .iter()
                    .map(|s| format!("{} ✓", s))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        if targets_configured.is_empty() {
            println!("Targets: (none configured)");
        } else {
            println!(
                "Targets: {}",
                targets_configured
                    .iter()
                    .map(|t| format!("{} ✓", t))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        if let Some(repo) = git_repo {
            println!("Git: {}", repo);
        }
    }

    Ok(())
}

/// Handle source subcommands (add, list, revoke, generate).
async fn handle_source_action(action: SourceAction, flags: &CliFlags) -> Result<(), AppError> {
    match action {
        SourceAction::Add(args) => {
            if flags.dry_run {
                print_out(flags, "(dry-run) Source add skipped");
                return Ok(());
            }

            let source_name = args.name.to_string();

            // If token is provided directly, use it
            if let Some(token) = args.token {
                config::set_source_token(&source_name, &token).map_err(AppError::auth)?;
                print_out(
                    flags,
                    &format!("Source '{}' authenticated successfully.", source_name),
                );
                return Ok(());
            }

            // Prompt for token interactively
            let mut token = read_token_securely(None, flags)?;
            config::set_source_token(&source_name, &token).map_err(AppError::auth)?;

            // Validate the token
            if let Some(source_impl) = sources::get(args.name) {
                match source_impl.validate_auth(&token).await {
                    Ok(true) => {}
                    Ok(false) => {
                        print_err(flags, "Token validation failed - token may be invalid");
                    }
                    Err(e) => {
                        print_err(flags, &format!("Could not validate token: {}", e));
                    }
                }
            }

            print_out(
                flags,
                &format!("Source '{}' authenticated successfully.", source_name),
            );
            token.zeroize();
        }

        SourceAction::List => {
            let cfg = config::load()?;
            let mut names: Vec<String> = cfg.sources.keys().cloned().collect();
            names.sort();

            if flags.json {
                let payload = serde_json::json!({
                    "api_version": "1",
                    "status": "ok",
                    "data": { "sources": names }
                });
                print_json(&payload);
            } else {
                if names.is_empty() {
                    println!("No sources configured.");
                    println!("Run 'cred source add <source>' to authenticate with a source.");
                } else {
                    println!("Configured Sources:");
                    for name in names {
                        println!("- {}", name);
                    }
                }
            }
        }

        SourceAction::Revoke { name } => {
            require_yes(flags, "source revoke")?;

            let source_name = name.to_string();

            // Get the auth token before we revoke it (needed to delete keys at source)
            let auth_token = config::get_source_token(&source_name)?;

            // Find vault entries from this source that have source_id (generated keys)
            let mut keys_to_delete: Vec<(String, String)> = Vec::new();
            if let Ok(proj) = project::Project::find() {
                if let Ok(master_key) = proj.get_master_key() {
                    if let Ok(v) = vault::Vault::load(&proj.vault_path, master_key) {
                        for (key, entry) in v.list_entries() {
                            if entry.source.as_deref() == Some(&source_name) {
                                if let Some(id) = &entry.source_id {
                                    keys_to_delete.push((key.clone(), id.clone()));
                                }
                            }
                        }
                    }
                }
            }

            if flags.dry_run {
                if keys_to_delete.is_empty() {
                    print_out(
                        flags,
                        &format!(
                            "(dry-run) Would revoke source '{}' authentication",
                            source_name
                        ),
                    );
                } else {
                    print_out(
                        flags,
                        &format!(
                            "(dry-run) Would delete {} generated key(s) at {} and revoke authentication:",
                            keys_to_delete.len(),
                            source_name
                        ),
                    );
                    for (key, id) in &keys_to_delete {
                        print_out(flags, &format!("  - {} (id: {})", key, id));
                    }
                }
                return Ok(());
            }

            // Delete generated keys at the source (if we have auth token)
            let mut deleted_count = 0;
            let mut failed_keys: Vec<String> = Vec::new();

            if !keys_to_delete.is_empty() {
                if let Some(ref token) = auth_token {
                    if let Some(source_impl) = sources::get(name) {
                        for (key, source_id) in &keys_to_delete {
                            match source_impl.revoke(source_id, token).await {
                                Ok(()) => {
                                    deleted_count += 1;
                                    if !flags.json {
                                        println!("  ✓ Deleted '{}' at {}", key, source_name);
                                    }
                                }
                                Err(e) => {
                                    failed_keys.push(format!("{}: {}", key, e));
                                }
                            }
                        }
                    }
                } else {
                    // No auth token - warn that keys may be orphaned
                    print_err(
                        flags,
                        &format!(
                            "Warning: {} generated key(s) may be orphaned at {} (no auth token to delete them)",
                            keys_to_delete.len(),
                            source_name
                        ),
                    );
                }
            }

            // Remove from local vault
            if let Ok(proj) = project::Project::find() {
                if let Ok(master_key) = proj.get_master_key() {
                    if let Ok(mut v) = vault::Vault::load(&proj.vault_path, master_key) {
                        for (key, _) in &keys_to_delete {
                            v.remove_entry(key);
                        }
                        let _ = v.save();
                    }
                }
            }

            // Remove the source authentication
            config::remove_source_token(&source_name)?;

            if flags.json {
                let payload = serde_json::json!({
                    "api_version": "1",
                    "status": "ok",
                    "data": {
                        "source": source_name,
                        "keys_deleted": deleted_count,
                        "keys_failed": failed_keys,
                        "message": "Source revoked"
                    }
                });
                print_json(&payload);
            } else {
                if deleted_count > 0 {
                    println!(
                        "✓ Revoked source '{}' and deleted {} generated key(s)",
                        source_name, deleted_count
                    );
                } else {
                    println!("✓ Revoked source '{}'", source_name);
                }
                if !failed_keys.is_empty() {
                    print_err(
                        flags,
                        &format!("Failed to delete {} key(s):", failed_keys.len()),
                    );
                    for msg in &failed_keys {
                        print_err(flags, &format!("  - {}", msg));
                    }
                }
            }
        }

        SourceAction::Generate(args) => {
            if flags.dry_run {
                let env_suffix = if args.env == vault::DEFAULT_ENV {
                    String::new()
                } else {
                    format!(" in env '{}'", args.env)
                };
                print_out(
                    flags,
                    &format!(
                        "(dry-run) Would generate '{}' from source '{}'{}",
                        args.key_name, args.source, env_suffix
                    ),
                );
                return Ok(());
            }

            let source_name = args.source.to_string();

            // Get the source auth token
            let auth_token = config::get_source_token(&source_name)?.ok_or_else(|| {
                AppError::auth(anyhow::anyhow!(
                    "Source '{}' not authenticated. Run 'cred source add {}'",
                    source_name,
                    source_name
                ))
            })?;

            // Get the source adapter
            let source_impl = sources::get(args.source).ok_or_else(|| {
                AppError::user(anyhow::anyhow!("Unknown source: {}", source_name))
            })?;

            // Build generate options
            let options = sources::GenerateOptions {
                scopes: args.permission.map(|p| vec![p]).unwrap_or_default(),
                expires_in_days: None,
                description: args.description.clone(),
            };

            // Generate the credential
            let credential = source_impl
                .generate(&args.key_name, &auth_token, &options)
                .await
                .map_err(AppError::user)?;

            // Store in vault with source metadata and remote ID
            let proj = project::Project::find()?;
            let master_key = proj.get_master_key()?;
            let mut v = vault::Vault::load(&proj.vault_path, master_key)?;
            let fmt = vault::Vault::detect_format(&credential.value);
            v.set_with_metadata_in_env(
                &args.env,
                &args.key_name,
                &credential.value,
                fmt,
                args.description,
                Some(source_name.clone()),
                credential.id.clone(),
            );
            v.save()?;

            if flags.json {
                let payload = serde_json::json!({
                    "api_version": "1",
                    "status": "ok",
                    "data": {
                        "key": args.key_name,
                        "env": args.env,
                        "source": source_name,
                        "source_id": credential.id,
                        "message": "Credential generated and stored"
                    }
                });
                print_json(&payload);
            } else {
                let env_suffix = if args.env == vault::DEFAULT_ENV {
                    String::new()
                } else {
                    format!(" (env: {})", args.env)
                };
                println!(
                    "✓ Generated '{}' from {} and stored in vault{}",
                    args.key_name, source_name, env_suffix
                );
                if let Some(id) = &credential.id {
                    println!("  Remote ID: {} (saved for revocation)", id);
                }
                println!("  Run 'cred push <target>' to deploy this secret");
            }
        }

        SourceAction::Keys { source } => {
            let source_name = source.to_string();

            // Get the source auth token
            let auth_token = config::get_source_token(&source_name)?.ok_or_else(|| {
                AppError::auth(anyhow::anyhow!(
                    "Source '{}' not authenticated. Run 'cred source add {}'",
                    source_name,
                    source_name
                ))
            })?;

            // Get the source adapter
            let source_impl = sources::get(source).ok_or_else(|| {
                AppError::user(anyhow::anyhow!("Unknown source: {}", source_name))
            })?;

            // List keys at the source
            let keys = source_impl
                .list(&auth_token)
                .await
                .map_err(AppError::user)?;

            if flags.json {
                let payload = serde_json::json!({
                    "api_version": "1",
                    "status": "ok",
                    "data": {
                        "source": source_name,
                        "keys": keys
                    }
                });
                print_json(&payload);
            } else {
                if keys.is_empty() {
                    println!("No API keys found at {}.", source_name);
                } else {
                    println!("API keys at {}:", source_name);
                    for key in keys {
                        println!("  - {}", key);
                    }
                }
            }
        }

        SourceAction::Delete(args) => {
            require_yes(flags, "source delete")?;

            let source_name = args.source.to_string();

            // Load vault and find the entry
            let proj = project::Project::find()?;
            let master_key = proj.get_master_key()?;
            let mut v = vault::Vault::load(&proj.vault_path, master_key)?;

            let entry = v
                .get_entry_in_env(&args.env, &args.key_name)
                .ok_or_else(|| {
                    AppError::user(anyhow::anyhow!(
                        "Key '{}' not found in env '{}'",
                        args.key_name,
                        args.env
                    ))
                })?;

            // Verify the key came from this source
            if entry.source.as_deref() != Some(&source_name) {
                return Err(AppError::user(anyhow::anyhow!(
                    "Key '{}' was not generated from source '{}' (source: {:?})",
                    args.key_name,
                    source_name,
                    entry.source
                )));
            }

            // Get the source_id for revocation
            let source_id = entry.source_id.clone().ok_or_else(|| {
                AppError::user(anyhow::anyhow!(
                    "Key '{}' has no source_id stored. Cannot delete at source.",
                    args.key_name
                ))
            })?;

            if flags.dry_run {
                let env_suffix = if args.env == vault::DEFAULT_ENV {
                    String::new()
                } else {
                    format!(" (env: {})", args.env)
                };
                print_out(
                    flags,
                    &format!(
                        "(dry-run) Would delete '{}' (id: {}) from {} and local vault{}",
                        args.key_name, source_id, source_name, env_suffix
                    ),
                );
                return Ok(());
            }

            // Get the source auth token
            let auth_token = config::get_source_token(&source_name)?.ok_or_else(|| {
                AppError::auth(anyhow::anyhow!(
                    "Source '{}' not authenticated. Run 'cred source add {}'",
                    source_name,
                    source_name
                ))
            })?;

            // Get the source adapter
            let source_impl = sources::get(args.source).ok_or_else(|| {
                AppError::user(anyhow::anyhow!("Unknown source: {}", source_name))
            })?;

            // Delete at the source
            source_impl
                .revoke(&source_id, &auth_token)
                .await
                .map_err(AppError::user)?;

            // Remove from local vault
            v.remove_entry_in_env(&args.env, &args.key_name);
            v.save()?;

            if flags.json {
                let payload = serde_json::json!({
                    "api_version": "1",
                    "status": "ok",
                    "data": {
                        "key": args.key_name,
                        "env": args.env,
                        "source": source_name,
                        "source_id": source_id,
                        "message": "Credential deleted from source and local vault"
                    }
                });
                print_json(&payload);
            } else {
                let env_suffix = if args.env == vault::DEFAULT_ENV {
                    String::new()
                } else {
                    format!(" (env: {})", args.env)
                };
                println!(
                    "✓ Deleted '{}' from {} and local vault{}",
                    args.key_name, source_name, env_suffix
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod main_tests {
    use super::*;

    #[test]
    fn test_exit_codes_values() {
        assert_eq!(ExitCode::Ok as i32, 0);
        assert_eq!(ExitCode::UserError as i32, 1);
        assert_eq!(ExitCode::NotAuthenticated as i32, 2);
        assert_eq!(ExitCode::NetworkError as i32, 3);
        assert_eq!(ExitCode::TargetRejected as i32, 4);
        assert_eq!(ExitCode::VaultError as i32, 5);
        assert_eq!(ExitCode::GitError as i32, 6);
    }
}
