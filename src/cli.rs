//! CLI argument and command definitions for cred.
//! Parsed once in `main` and dispatched to command handlers.

use crate::targets::Target;
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Clone, Copy)]
/// Global switches derived from CLI flags/env that affect output and prompts.
pub struct CliFlags {
    pub json: bool,
    pub non_interactive: bool,
    pub dry_run: bool,
    pub yes: bool,
    pub no_color: bool,
}

#[derive(Parser)]
#[command(name = "cred")]
#[command(about = "Local-first credential manager", long_about = None)]
pub struct Cli {
    /// Output JSON (machine-readable); no prose/tables
    #[arg(long, global = true)]
    pub json: bool,
    /// Run without prompts; fail if input required
    #[arg(long, global = true)]
    pub non_interactive: bool,
    /// Do not mutate anything; show planned changes
    #[arg(long, global = true)]
    pub dry_run: bool,
    /// Confirm destructive actions (required for deletes)
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new cred project in the current directory
    Init,

    /// Run health checks (use --json for machine output)
    Doctor,

    /// Manage global target authentication
    Target {
        #[command(subcommand)]
        action: TargetAction,
    },

    /// Manage local secrets
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },

    /// Import secrets from a .env file into the local vault
    Import(ImportArgs),

    /// Export vault secrets to a .env file
    Export(ExportArgs),

    /// Upload (Push) secrets to a remote hosting target (e.g. GitHub)
    Push(PushArgs),

    /// Atomic Delete: Removes secrets from the Remote Target AND Local Vault.
    Prune(PruneArgs),

    /// Inspect and modify cred global configuration (non-secret)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Project-level utilities
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
}

#[derive(Args, Debug)]
pub struct PushArgs {
    /// The target to push to
    pub target: Target,

    /// Specific keys to push. If empty, pushes all secrets.
    #[arg(num_args = 0..)]
    pub keys: Vec<String>,

    /// Explicit repository (required if not in git for GitHub)
    #[arg(long)]
    pub repo: Option<String>,
}

#[derive(Args, Debug)]
pub struct PruneArgs {
    /// The target to prune from
    pub target: Target,

    /// Specific keys to remove
    #[arg(num_args = 0..)]
    pub keys: Vec<String>,

    /// Explicit repository (required if not in git for GitHub)
    #[arg(long)]
    pub repo: Option<String>,

    /// Prune all known keys (requires --yes unless dry-run)
    #[arg(long)]
    pub all: bool,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Get a config value by key path (e.g. preferences.default_target)
    Get { key: String },
    /// Set a config value by key path
    Set { key: String, value: String },
    /// Unset a config value by key path
    Unset { key: String },
    /// List the full config
    List,
}

#[derive(Subcommand, Debug)]
pub enum ProjectAction {
    /// Show project status (git/vault/targets), JSON recommended
    Status,
}

#[derive(Subcommand, Debug)]
pub enum TargetAction {
    Set(SetTargetArgs),
    List,
    /// Revoke a target's authentication token (Logout)
    Revoke {
        name: Target,
    },
}

#[derive(Args, Debug)]
pub struct SetTargetArgs {
    pub name: Target,

    /// Auth token (will prompt if omitted)
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum SecretAction {
    Set {
        key: String,
        value: String,
    },
    Get {
        key: String,
    },
    List {},
    /// Remove from Local Vault ONLY (Use 'prune' for remote removal)
    Remove {
        key: String,
    },
    /// Revoke a generated secret at the source AND locally
    Revoke {
        key: String,
        #[arg(long)]
        target: Target,
    },
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Path to a .env file to import
    pub path: String,
    /// Overwrite existing keys instead of skipping
    #[arg(long)]
    pub overwrite: bool,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Path to write the exported .env file
    pub path: String,
    /// Overwrite the output file if it exists
    #[arg(long)]
    pub force: bool,
}
