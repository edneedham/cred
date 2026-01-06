//! CLI argument and command definitions for cred.
//! Parsed once in `main` and dispatched to command handlers.

use crate::sources::Source;
use crate::targets::Target;
use crate::vault::{DEFAULT_ENV, SecretFormat};
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

    /// Show project and vault status (sources, secrets, targets)
    Status,

    /// Manage credential sources (where secrets come from)
    Source {
        #[command(subcommand)]
        action: SourceAction,
    },

    /// Manage global target authentication (where secrets go to)
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

    /// Manage vault environments
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum EnvAction {
    /// List all environments in the vault
    List,
    /// Create a new empty environment
    Create {
        /// Name of the environment to create
        name: String,
    },
    /// Delete an environment and all its secrets
    Delete {
        /// Name of the environment to delete
        name: String,
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

    /// Environment to push secrets from (defaults to "default")
    #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
    pub env: String,
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

    /// Environment to prune secrets from (defaults to "default")
    #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
    pub env: String,
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
pub enum TargetAction {
    /// Authenticate with a target (store token)
    Set(SetTargetArgs),
    /// List configured targets
    List,
    /// Revoke a target's authentication token (Logout)
    Revoke { name: Target },
}

#[derive(Args, Debug)]
pub struct SetTargetArgs {
    /// The target to authenticate with
    pub name: Target,

    /// Auth token (will prompt if omitted). Use a fine-grained PAT with minimal scopes.
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum SourceAction {
    /// Authenticate with a source (store master API key)
    Add(AddSourceArgs),
    /// List configured sources
    List,
    /// Revoke a source's authentication (removes stored master key)
    Revoke { name: Source },
    /// Generate a new credential from a source and store it locally
    Generate(GenerateSourceArgs),
    /// List API keys at the source
    Keys { source: Source },
    /// Delete a generated credential at the source AND from local vault
    Delete(DeleteSourceKeyArgs),
}

#[derive(Args, Debug)]
pub struct DeleteSourceKeyArgs {
    /// The source where the key was generated
    pub source: Source,

    /// The vault key name of the credential to delete
    pub key_name: String,

    /// Environment containing the secret (defaults to "default")
    #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
    pub env: String,
}

#[derive(Args, Debug)]
pub struct AddSourceArgs {
    /// The source to authenticate with
    pub name: Source,

    /// Auth token (will prompt if omitted)
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(Args, Debug)]
pub struct GenerateSourceArgs {
    /// The source to generate a credential from
    pub source: Source,

    /// The key name to store the generated credential under
    pub key_name: String,

    /// Permission level: "full_access" or "sending_access" (Resend)
    #[arg(long, short = 'p')]
    pub permission: Option<String>,

    /// Description for the secret
    #[arg(long, short = 'd')]
    pub description: Option<String>,

    /// Environment to store the generated secret in (defaults to "default")
    #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
    pub env: String,
}

#[derive(Subcommand, Debug)]
pub enum SecretAction {
    /// Set a secret value (with optional metadata)
    Set {
        key: String,
        value: String,
        /// Optional description for the secret
        #[arg(long, short = 'd')]
        description: Option<String>,
        /// Format hint: raw, multiline, base64, json (auto-detected if omitted)
        #[arg(long, short = 'f')]
        format: Option<SecretFormat>,
        /// Environment to set the secret in (defaults to "default")
        #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
        env: String,
    },
    /// Get a secret value
    Get {
        key: String,
        /// Environment to get the secret from (defaults to "default")
        #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
        env: String,
    },
    /// List all secrets
    List {
        /// Environment to list secrets from (defaults to "default", use "*" for all)
        #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
        env: String,
    },
    /// Set or update a secret's description
    Describe {
        key: String,
        /// The description text (omit to clear)
        description: Option<String>,
        /// Environment containing the secret (defaults to "default")
        #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
        env: String,
    },
    /// Remove from Local Vault ONLY (Use 'prune' for remote removal)
    Remove {
        key: String,
        /// Environment to remove the secret from (defaults to "default")
        #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
        env: String,
    },
    /// Revoke a generated secret at the source AND locally
    Revoke {
        key: String,
        #[arg(long)]
        target: Target,
        /// Environment containing the secret (defaults to "default")
        #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
        env: String,
    },
    /// Show version history for a secret
    History {
        key: String,
        /// Environment containing the secret (defaults to "default")
        #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
        env: String,
    },
    /// Rollback a secret to a previous version
    Rollback {
        key: String,
        /// Version index to rollback to (0 = most recent previous version)
        #[arg(long, short = 'v', default_value = "0")]
        version: usize,
        /// Environment containing the secret (defaults to "default")
        #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
        env: String,
    },
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Path to a .env file to import
    pub path: String,
    /// Overwrite existing keys instead of skipping
    #[arg(long)]
    pub overwrite: bool,
    /// Environment to import secrets into (defaults to "default")
    #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
    pub env: String,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Path to write the exported .env file
    pub path: String,
    /// Overwrite the output file if it exists
    #[arg(long)]
    pub force: bool,
    /// Environment to export secrets from (defaults to "default")
    #[arg(long, short = 'e', default_value = DEFAULT_ENV)]
    pub env: String,
}
