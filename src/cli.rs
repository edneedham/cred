use clap::{Args, Parser, Subcommand};
use crate::targets::Target;

#[derive(Parser)]
#[command(name = "cred")]
#[command(about = "Local-first credential manager", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new cred project in the current directory
    Init,

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

    /// Upload (Push) secrets to a remote hosting target (e.g. GitHub)
    Push(PushArgs),

    /// Atomic Delete: Removes secrets from the Remote Target AND Local Vault.
    Prune(PruneArgs),

    /// Inspect and modify cred global configuration (non-secret)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
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

#[derive(Subcommand)]
#[derive(Debug)]
pub enum TargetAction {
    Set(SetTargetArgs),
    List,
    /// Revoke a target's authentication token (Logout)
    Revoke { name: Target }, 
}

#[derive(Args, Debug)]
pub struct SetTargetArgs {
    pub name: Target,

    /// Auth token (will prompt if omitted)
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(Subcommand)]
#[derive(Debug)]
pub enum SecretAction {
    Set { 
        key: String, 
        value: String,
    },
    Get { 
        key: String,
    },
    List {
    },
    /// Remove from Local Vault ONLY (Use 'prune' for remote removal)
    Remove { 
        key: String,
    },
    /// Revoke a generated secret at the source AND locally
    Revoke {
        key: String,
        #[arg(long)]
        target: Target,
    }
}