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
}

#[derive(Args, Debug)]
pub struct PushArgs {
    /// The target to push to
    pub target: Target,

    /// Specific keys to push. If empty, uses scope or pushes ALL secrets.
    #[arg(num_args = 0..)]
    pub keys: Vec<String>,

    /// Filter by specific scopes defined in project.toml.
    #[arg(long, value_delimiter = ',')]
    pub scope: Vec<String>,

    /// Target environment (e.g., production, preview).
    #[arg(long, short)]
    pub env: Option<String>,
}

#[derive(Args, Debug)]
pub struct PruneArgs {
    /// The target to prune from
    pub target: Target,

    /// Specific keys to remove
    #[arg(num_args = 0..)]
    pub keys: Vec<String>,

    /// Remove all keys belonging to a specific scope
    #[arg(long, value_delimiter = ',')]
    pub scope: Vec<String>,

    /// Target environment
    #[arg(long, short)]
    pub env: Option<String>,
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
        #[arg(long, short)]
        env: String,
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,
    },
    Get { 
        key: String,
        #[arg(long, short)]
        env: String,
    },
    List {
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Remove from Local Vault ONLY (Use 'prune' for remote removal)
    Remove { 
        key: String,
        #[arg(long, short)]
        env: String,
    },
    /// Revoke a generated secret at the source AND locally
    Revoke {
        key: String,
        #[arg(long)]
        target: Target,
        #[arg(long, short)]
        env: String,
        
        /// Optional: Also prune this secret from a downstream target (e.g. github)
        #[arg(long)]
        prune_target: Option<Target>,
    }
}