use clap::{Parser, Subcommand};
use crate::providers::ProviderType;

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

    /// Manage global provider authentication
    Provider {
        #[command(subcommand)]
        action: ProviderAction,
    },

    /// Manage local secrets
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },

    /// Upload (Push) secrets to a remote hosting provider (e.g. GitHub)
    Push {
        /// The provider to push to
        provider: ProviderType,

        /// Specific keys to push. If empty, uses scope or pushes ALL secrets.
        #[arg(num_args = 0..)]
        keys: Vec<String>,

        /// Filter by specific scopes defined in project.toml.
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,

        /// Target environment (e.g., production, preview).
        #[arg(long, short)]
        env: Option<String>,
    },

    /// Atomic Delete: Removes secrets from the Remote Provider AND Local Vault.
    Prune {
        /// The provider to prune from
        provider: ProviderType,

        /// Specific keys to remove
        #[arg(num_args = 0..)]
        keys: Vec<String>,

        /// Remove all keys belonging to a specific scope
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,

        /// Target environment
        #[arg(long, short)]
        env: Option<String>,
    }
}

#[derive(Subcommand)]
#[derive(Debug)]
pub enum ProviderAction {
    Set { name: ProviderType, token: String },
    List,
    /// Revoke a provider's authentication token (Logout)
    Revoke { name: ProviderType }, 
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
    /// Generate a new secret from a Source Provider (e.g. Resend)
    Generate { 
        provider: ProviderType, 
        #[arg(long, short)]
        env: String,
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,
    },
    /// Revoke a generated secret at the source AND locally
    Revoke {
        key: String,
        #[arg(long)]
        provider: ProviderType,
        #[arg(long, short)]
        env: String,
        
        /// Optional: Also prune this secret from a downstream target (e.g. github)
        #[arg(long)]
        prune_target: Option<ProviderType>,
    }
}