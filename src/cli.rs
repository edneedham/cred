use clap::{Parser, Subcommand};

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
        provider: String,

        /// Specific keys to push. If empty, uses scope or pushes ALL secrets.
        #[arg(num_args = 0..)]
        keys: Vec<String>,

        /// Filter by specific scopes defined in project.toml.
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,

        /// Target environment (e.g., production, preview).
        #[arg(long, short)]
        env: Option<String>,

        /// Repository (required for GitHub)
        #[arg(long)]
        repo: Option<String>,
    },

    /// Atomic Delete: Removes secrets from the Remote Provider AND Local Vault.
    Prune {
        /// The provider to prune from
        provider: String,

        /// Specific keys to remove
        #[arg(num_args = 0..)]
        keys: Vec<String>,

        /// Remove all keys belonging to a specific scope
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,

        /// Target environment
        #[arg(long, short)]
        env: Option<String>,

        /// Repository (required for GitHub)
        #[arg(long)]
        repo: Option<String>,
    }
}

#[derive(Subcommand)]
#[derive(Debug)]
pub enum ProviderAction {
    Set { name: String, token: String },
    List,
    /// Revoke a provider's authentication token (Logout)
    Revoke { name: String }, 
}

#[derive(Subcommand)]
#[derive(Debug)]
pub enum SecretAction {
    Set { 
        key: String, 
        value: String,
        #[arg(long, short, default_value = "development")]
        env: String,
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,
    },
    Get { 
        key: String,
        #[arg(long, short, default_value = "development")]
        env: String,
    },
    List {
        #[arg(long, short)]
        env: Option<String>,
    },
    /// Remove from Local Vault ONLY (Use 'prune' for remote removal)
    Remove { 
        key: String,
        #[arg(long, short, default_value = "development")]
        env: String,
    },
    /// Generate a new secret from a Source Provider (e.g. Resend)
    Generate { 
        provider: String, 
        #[arg(long, short, default_value = "development")]
        env: String,
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,
    },
    /// Revoke a generated secret at the source AND locally
    Revoke {
        key: String,
        #[arg(long)]
        provider: String,
        #[arg(long, short, default_value = "development")]
        env: String,
        
        /// Optional: Also prune this secret from a downstream target (e.g. github)
        #[arg(long)]
        prune_target: Option<String>,
        #[arg(long)]
        repo: Option<String>,
    }
}