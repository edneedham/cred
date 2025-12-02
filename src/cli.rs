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

    /// Push secrets to a remote provider
    Push {
        /// The provider to push to (github, vercel, etc.)
        provider: String,

        /// Optional: Specific keys to push. If empty, uses scope or pushes ALL secrets.
        #[arg(num_args = 0..)]
        keys: Vec<String>,

        /// Filter by specific scopes defined in project.toml.
        /// Usage: --scope backend --scope frontend
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,

        /// Target environment (e.g., production, preview, development).
        /// If omitted, cred pushes ALL environments found in the vault.
        #[arg(long, short)]
        env: Option<String>,

        /// Repository (required for GitHub)
        #[arg(long)]
        repo: Option<String>,
    },
    Prune {
        /// The provider to prune from (github, vercel, etc.)
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
    // Remove a provider's auth token from global config
    Remove { name: String }
}

#[derive(Subcommand)]
#[derive(Debug)]
pub enum SecretAction {
    Set { 
        key: String, 
        value: String,
        /// The environment to store this secret in
        #[arg(long, short, default_value = "development")]
        env: String,
        
        /// Add this secret to specific scopes in project.toml automatically
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,
    },
    Get { 
        key: String,
        #[arg(long, short, default_value = "development")]
        env: String,
    },
    List {
        /// If provided, lists only secrets for this environment
        #[arg(long, short)]
        env: Option<String>,
    },
    Remove { 
        key: String,
        #[arg(long, short, default_value = "development")]
        env: String,
    },
    Generate { 
        provider: String, 
        env: String,
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,
    },
}