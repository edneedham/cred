use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cred")]
#[command(about = "The easy way to manage your credentials, remotely and locally", long_about = None)]
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

        /// Optional flags (like --repo for github)
        #[arg(long)]
        repo: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ProviderAction {
    Set { name: String, token: String },
    List,
}

#[derive(Subcommand, Debug)]
pub enum SecretAction {
    Set { key: String, value: String },
    Get { key: String },
    List,
    Remove { key: String },
    Generate { provider: String, env: String },
}