use crate::cli::CliFlags;
use crate::error::AppError;
use anyhow::{self, Context};
use rpassword::prompt_password;

pub fn require_yes(flags: &CliFlags, action: &str) -> Result<(), AppError> {
    if !flags.yes {
        return Err(AppError::user(anyhow::anyhow!(
            "{} is destructive; rerun with --yes",
            action
        )));
    }
    Ok(())
}

pub fn print_out(flags: &CliFlags, msg: &str) {
    if !flags.json && !flags.no_color {
        println!("{}", msg);
    } else if !flags.json {
        println!("{}", msg);
    }
}

pub fn print_plain(msg: &str) {
    println!("{}", msg);
}

pub fn print_plain_err(msg: &str) {
    eprintln!("{}", msg);
}

pub fn print_json(payload: &serde_json::Value) {
    print_plain(&serde_json::to_string(payload).unwrap_or_default());
}

pub fn print_err(flags: &CliFlags, msg: &str) {
    if !flags.json && !flags.no_color {
        eprintln!("{}", msg);
    } else if !flags.json {
        eprintln!("{}", msg);
    }
}

pub fn read_token_securely(
    maybe_token: Option<String>,
    flags: &CliFlags,
) -> Result<String, AppError> {
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
