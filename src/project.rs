use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};

pub struct Project {
    pub root: PathBuf,
    pub vault_path: PathBuf,
}

impl Project {
    /// Recursively searches for the .cred directory starting from PWD up to root.
    pub fn find() -> Result<Self> {
        let current_dir = env::current_dir().context("Failed to get current directory")?;

        for ancestor in current_dir.ancestors() {
            let cred_dir = ancestor.join(".cred");
            if cred_dir.exists() && cred_dir.is_dir() {
                return Ok(Project {
                    root: ancestor.to_path_buf(),
                    vault_path: cred_dir.join("vault.json"),
                });
            }
        }

        bail!("No .cred directory found. Run 'cred init' to start.")
    }
}

/// Public entry point: Initialize in current directory.
pub fn init() -> Result<()> {
    let current_dir = env::current_dir().context("Failed to get current directory")?;
    init_at(&current_dir)
}

/// Internal testable logic
pub(crate) fn init_at(root: &Path) -> Result<()> {
    let cred_dir = root.join(".cred");

    if cred_dir.exists() {
        bail!("Cred is already initialized here: {}", cred_dir.display());
    }

    // 1. Create .cred directory
    fs::create_dir(&cred_dir).context("Failed to create .cred directory")?;

    // 2. Create project.toml
    let project_toml = r#"# Cred Project Configuration
name = "my-project"
version = "0.1.0"
"#;
    fs::write(cred_dir.join("project.toml"), project_toml)
        .context("Failed to create project.toml")?;

    // 3. Create empty vault
    fs::write(cred_dir.join("vault.json"), "{}")
        .context("Failed to create vault.json")?;

    // 4. Update .gitignore
    update_gitignore(root)?;

    println!("Initialized new cred project at {}", cred_dir.display());
    Ok(())
}

fn update_gitignore(root: &Path) -> Result<()> {
    let gitignore = root.join(".gitignore");
    let entry = "\n.cred/\n";

    let mut file = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(&gitignore)
        .context("Failed to open or create .gitignore")?;

    // Simple check to avoid duplicate appending if file existed
    if let Ok(content) = fs::read_to_string(&gitignore) {
        if !content.contains(".cred/") {
            writeln!(file, "{}", entry)?;
            println!("Added .cred/ to .gitignore");
        }
    } else {
        writeln!(file, "{}", entry)?;
    }

    Ok(())
}