use anyhow::{bail, Result};
use cred::{project, targets::{self, TargetAdapter}, vault};
use reqwest::Client;
use std::collections::HashMap;
use std::env;
use std::fs;
use tempfile::tempdir;

const UA: &str = "cred-e2e";

// End-to-end GitHub target flow: set secrets locally, push, verify via API, then prune.
// Skips unless RUN_E2E=1 with GITHUB_PAT and E2E_GITHUB_REPO provided.
#[tokio::test]
async fn github_push_and_prune_round_trip() -> Result<()> {
    if env::var("RUN_E2E").as_deref() != Ok("1") {
        eprintln!("skipping e2e (set RUN_E2E=1)");
        return Ok(());
    }
    let token = env::var("GITHUB_PAT").map_err(|_| anyhow::anyhow!("set GITHUB_PAT"))?;
    let full_repo = env::var("E2E_GITHUB_REPO")
        .map_err(|_| anyhow::anyhow!("set E2E_GITHUB_REPO=owner/cred-test"))?;

    let client = Client::new();

    // Isolate config/home
    let tmp = tempdir()?;
    let tmp_path = tmp.path().to_path_buf();
    fs::create_dir_all(tmp_path.join("home/.config")).unwrap();
    unsafe {
        env::set_var("CRED_KEYSTORE", "memory");
        env::set_var("CRED_MASTER_KEY_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        env::set_var("HOME", tmp_path.join("home"));
        env::set_var("XDG_CONFIG_HOME", tmp_path.join("home/.config"));
    }
    env::set_current_dir(&tmp_path)?;
    project::init()?;

    let proj = project::Project::find()?;
    let key = proj.get_master_key()?;
    let mut v = vault::Vault::load(&proj.vault_path, key)?;
    v.set("E2E_ALPHA", "alpha");
    v.set("E2E_BETA", "beta");
    v.save()?;

    let secrets: HashMap<String, String> = v.list().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let gh = targets::get(targets::Target::Github).expect("github target");
    let opts = targets::PushOptions { repo: Some(full_repo.clone()) };

    gh.push(&secrets, &token, &opts).await?;
    assert_secret_exists(&client, &token, &full_repo, "E2E_ALPHA").await?;
    gh.delete(&vec!["E2E_ALPHA".into(), "E2E_BETA".into()], &token, &opts).await?;
    assert_secret_absent(&client, &token, &full_repo, "E2E_ALPHA").await?;
    Ok(())
}

// Assert secret exists remotely using GitHub Actions secrets API.
async fn assert_secret_exists(client: &Client, token: &str, repo: &str, name: &str) -> Result<()> {
    let url = format!("https://api.github.com/repos/{}/actions/secrets/{}", repo, name);
    let resp = client.get(url)
        .header("User-Agent", UA)
        .bearer_auth(token)
        .send().await?;
    if !resp.status().is_success() {
        bail!("secret {} not found (status {})", name, resp.status());
    }
    Ok(())
}

// Assert secret is absent remotely; success means 404/410 or non-success status.
async fn assert_secret_absent(client: &Client, token: &str, repo: &str, name: &str) -> Result<()> {
    let url = format!("https://api.github.com/repos/{}/actions/secrets/{}", repo, name);
    let resp = client.get(url)
        .header("User-Agent", UA)
        .bearer_auth(token)
        .send().await?;
    if resp.status().is_success() {
        bail!("secret {} still present", name);
    }
    Ok(())
}