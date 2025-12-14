//! End-to-end tests for GitHub as a source.
//! Requires RUN_E2E=1 and various GitHub credentials to be set.

use crate::{
    config,
    sources::{self, SourceAdapter, github::GithubSource},
};
use anyhow::Result;
use std::env;
use std::fs;
use tempfile::tempdir;

// E2E: Validate a GitHub PAT via the source adapter.
// Skips unless RUN_E2E=1 with GITHUB_PAT provided.
#[tokio::test]
async fn github_source_validate_auth() -> Result<()> {
    if env::var("RUN_E2E").as_deref() != Ok("1") {
        eprintln!("skipping e2e (set RUN_E2E=1)");
        return Ok(());
    }
    let token = env::var("GITHUB_PAT").map_err(|_| anyhow::anyhow!("set GITHUB_PAT"))?;

    let source = sources::get(sources::Source::Github).expect("github source");
    let valid = source.validate_auth(&token).await?;

    assert!(valid, "PAT should be valid");
    Ok(())
}

// E2E: Test device flow initiation returns valid user code.
// This only tests the first step - actual completion requires human action.
// Skips unless RUN_E2E=1 with GITHUB_OAUTH_CLIENT_ID provided.
#[tokio::test]
async fn github_source_device_flow_initiation() -> Result<()> {
    if env::var("RUN_E2E").as_deref() != Ok("1") {
        eprintln!("skipping e2e (set RUN_E2E=1)");
        return Ok(());
    }

    let client_id = match env::var("GITHUB_OAUTH_CLIENT_ID") {
        Ok(id) => id,
        Err(_) => {
            eprintln!("skipping device flow test (set GITHUB_OAUTH_CLIENT_ID)");
            return Ok(());
        }
    };

    let scopes = vec!["read:user".to_string()];
    let (state, device_code) =
        GithubSource::initiate_device_flow(Some(&client_id), &scopes).await?;

    // Verify we got valid response data
    assert!(!state.user_code.is_empty(), "user_code should not be empty");
    assert!(
        !state.verification_uri.is_empty(),
        "verification_uri should not be empty"
    );
    assert!(!device_code.is_empty(), "device_code should not be empty");
    assert!(state.expires_in > 0, "expires_in should be positive");

    // Verify URL is the expected GitHub verification endpoint
    assert!(
        state.verification_uri.contains("github.com"),
        "verification_uri should be a GitHub URL"
    );

    println!("Device flow initiated successfully:");
    println!("  User code: {}", state.user_code);
    println!("  Verify at: {}", state.verification_uri);
    println!("  Expires in: {}s", state.expires_in);

    Ok(())
}

// E2E: Test source token storage and retrieval flow.
// Uses memory keystore, no external dependencies.
#[tokio::test]
async fn github_source_token_storage_round_trip() -> Result<()> {
    if env::var("RUN_E2E").as_deref() != Ok("1") {
        eprintln!("skipping e2e (set RUN_E2E=1)");
        return Ok(());
    }

    // Isolate config
    let tmp = tempdir()?;
    let tmp_path = tmp.path().to_path_buf();
    fs::create_dir_all(tmp_path.join("home/.config"))?;

    unsafe {
        env::set_var("CRED_KEYSTORE", "memory");
        env::set_var("HOME", tmp_path.join("home"));
        env::set_var("XDG_CONFIG_HOME", tmp_path.join("home/.config"));
    }

    let test_token = "ghp_test_source_token_12345";

    // Store source token
    config::set_source_token("github", test_token)?;

    // Retrieve and verify
    let retrieved = config::get_source_token("github")?;
    assert_eq!(
        retrieved,
        Some(test_token.to_string()),
        "retrieved token should match"
    );

    // Verify source appears in config
    let cfg = config::load()?;
    assert!(
        cfg.sources.contains_key("github"),
        "github should be in sources"
    );
    assert!(
        cfg.sources.get("github").unwrap().auth_ref.is_some(),
        "auth_ref should be set"
    );

    // Remove source token
    config::remove_source_token("github")?;

    // Verify removed
    let after_remove = config::get_source_token("github")?;
    assert!(after_remove.is_none(), "token should be removed");

    // Verify source removed from config
    let cfg_after = config::load()?;
    assert!(
        !cfg_after.sources.contains_key("github"),
        "github should be removed from sources"
    );

    Ok(())
}

// E2E: Full round trip - store token, validate it, then clean up.
// Combines storage with actual GitHub API validation.
#[tokio::test]
async fn github_source_full_round_trip() -> Result<()> {
    if env::var("RUN_E2E").as_deref() != Ok("1") {
        eprintln!("skipping e2e (set RUN_E2E=1)");
        return Ok(());
    }
    let token = env::var("GITHUB_PAT").map_err(|_| anyhow::anyhow!("set GITHUB_PAT"))?;

    // Isolate config
    let tmp = tempdir()?;
    let tmp_path = tmp.path().to_path_buf();
    fs::create_dir_all(tmp_path.join("home/.config"))?;

    unsafe {
        env::set_var("CRED_KEYSTORE", "memory");
        env::set_var("HOME", tmp_path.join("home"));
        env::set_var("XDG_CONFIG_HOME", tmp_path.join("home/.config"));
    }

    // 1. Store the token as if user ran `cred source add github`
    config::set_source_token("github", &token)?;

    // 2. Retrieve it
    let stored_token = config::get_source_token("github")?.expect("token should exist");

    // 3. Validate it against GitHub API
    let source = sources::get(sources::Source::Github).expect("github source");
    let valid = source.validate_auth(&stored_token).await?;
    assert!(valid, "stored PAT should be valid");

    // 4. Clean up
    config::remove_source_token("github")?;

    Ok(())
}
