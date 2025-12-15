//! End-to-end tests for Resend as a source.
//! Requires RUN_E2E=1 and RESEND_API_KEY to be set.
//!
//! Note: Resend has a rate limit of 2 requests/second.
//! Tests include delays to avoid hitting this limit.

use crate::{
    config,
    sources::{self, GenerateOptions, SourceAdapter},
};
use anyhow::Result;
use std::env;
use std::fs;
use std::time::Duration;
use tempfile::tempdir;
use tokio::time::sleep;

/// Delay between API calls to respect Resend's rate limit (2 req/s).
const RATE_LIMIT_DELAY: Duration = Duration::from_millis(600);

// E2E: Validate a Resend API key via the source adapter.
// Skips unless RUN_E2E=1 with RESEND_API_KEY provided.
#[tokio::test]
async fn resend_source_validate_auth() -> Result<()> {
    if env::var("RUN_E2E").as_deref() != Ok("1") {
        eprintln!("skipping e2e (set RUN_E2E=1)");
        return Ok(());
    }
    let token = env::var("RESEND_API_KEY").map_err(|_| anyhow::anyhow!("set RESEND_API_KEY"))?;

    // Rate limit delay before API call
    sleep(RATE_LIMIT_DELAY).await;

    let source = sources::get(sources::Source::Resend).expect("resend source");
    let valid = source.validate_auth(&token).await?;

    assert!(valid, "API key should be valid");
    Ok(())
}

// E2E: Test API key generation and deletion.
// Creates a new API key, verifies it exists in list, then deletes it.
// Skips unless RUN_E2E=1 with RESEND_API_KEY provided.
#[tokio::test]
async fn resend_source_generate_and_revoke() -> Result<()> {
    if env::var("RUN_E2E").as_deref() != Ok("1") {
        eprintln!("skipping e2e (set RUN_E2E=1)");
        return Ok(());
    }
    let master_key =
        env::var("RESEND_API_KEY").map_err(|_| anyhow::anyhow!("set RESEND_API_KEY"))?;

    let source = sources::get(sources::Source::Resend).expect("resend source");

    // Generate a new API key with sending_access permission
    let options = GenerateOptions {
        scopes: vec!["sending_access".to_string()],
        expires_in_days: None,
        description: Some("cred-e2e-test-key".to_string()),
    };

    sleep(RATE_LIMIT_DELAY).await;
    let credential = source.generate("TEST_KEY", &master_key, &options).await?;

    // Verify the token was returned (starts with re_)
    assert!(
        credential.value.starts_with("re_"),
        "Generated token should start with re_"
    );

    // Verify we got an ID back
    let key_id = credential.id.as_ref().expect("should have id");
    assert!(!key_id.is_empty(), "ID should not be empty");

    println!("Generated API key: {}...", &credential.value[..10]);
    println!("Key ID: {}", key_id);

    // List keys and find our new one
    sleep(RATE_LIMIT_DELAY).await;
    let keys = source.list(&master_key).await?;
    let found = keys.iter().any(|k| k.contains("cred-e2e-test-key"));
    assert!(found, "Generated key should appear in list");

    // Revoke/delete the key
    sleep(RATE_LIMIT_DELAY).await;
    source.revoke(key_id, &master_key).await?;

    // Verify it's gone
    sleep(RATE_LIMIT_DELAY).await;
    let keys_after = source.list(&master_key).await?;
    let still_found = keys_after.iter().any(|k| k.contains("cred-e2e-test-key"));
    assert!(!still_found, "Key should be deleted");

    println!("Successfully generated and revoked API key");
    Ok(())
}

// E2E: Test source token storage and retrieval flow.
// Uses memory keystore, no external dependencies.
#[tokio::test]
async fn resend_source_token_storage_round_trip() -> Result<()> {
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

    let test_token = "re_test_source_token_12345";

    // Store source token
    config::set_source_token("resend", test_token)?;

    // Retrieve and verify
    let retrieved = config::get_source_token("resend")?;
    assert_eq!(
        retrieved,
        Some(test_token.to_string()),
        "retrieved token should match"
    );

    // Verify source appears in config
    let cfg = config::load()?;
    assert!(
        cfg.sources.contains_key("resend"),
        "resend should be in sources"
    );
    assert!(
        cfg.sources.get("resend").unwrap().auth_ref.is_some(),
        "auth_ref should be set"
    );

    // Remove source token
    config::remove_source_token("resend")?;

    // Verify removed
    let after_remove = config::get_source_token("resend")?;
    assert!(after_remove.is_none(), "token should be removed");

    // Verify source removed from config
    let cfg_after = config::load()?;
    assert!(
        !cfg_after.sources.contains_key("resend"),
        "resend should be removed from sources"
    );

    Ok(())
}

// E2E: List existing API keys.
// Skips unless RUN_E2E=1 with RESEND_API_KEY provided.
#[tokio::test]
async fn resend_source_list_keys() -> Result<()> {
    if env::var("RUN_E2E").as_deref() != Ok("1") {
        eprintln!("skipping e2e (set RUN_E2E=1)");
        return Ok(());
    }
    let token = env::var("RESEND_API_KEY").map_err(|_| anyhow::anyhow!("set RESEND_API_KEY"))?;

    // Rate limit delay before API call
    sleep(RATE_LIMIT_DELAY).await;

    let source = sources::get(sources::Source::Resend).expect("resend source");
    let keys = source.list(&token).await?;

    println!("Found {} API keys:", keys.len());
    for key in &keys {
        println!("  - {}", key);
    }

    // Should have at least the master key we're using
    assert!(!keys.is_empty(), "Should have at least one API key");
    Ok(())
}
