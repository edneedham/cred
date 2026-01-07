# Changelog

## v0.10.0

### New Target: Vercel

Push environment variables directly to Vercel projects:

```bash
cred target set vercel
cred push vercel
```

**Features:**

-   Auto-detects project from `.vercel/project.json` (created by `vercel link`)
-   Environment mapping: `prod` → production, `default` → development, others → preview
-   Supports `--project <id>` flag for explicit project specification

**Setup:**

1. Create an Access Token at vercel.com/account/tokens
2. Run `cred target set vercel`
3. Link your project with `vercel link` (or use `--project`)

### CLI Improvements

-   Added `--project` flag to `push` and `prune` commands for Vercel projects

## v0.9.0

### Breaking Changes

-   **Removed passphrase mode** — cred is now single-machine only

    -   Removed `cred init --passphrase`
    -   Removed `cred key status` and `cred key convert` commands
    -   Removed `CRED_PASSPHRASE` environment variable support
    -   Removed `key_mode` and `salt` fields from project.toml

-   **Removed `CRED_MASTER_KEY_B64`** — no more key injection
    -   The env var for providing the master key is removed
    -   Workflows should never run cred; they read from targets directly

### Simplified Model

cred is now explicitly for **solo developers on a single machine**:

```
Your machine              Target platform          Your workflow
 ┌─────────┐               ┌──────────────┐         ┌──────────┐
 │  cred   │──push───────►│   GitHub     │◄────────│ workflow │
 │ (vault) │               │   Secrets    │  reads  │          │
 └─────────┘               └──────────────┘         └──────────┘
```

-   Encryption key stored in OS keyring (single machine)
-   Push secrets to targets (GitHub Actions, etc.)
-   Workflows read secrets from targets directly — no cred involved

### Why This Change

The previous model implied you could run cred in CI/CD, but that didn't work:

-   vault.enc was gitignored, so it couldn't be shared
-   Committing encrypted vaults has security implications
-   The model was confusing and incomplete

The new model is honest: cred stores secrets locally and pushes to targets.

## v0.8.0

### Secret History & Rollback

-   **Version history**: Secrets now track up to 10 previous versions
-   History is preserved automatically on every update
-   Only stores history when the value actually changes

### New Commands

-   `cred secret history <key>` — View version history for a secret
-   `cred secret rollback <key> --version <N>` — Restore a previous version

### Vault Schema

-   Added `history` field to `SecretEntry` (backward compatible)
-   Existing vaults work without migration

### Example

```bash
# View history
cred secret history DATABASE_URL

# Rollback to previous version
cred secret rollback DATABASE_URL --version 0 --yes
```

## v0.7.0

> ⚠️ **Note**: Passphrase mode was removed in v0.9.0. The features below are no longer available.

### Multi-Machine Access (Removed in v0.9.0)

-   ~~Passphrase mode: Derive encryption key from passphrase using Argon2id~~
-   ~~`cred init --passphrase`, `cred key status`, `cred key convert`~~
-   ~~`CRED_PASSPHRASE` env var~~

## v0.6.0

### Breaking Changes

-   **Vault schema v3**: Secrets are now scoped to environments
-   Existing vaults auto-migrate to v3 on first load (secrets placed in "default" environment)
-   This is a one-way migration; users cannot downgrade to older cred versions after migration

### Environment Namespacing

-   `--env <ENV>` flag for secret operations: `secret set`, `secret get`, `secret list`, `secret remove`, `secret describe`
-   `--env <ENV>` flag for data operations: `push`, `prune`, `import`, `export`
-   `cred env list` — List all environments in the vault
-   `cred env create <name>` — Create a new empty environment
-   `cred env delete <name>` — Delete an environment and all its secrets (requires `--yes`)
-   `cred status` now groups secrets by environment
-   `cred secret list --env "*"` lists secrets across all environments

### New Vault API

-   `list_environments()` — List all environment names
-   `create_environment()`, `delete_environment()` — Manage environments
-   `*_in_env()` variants for all secret operations (set, get, remove, list, etc.)
-   `list_all_entries()` — List all secrets across all environments
-   `total_count()` — Count secrets across all environments

### Migration

-   **Automatic**: v1 and v2 vaults migrate transparently to v3 on load
-   **Manual**: No action required unless you want to use multiple environments
-   Migrated secrets are placed in the "default" environment

## v0.5.0

### Breaking Changes

-   **Removed `cred project status`** — This command has been consolidated into `cred status`
-   **Removed `[modified]` tracking** — The `modified` field has been removed from JSON output and the `[modified]` marker from CLI output (was never reachable in normal usage)
-   JSON output for `cred status` now includes `git_repo` field
-   JSON output for `cred push --dry-run` simplified: `will_push` now contains all keys (removed `unchanged` field)

### Enhanced Status Command

-   `cred status` now shows detected Git repository (e.g., `Git: owner/repo`)
-   JSON output includes `"git_repo": "owner/repo"` (or `null` if not in a git repo)
-   Replaces the diagnostic-focused `cred project status` with a simpler, unified view

### Internal

-   Removed `is_dirty()` and `dirty_keys()` from vault (dead code)

### Documentation

-   Reorganized command documentation structure
-   Added dedicated pages for `status` and `doctor` commands
-   Improved navigation in docs sidebar

## v0.4.0

### Sources — Programmatic Credential Generation

This release introduces **Sources**, a new architecture for programmatically generating credentials from external platforms. Unlike targets (where secrets are pushed), sources can create new API keys on demand.

#### New Commands

-   `cred source add <source>` — Authenticate with a source (store master API key)
-   `cred source list` — List configured sources
-   `cred source generate <source> <key>` — Generate a new API key and store in vault
-   `cred source keys <source>` — List API keys at the source
-   `cred source delete <source> <key>` — Delete a key at the source AND from vault
-   `cred source revoke <source>` — Revoke authentication (also deletes all generated keys)
-   `cred status` — New top-level command showing sources, secrets, and targets

#### Resend Integration

-   **First source**: Resend (email platform) with full API key lifecycle
-   Generate keys with permission levels: `full_access` or `sending_access`
-   List, delete, and revoke keys programmatically
-   Keys are tracked with `source_id` for automated cleanup

#### Vault Schema Extended

-   **New fields**: `source` (origin of secret) and `source_id` (remote ID for revocation)
-   Manual secrets default to `source: "manual"`
-   Generated secrets track their origin and remote ID

#### Architecture

-   **Hub-and-spoke model**: Sources generate credentials → Vault stores them → Targets receive them
-   Sources use master keys with broad permissions to create narrower-scoped credentials
-   Targets use minimal-permission tokens (principle of least privilege)

#### Internal

-   New `SourceAdapter` trait with `generate`, `list`, `revoke`, `validate_auth` methods
-   `GeneratedCredential` struct returns both value and remote ID
-   Source tokens stored in OS keyring alongside target tokens
-   12 new tests for source functionality

## v0.3.2

### Value Hashing Infrastructure

-   **SHA-256 hashing**: Each secret's value hash is computed and stored on save
-   Foundation for future features: undo, batch operations, merge conflict detection
-   Detects migrated v1 secrets that lack hashes (shown as modified until re-saved)

### Internal

-   Added `sha2` dependency for SHA-256 hashing
-   New vault API: `is_dirty()`, `dirty_keys()` for change detection
-   `cred secret list --json` includes `"modified"` field
-   `cred push --dry-run` distinguishes modified vs unchanged secrets
-   `cred push --dry-run` distinguishes modified vs unchanged secrets (removed in v0.5.0)

## v0.3.1

### Smart Format Detection

-   **PEM**: Auto-detected for certificates and keys (`-----BEGIN ...`)
-   **JSON**: Objects `{...}` and arrays `[...]`
-   **Base64**: Single-line base64-encoded content
-   **Multiline**: Generic multi-line text
-   **Raw**: Single-line text (default)

Format is now optional — secrets are classified automatically on save.

## v0.3.0

### Vault Schema v2

-   **Breaking**: Vault schema upgraded to v2 with per-secret metadata
-   Existing v1 vaults are automatically migrated on first load
-   Each secret now stores: `value`, `format`, `hash`, `created_at`, `updated_at`, `description`

### New Features

-   `cred secret set` now accepts `--description` (`-d`) and `--format` (`-f`) flags
-   `cred secret describe KEY "text"` command to update descriptions
-   `cred secret get --json` includes full metadata (format, timestamps, description)
-   `cred secret list --json` returns metadata for all secrets
-   `cred secret list` shows descriptions inline in plain text output
-   `cred secret remove` now shows secret age (e.g., "3 days old") when deleting

### Internal

-   Added `chrono` dependency for timestamp handling
-   New vault API: `get_entry()`, `remove_entry()`, `list_entries()`, `set_with_metadata()`, `set_description()`

## v0.2.1

-   Re-release of v0.2.0
-   Add homebrew workflow and update release pipeline

## v0.2.0

-   Added `cred import` to load `.env` files into the vault with non-destructive defaults and optional `--overwrite`.
-   Added `cred export` to write vault contents to `.env` files with overwrite guard and dry-run support.
-   Documented import/export usage and added tests for merge/overwrite/export behaviors.
-   Version bump to 0.2.0.
