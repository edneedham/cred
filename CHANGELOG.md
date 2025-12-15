# Changelog

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
-   `cred project status` includes `dirty_count`

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
