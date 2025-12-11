# Changelog

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
