[![CI and Release](https://github.com/edneedham/cred/actions/workflows/ci-cd.yml/badge.svg?branch=main)](https://github.com/edneedham/cred/actions/workflows/ci-cd.yml)
[![Crates.io](https://img.shields.io/crates/v/cred.svg)](https://crates.io/crates/cred)
[![GitHub Release](https://img.shields.io/github/v/release/edneedham/cred)](https://github.com/edneedham/cred/releases/latest)
[![Homebrew](https://img.shields.io/badge/homebrew-edneedham%2Fcred-orange)](https://github.com/edneedham/homebrew-cred)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Downloads](https://img.shields.io/github/downloads/edneedham/cred/total)](https://github.com/edneedham/cred/releases)

# cred

## What it is

`cred` stores encrypted secrets locally and safely pushes them to CI/CD platforms on demand.

⚠️ **Status: Early Preview (v0.4.0)**

`cred` is currently in active development. The on-disk format, CLI surface, and security model may change between minor versions. Do not rely on it as your sole secrets backup yet.

## What it is **not**

-   A hosted secrets manager
-   A multi-user access control system
-   A replacement for HashiCorp Vault or AWS Secrets Manager
-   A bidirectional secrets sync tool
-   A runtime secret injector for applications

## Who is this for

-   Open-source maintainers
-   Small teams
-   Solo developers
-   People who don't _need_ enterprise infrastructure yet

---

## Why cred exists

Managing secrets across projects, targets, and sources is a mess and a chore.

`cred` solves this by giving you:

### **1. A Matrix Vault per Project**

Your secrets live inside `.cred/vault.enc` as an encrypted store with per-secret metadata (format, timestamps, description, source).

### **2. Sources and Targets**

`cred` distinguishes between **sources** (where credentials come from) and **targets** (where secrets are pushed to):

-   **Sources**: Platforms that can programmatically generate credentials (e.g., Resend API keys)
-   **Targets**: Platforms where you push secrets for deployment (e.g., GitHub Actions secrets)

### **3. A global configuration store**

Metadata and preferences live in `~/.config/cred/global.toml`, while source and target tokens are stored securely in the OS credential store (keyring). Nothing sensitive is written to the TOML.

### **4. Target-agnostic secret pushing**

You manage secrets locally, but `cred` can upload them to specified targets.

#### Supported sources:

-   Resend (API key generation)

#### Supported targets:

-   GitHub (Actions secrets)

---

## Installation

### Homebrew (macOS)

```bash
brew tap edneedham/cred
brew install edneedham/cred/cred
```

### Quick install (shell)

```bash
curl -fsSL https://raw.githubusercontent.com/edneedham/cred/main/scripts/install.sh | sh -s
```

### Install with Cargo:

```bash
cargo install cred
```

### Pre-built binaries

Download the latest release for your platform from [GitHub Releases](https://github.com/edneedham/cred/releases).

Available targets:

-   `cred-vX.Y.Z-aarch64-apple-darwin` - macOS Apple Silicon
-   `cred-vX.Y.Z-x86_64-apple-darwin` - macOS Intel
-   `cred-vX.Y.Z-x86_64-unknown-linux-gnu` - Linux x86_64
-   `cred-vX.Y.Z-x86_64-pc-windows-msvc.exe` - Windows

Make the binary executable and move it to your PATH:

```bash
chmod +x cred-*
sudo mv cred-* /usr/local/bin/cred
```

Check installation:

```bash
cred --version
```

---

## Usage

It follows a simple workflow:

-   Initialize a project

-   (Optional) Add a source for credential generation

-   Add a target for secret deployment

-   Store secrets locally (manually or from a source)

-   Push secrets to the target

-   Inspect, update, or remove as needed

### 1. Initialize a Project

Run this once inside your project directory:

```bash
cred init
```

This creates a local encrypted vault in the project and binds it to the current directory.

```bash
.cred/
  project.toml
  vault.enc
```

Global configuration lives at:

```bash
~/.config/cred/global.toml
```

Check project health:

`cred doctor`

Inspect project status:

`cred project status`

Machine-readable:

`cred project status --json`

Or use the top-level status command for a hub-and-spoke view:

`cred status`

```
Vault: 3 secrets

  RESEND_API_KEY       [resend]
  DATABASE_URL         [manual]
  JWT_SECRET           [manual] [modified]

Sources: resend ✓
Targets: github ✓
```

### 2. (Optional) Add a Source (e.g. Resend)

Sources are platforms that can **programmatically generate credentials**. Unlike targets (which only receive secrets), sources create new API keys on demand.

**Add your master API key:**

`cred source add resend --token "$RESEND_API_KEY"`

Or interactively (will prompt for token):

`cred source add resend`

**Generate a new API key from the source:**

```bash
cred source generate resend RESEND_EMAIL_KEY --permission sending_access -d "Email service key"
```

This creates a new API key via Resend's API and stores it in your vault with `source: resend` metadata.

**Permission levels** (Resend-specific):

-   `full_access` — Can create, delete, get, and update any resource
-   `sending_access` — Can only send emails (recommended for most use cases)

**List API keys at the source:**

`cred source keys resend`

**Delete a generated key** (removes from source AND local vault):

`cred source delete resend RESEND_EMAIL_KEY --yes`

**List configured sources:**

`cred source list`

**Revoke source authentication** (deletes all generated keys and removes master key):

`cred source revoke resend --yes`

This will:

1. Delete all API keys generated from this source at Resend
2. Remove them from the local vault
3. Remove the stored master key

#### Why Sources Use Master Keys

Sources authenticate with a master API key that has permission to create additional keys. The generated keys can have narrower scopes (e.g., `sending_access` only), following the principle of least privilege.

### 3. Add a Target (e.g. GitHub)

Targets are platforms where you push secrets for deployment. Authenticate a deployment target:

`cred target set github`

You will be securely prompted for a token. The token is stored in your OS credential store, not in plaintext on disk.

**For GitHub targets**, create a fine-grained Personal Access Token at https://github.com/settings/tokens with only the `Actions secrets` permission for your repository.

Non-interactive (CI):

`cred target set github --token "$GITHUB_TOKEN" --non-interactive`

List configured targets:

`cred target list`

Revoke a target:

`cred target revoke github --yes`

#### Why Targets Use Simple Tokens

Targets need **minimal permissions** — just enough to write secrets. This follows the principle of least privilege.

### 4. Store Secrets Locally

Add secrets to the encrypted local vault:

`cred secret set DATABASE_URL "postgres://user:pass@localhost:5432/db"`

`cred secret set JWT_SECRET "super-secret"`

Add metadata when storing secrets:

`cred secret set API_KEY "sk-xxx" --description "OpenAI production key"`

`cred secret set CERT_PEM "-----BEGIN..." -d "TLS certificate"`

Available formats: `raw`, `multiline`, `pem`, `base64`, `json`. Format is auto-detected if omitted:

-   **PEM** — certificates and keys (`-----BEGIN ...`)
-   **JSON** — objects `{...}` and arrays `[...]`
-   **Base64** — single-line base64-encoded content
-   **Multiline** — generic multi-line text
-   **Raw** — single-line text (default)

List all stored keys:

`cred secret list`

In plain text, descriptions are shown inline:

```
Vault content:
  API_KEY = ***** (OpenAI production key)
  JWT_SECRET = *****
```

Retrieve a value:

`cred secret get JWT_SECRET`

With `--json`, metadata is included:

```json
{
    "data": {
        "key": "JWT_SECRET",
        "value": "super-secret",
        "format": "raw",
        "created_at": "2025-12-11T12:00:00Z",
        "updated_at": "2025-12-11T12:00:00Z",
        "description": null
    }
}
```

Update a secret's description:

`cred secret describe API_KEY "Updated: rotating quarterly"`

Clear a description:

`cred secret describe API_KEY`

Remove a secret locally only:

`cred secret remove JWT_SECRET --yes`

The removal output shows when the secret was created:

```
✓ Removed 'JWT_SECRET' from local vault (3 days old)
```

### 5. Import from a .env file

Import `KEY=VALUE` pairs from a .env file into the vault. Existing keys are skipped by default to keep imports non-destructive.

`cred import .env`

Overwrite existing keys if needed:

`cred import .env --overwrite`

Use `--dry-run` to see what would change without writing.

### 6. Export vault to a .env file

Write vault contents to a .env file (keys are sorted). Existing files are preserved unless forced.

`cred export .env.backup`

Overwrite an existing file explicitly:

`cred export .env --force`

Use `--dry-run` to preview how many keys would be written.

### 7. Dry Run (Preview Changes)

Before pushing anything remotely, preview what will change:

`cred push github --dry-run`

Preview specific keys:

`cred push github DATABASE_URL JWT_SECRET --dry-run`

Nothing is uploaded when --dry-run is used.

### 8. Push Secrets to a Target

Push all local secrets to GitHub:

`cred push github`

Push only specific keys:

`cred push github DATABASE_URL JWT_SECRET`

If not inside a Git repository, specify the repo explicitly:

`cred push github --repo owner/repo`

Non-interactive mode (CI):

`cred push github --non-interactive`

Machine-readable output:

`cred push github --json`

### 9. Update a Secret

Update locally:

`cred secret set JWT_SECRET "new-secret-value"`

Preview:

`cred push github --dry-run`

Apply:

`cred push github`

Only changed keys are updated remotely.

### 10. Prune (Delete from Remote)

Remove a key everywhere:

`cred prune github JWT_SECRET --yes`

Preview a prune:

`cred prune github JWT_SECRET --dry-run`

Prune all known keys from a target:

`cred prune github --all --yes`

⚠️ **Destructive operations require --yes unless in --dry-run.**

### 11. Global Configuration

View configuration:

`cred config list`

Get a value:

`cred config get preferences.default_target`

Set a value:

`cred config set preferences.default_target github`

Unset a value:

`cred config unset preferences.default_target`

### 12. AI / Automation Friendly Usage

All commands support:

--json → machine output

--non-interactive → fail instead of prompting

--dry-run → safe planning mode

Example automation pattern:

`cred push github --non-interactive --json`

Typical Workflow

```bash
cred init
cred target set github
# Enter fine-grained PAT with Actions secrets permission...

cred secret set DATABASE_URL postgres://...
cred secret set JWT_SECRET super-secret

cred push github --dry-run
cred push github
```

With Sources (Credential Generation):

```bash
cred init
cred source add resend --token "$RESEND_MASTER_KEY"
cred target set github          # Fine-grained PAT

# Generate a new API key from Resend and store in vault
cred source generate resend RESEND_API_KEY --permission sending_access

cred status                     # Shows sources, secrets, targets
cred push github                # Push to GitHub Actions
```

CI Example

```bash
cred target set github \
  --token "$CRED_GITHUB_TOKEN" \
  --non-interactive
```

`cred push github --non-interactive`

Safety Guarantees

Secrets are encrypted at rest.

Source and target tokens are stored in the OS credential store.

No secrets are written to plaintext files unless explicitly exported.

--dry-run allows safe inspection before mutation.

--json ensures reliable automation.

---

Notes:

-   `--repo` is required if no git metadata was recorded; if provided, it must match the recorded repo to prevent cross-repo mistakes.
-   Prune is remote-only; use `cred secret remove` for local deletes.

---

## License

Licensed under either of:

-   Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
-   MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your choice.
