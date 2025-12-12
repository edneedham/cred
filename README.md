[![CI and Release](https://github.com/edneedham/cred/actions/workflows/ci-cd.yml/badge.svg?branch=main)](https://github.com/edneedham/cred/actions/workflows/ci-cd.yml)
[![Crates.io](https://img.shields.io/crates/v/cred.svg)](https://crates.io/crates/cred)
[![GitHub Release](https://img.shields.io/github/v/release/edneedham/cred)](https://github.com/edneedham/cred/releases/latest)
[![Homebrew](https://img.shields.io/badge/homebrew-edneedham%2Fcred-orange)](https://github.com/edneedham/homebrew-cred)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Downloads](https://img.shields.io/github/downloads/edneedham/cred/total)](https://github.com/edneedham/cred/releases)

# cred

## What it is

`cred` stores encrypted secrets locally and safely pushes them to CI/CD platforms on demand.

⚠️ **Status: Early Preview (v0.3.1)**

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

Your secrets live inside `.cred/vault.enc` as an encrypted store with per-secret metadata (format, timestamps, description).

### **2. A global target configuration store**

Metadata and preferences live in `~/.config/cred/global.toml`, while target tokens are stored securely in the OS credential store (keyring). Nothing sensitive is written to the TOML.

### **3. Target-agnostic secret pushing**

You manage secrets locally, but `cred` can upload them to specified targets.

#### Supported targets:

-   GitHub

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

-   Add a target

-   Store secrets locally

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

### 2. Add a Target (e.g. GitHub)

Authenticate a deployment target:

`cred target set github`

You will be securely prompted for a token. The token is stored in your OS credential store, not in plaintext on disk.

Non-interactive (CI):

`cred target set github --token "$GITHUB_TOKEN" --non-interactive`

List configured targets:

`cred target list`

Revoke a target:

`cred target revoke github`

### 3. Store Secrets Locally

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

### 4. Import from a .env file

Import `KEY=VALUE` pairs from a .env file into the vault. Existing keys are skipped by default to keep imports non-destructive.

`cred import .env`

Overwrite existing keys if needed:

`cred import .env --overwrite`

Use `--dry-run` to see what would change without writing.

### 5. Export vault to a .env file

Write vault contents to a .env file (keys are sorted). Existing files are preserved unless forced.

`cred export .env.backup`

Overwrite an existing file explicitly:

`cred export .env --force`

Use `--dry-run` to preview how many keys would be written.

### 6. Dry Run (Preview Changes)

Before pushing anything remotely, preview what will change:

`cred push github --dry-run`

Preview specific keys:

`cred push github DATABASE_URL JWT_SECRET --dry-run`

Nothing is uploaded when --dry-run is used.

### 7. Push Secrets to a Target

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

### 8. Update a Secret

Update locally:

`cred secret set JWT_SECRET "new-secret-value"`

Preview:

`cred push github --dry-run`

Apply:

`cred push github`

Only changed keys are updated remotely.

### 9. Prune (Delete Locally and Remotely)

Remove a key everywhere:

`cred prune github JWT_SECRET --yes`

Preview a prune:

`cred prune github JWT_SECRET --dry-run`

Prune all known keys from a target:

`cred prune github --all --yes`

⚠️ **Destructive operations require --yes unless in --dry-run.**

### 10. Global Configuration

View configuration:

`cred config list`

Get a value:

`cred config get preferences.default_target`

Set a value:

`cred config set preferences.default_target github`

Unset a value:

`cred config unset preferences.default_target`

### 11. AI / Automation Friendly Usage

All commands support:

--json → machine output

--non-interactive → fail instead of prompting

--dry-run → safe planning mode

Example automation pattern:

`cred push github --non-interactive --json`

Typical Workflow

`cred init`
`cred target set github`
`# displays an auth token prompt...`

`cred secret set DATABASE_URL postgres://...`
`cred secret set JWT_SECRET super-secret`

`cred push github --dry-run`
`cred push github`

CI Example

```bash
cred target set github \
  --token "$CRED_GITHUB_TOKEN" \
  --non-interactive
```

`cred push github --non-interactive`

Safety Guarantees

Secrets are encrypted at rest.

Target tokens are stored in the OS credential store.

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
