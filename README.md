[![CI](https://github.com/edneedham/cred/actions/workflows/ci-cd.yml/badge.svg?branch=main)](https://github.com/edneedham/cred/actions/workflows/ci-cd.yml)
[![Crates.io](https://img.shields.io/crates/v/cred.svg)](https://crates.io/crates/cred)
[![GitHub Release](https://img.shields.io/github/v/release/edneedham/cred)](https://github.com/edneedham/cred/releases/latest)
[![Homebrew](https://img.shields.io/badge/homebrew-edneedham%2Fcred-orange)](https://github.com/edneedham/homebrew-cred)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Downloads](https://img.shields.io/github/downloads/edneedham/cred/total)](https://github.com/edneedham/cred/releases)

# cred

Encrypted local secrets → Deployment platforms.

📖 **[Full Documentation](https://edneedham.github.io/cred/)**

---

## What it is

`cred` stores encrypted secrets locally and safely pushes them to target platforms on demand.

⚠️ **Status: Early Preview (v0.12.3)** — The on-disk format, CLI surface, and security model may change between minor versions.

### What it's not

-   A hosted secrets manager
-   A multi-user access control system
-   A replacement for HashiCorp Vault or AWS Secrets Manager
-   A runtime secret injector

### Who it's for

-   **Solo developers** managing secrets on a single machine
-   Open-source maintainers who push secrets to deployment platforms
-   Anyone who wants local-first secrets without running infrastructure

---

## Install

**Homebrew:**

```bash
brew tap edneedham/cred
brew install edneedham/cred/cred
```

**Shell:**

```bash
curl -fsSL https://raw.githubusercontent.com/edneedham/cred/main/scripts/install.sh | sh -s
```

**Cargo:**

```bash
cargo install cred
```

**Pre-built binaries:** [GitHub Releases](https://github.com/edneedham/cred/releases)

---

## Quick Start

```bash
# Initialize a project
cred init

# Add a target (GitHub Actions)
cred target set github

# Store a secret
cred secret set DATABASE_URL "postgres://..."

# Push to GitHub
cred push github
```

See the [Getting Started guide](https://edneedham.github.io/cred/getting-started.html) for more.

---

## Features

-   **Encrypted vault** — Secrets stored locally with ChaCha20-Poly1305
-   **Environments** — Organize secrets by context (dev, staging, prod)
-   **Version history** — Track changes, rollback to previous versions
-   **Sources** — Generate credentials from APIs (Resend)
-   **Targets** — Push secrets to deployment platforms (GitHub Actions, Vercel, Fly.io)
-   **OS keyring** — Tokens stored in macOS Keychain, GNOME Keyring, or Windows Credential Manager
-   **Automation-ready** — `--json`, `--dry-run`, `--non-interactive` flags

---

## Documentation

-   [Installation](https://edneedham.github.io/cred/installation.html)
-   [Getting Started](https://edneedham.github.io/cred/getting-started.html)
-   [Commands Reference](https://edneedham.github.io/cred/commands/)
-   [Security Model](https://edneedham.github.io/cred/security.html)

---

## License

Licensed under either of:

-   Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
-   MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your choice.
