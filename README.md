# cred

`cred` is a local-first credential manager that lets you create, store, and manage secrets on your machine — and then push them directly to the platforms that need them for deployment or CI/CD.

I wanted something consistent for handling `.env` variables, API keys, PEM files, and target-specific secrets etc.. I think this is it.

## Who is this for

-   Open-source maintainers
-   Small teams
-   Solo developers
-   People who don't _need_ enterprise infrastructure yet

---

A Target consumes secrets; a Source produces secrets. They are never the same abstraction.

## Why cred exists

Managing secrets across projects, targets, and sources is a mess.

Every platform has different rules for how it parses `.env`, how it handles multiline secrets, and how you upload them. Debugging why something worked locally but broke in CI/CD is tedious and error-prone.

`cred` solves this by giving you:

### **1. A Matrix Vault per Project**

Your secrets live inside `.cred/vault.enc` as an encrypted flat key/value store.

### **2. A global target authentication vault**

Stored once at:

```
~/.config/cred/global.toml
```

This keeps your target login tokens separate from project secrets.

### **3. Target-agnostic secret pushing**

You manage secrets locally, but `cred` can upload them to:

-   GitHub (Actions secrets)

With new targets to be added.

Use:

```bash
cred push <target>
```

This makes your CI/CD pipelines simple because the secrets already exist exactly where the target expects them.

### **4. Automatic secret generation**

Some sources (planned) allow API-driven key creation. Future `cred` releases can request and store these keys for you.

### **5. One workflow instead of five**

No more juggling different CLIs and UI dashboards.
No more breaking `.env` formats across platforms.
No more encoding keys manually.

---

## Installation

Install with Cargo:

```bash
cargo install cred
```

Check installation:

```bash
cred --version
```

---

## Usage

### Initialize a new project

```bash
cred init
```

This will:

-   Create `.cred/` in the current directory (if none found in parent directories)
-   Create `.cred/project.toml`
-   Create `.cred/vault.enc`
-   Verify your global vault at `~/.config/cred/global.toml`
-   Automatically add `.cred/` to `.gitignore`

Example output:

```
Initialized new cred project at ./ .cred
Global vault located at ~/.config/cred/global.toml
```

---

## Global target authentication

Before you can push secrets, authenticate the targets you want to use:

```bash
cred target set github --token GH_TOKEN=ghp_123...
```

Tokens live in your global.toml — never inside projects. If you omit `--token`, `cred` will securely prompt for it.

And to remove unused targets:

```bash
cred target revoke github
```

---

## Managing local project secrets

All secrets live in a single encrypted key/value store.

### Set a secret

```bash
cred secret set DATABASE_URL postgres://localhost:5432/db
```

### List all secrets

```bash
cred secret list
```

### Remove a secret

```bash
cred secret remove DATABASE_URL
```

## Security Model

All sensitive project secrets are encrypted at rest, never stored in plaintext on disk, and only decrypted in memory when required. There is no central server, no accounts, and no remote storage owned by cred.

### What is encrypted

All project secrets (API keys, environment variables, PEM files, tokens, certificates, etc.) are stored in an encrypted local vault:

```bash
.cred/vault.enc
```

### Encryption properties

-   Algorithm: ChaCha20-Poly1305 (authenticated encryption)
-   Key size: 256-bit
-   Nonce: Random per write
-   Plaintext secrets: Exist **only in memory**
-   At-rest storage: Always encrypted
-   Integrity protected: Tampering with the vault is detected

Therefore, even if someone steals your project folder, repository, backups, or filesystem snapshot, they **cannot read your secrets** without access to your local encryption key.

\*\*\* Where the encryption key is stored
By default, the encryption key is stored in your operating system’s secure key store:

-   macOS: Keychain
-   Windows: Credential Manager
-   Linux: Secret Service (libsecret)

This provides:

-   Hardware-backed protection on many systems
-   OS-level access control
-   No plaintext keys on disk
-   No passwords to remember

This is the same security model used by:

-   Git credential helpers
-   VS Code secret storage
-   Docker credentials
-   Chrome / browser password managers

---

## Pushing secrets to targets (CI/CD ready)

This is the core purpose of `cred`.

Push to GitHub (for Actions):

```bash
cred push github
```

Push specific keys only:

```bash
cred push github API_URL API_KEY
```

These commands read your local `.cred/vault.enc`, transform formats required by the target, upload secrets using the target API, and validate the result. No more manually creating secrets via platform dashboards.

## Removing secrets from targets

Mistakes and changes happen.

### Remove all secrets from a target

```bash
cred prune <target> KEY1 KEY2
```

### Remove a single secret from a target

```bash
cred prune <target> <key>
```

---

## Project structure

Once initialized:

```
.cred/
  project.toml
  vault.json
```

Global configuration lives at:

```
~/.config/cred/global.toml
```

---

## Status

`cred` is under active development. The `1.0` milestone focuses on:

-   A stable vault format
-   Reliable target authentication
-   Universal secret push flows
-   Consistent secret handling across platforms
