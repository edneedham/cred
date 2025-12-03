# cred

`cred` is a local-first credential manager that lets you create, store, and manage secrets on your machine — and then push them directly to the platforms that need them for deployment or CI/CD.

I wanted something consistent for handling `.env` variables, API keys, PEM files, and provider-specific secrets. I think this is it.

---

## Why cred exists

Managing secrets across projects and providers is a mess.

Every platform has different rules for how it parses `.env`, how it handles multiline secrets, and how you upload them. Debugging why something worked locally but broke in CI/CD is tedious and error-prone.

`cred` solves this by giving you:

### **1. A Matrix Vault per Project**
Your secrets live inside `.cred/vault.json`. Unlike a flat `.env` file, `cred` stores secrets in a structured matrix:
```json
{
  "development": { "DB_URL": "localhost:5432" },
  "production":  { "DB_URL": "db.aws.com" }
}
```

### **2. Scoped Grouping (Monorepo Ready)

You can tag secrets into Scopes (e.g., backend, frontend, worker). This allows you to push only specific subsets of secrets to specific providers without splitting your project.

### **2. A global provider authentication vault**

Stored once at:

```
~/.config/cred/global.toml
```

This keeps your provider login tokens separate from project secrets.

### **3. Provider-agnostic secret pushing**

You manage secrets locally, but `cred` can upload them to:

* GitHub (Actions secrets)
* Vercel
* Cloudflare
* Supabase
* Fly.io
* Resend
* (and more via providers)

Use:

```bash
cred push <provider>
```

This makes your CI/CD pipelines simple because the secrets already exist exactly where the provider expects them.

### **4. Automatic secret generation**

Some providers (like Resend, Cloudflare, Supabase) allow API-driven key creation.
`cred` can request and store these keys for you.

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

* Create `.cred/` in the current directory (if none found in parent directories)
* Create `.cred/project.toml`
* Create `.cred/vault.enc`
* Verify your global vault at `~/.config/cred/global.toml`
* Automatically add `.cred/` to `.gitignore`

Example output:

```
Initialized new cred project at ./ .cred
Global vault located at ~/.config/cred/global.toml
```

---

## Global provider authentication

Before you can push secrets, authenticate the providers you want to use:

```bash
cred provider set cloudflare CF_API_TOKEN=abcd1234
cred provider set vercel VERCEL_TOKEN=xyz789
cred provider set github GH_TOKEN=ghp_123...
```

These live in your global.toml — never inside projects.

And to remove unused providers:

```bash
cred provider remove github
```

---

## Managing local project secrets

Secrets are always associated with an *Environment* (defaults to development)

### Set a secret for development:

```bash
cred secret set DATABASE_URL postgres://localhost:5432/db
```
### Set a secret for production:

```bash
cred secret set DATABASE_URL postgres://prod-db.aws.com/db --env production
```

### Set a secret and assign it to Scopes (Groups):

You can assign a secret to multiple scopes at creation time.

```bash
cred secret set STRIPE_KEY sk_live_123 --env production --scope backend --scope worker
```

* Adds secret to the `production` vault.
* Updates `project.toml` to list `STRIPE_KEY` under `[scopes.backend]` and `[scopes.worker]`.

### List all secrets

```bash
cred secret list
```

### List specific environment secrets

```bash
cred secret list --env production
```

### List specific scope secrets

```bash
cred secret list --scope backend
```

### Remove a secret

```bash
cred secret remove DATABASE_URL
```

### Generate a secret using a provider API (defaults to `development`)

```bash
cred secret generate resend --env production
```

## Security Model

All sensitive project secrets are encrypted at rest, never stored in plaintext on disk, and only decrypted in memory when required. There is no central server, no accounts, and no remote storage owned by cred.

### What is encrypted

All project secrets (API keys, environment variables, PEM files, tokens, certificates, etc.) are stored in an encrypted local vault:

```bash
.cred/vault.enc
```

### Encryption properties

* Algorithm: ChaCha20-Poly1305 (authenticated encryption)
* Key size: 256-bit
* Nonce: Random per write
* Plaintext secrets: Exist *only in memory*
* At-rest storage: Always encrypted
* Integrity protected: Tampering with the vault is detected

Therefore, even if someone steals your project folder, repository, backups, or filesystem snapshot, they *cannot read your secrets* without access to your local encryption key.

*** Where the encryption key is stored
By default, the encryption key is stored in your operating system’s secure key store:

* macOS: Keychain
* Windows: Credential Manager
* Linux: Secret Service (libsecret)

This provides:

* Hardware-backed protection on many systems
* OS-level access control
* No plaintext keys on disk
* No passwords to remember

This is the same security model used by:

* Git credential helpers
* VS Code secret storage
* Docker credentials
* Chrome / browser password managers

---

## Pushing secrets to providers (CI/CD ready)

This is the core purpose of `cred`.

### Push to Vercel:

```bash
cred push vercel
```

Push to GitHub (for Actions):

```bash
cred push github --repo myuser/myrepo
```

Push to Cloudflare:

```bash
cred push cloudflare
```

Push to Supabase:

```bash
cred push supabase
```

These commands:

1. Read your local `.cred/vault.json`
2. Transform formats required by provider
3. Upload secrets using the provider API
4. Validate the result

No more manually creating secrets via platform dashboards.

## Removing secrets from providers

Mistakes and changes happen.

### Remove all secrets from a provider

```bash
cred remove <provider>
```

### Remove a single secret from a provider

```bash
cred remove <provider> <key>
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

* A stable vault format
* Reliable provider authentication
* Universal secret push flows
* Consistent `.env` and PEM handling across platforms

