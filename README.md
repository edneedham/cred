# cred

`cred` is a local-first credential manager that lets you create, store, and manage secrets on your machine — and then push them directly to the platforms that need them for deployment or CI/CD.

It gives you one consistent workflow for handling `.env` variables, API keys, PEM files, and provider-specific secrets without relying on half-baked UI dashboards or inconsistent CLIs.

---

## Why cred exists

Managing secrets across projects and providers is a mess.

Every platform has different rules for how it parses `.env`, how it handles multiline secrets, and how you upload them. Debugging why something worked locally but broke in CI/CD is tedious and error-prone.

`cred` solves this by giving you:

### **1. A local encrypted vault per project**

Your secrets live inside a `.cred/` directory within your project.
This guarantees consistent formatting and parsing locally.

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

---

## Managing local project secrets

Secrets are always associated with an *Environment* (defaults to development)

### Add or update a secret for development:

```bash
cred secret set DATABASE_URL postgres://localhost:5432/db
```
### Add or update a secret for production:

```bash
cred secret set DATABASE_URL postgres://prod-db.aws.com/db --env production
```

### Add or update a secret and assign it to a Scope:

```bash
cred secret set STRIPE_KEY sk_live_123 --env production --scope backend
```

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

### Generate a secret using a provider API

```bash
cred secret generate resend production
```

This creates:

```
RESEND_API_KEY=mynewresendkey
```

and saves it to your project vault.

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

