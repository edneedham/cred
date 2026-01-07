# Introduction

## What it is

**`cred`** is a command-line tool that stores encrypted secrets locally and pushes them to deployment platforms on demand.

⚠️ **Status: Early Preview (v0.11.0)**

`cred` is currently in active development. The on-disk format, CLI surface, and security model may change between minor versions. Do not rely on it as your sole secrets backup yet.

## What it is **not**

-   A hosted secrets manager
-   A multi-user or multi-machine tool
-   A replacement for HashiCorp Vault or AWS Secrets Manager
-   A runtime secret injector for applications

## Who is this for

-   **Solo developers** managing secrets on a single machine
-   Open-source maintainers who push secrets to deployment platforms
-   Anyone who wants local-first secrets without running infrastructure

## Why cred exists

Managing secrets across projects and deployment platforms is a mess and a chore.

`cred` solves this by giving you:

### **1. An Encrypted Vault per Project**

Your secrets live inside `.cred/vault.enc` as an encrypted store with per-secret metadata (format, timestamps, description, source, version history).

### **2. Environment Namespacing**

Organize secrets by deployment context:

```bash
cred env create prod
cred secret set DATABASE_URL "postgres://prod..." --env prod
cred push github --env prod
```

### **3. Version History & Rollback**

Every secret update is tracked. Roll back to any of the last 10 versions:

```bash
cred secret history API_KEY
cred secret rollback API_KEY --version 0 --yes
```

### **4. Sources and Targets**

`cred` distinguishes between **sources** (where credentials come from) and **targets** (where secrets are pushed to):

-   **Sources**: Platforms that can programmatically generate credentials (e.g., Resend API keys)
-   **Targets**: Platforms where you push secrets for deployment (e.g., GitHub Actions secrets)

### **5. Secure Key Storage**

Your encryption key is stored in your OS credential store (Keychain, GNOME Keyring, Windows Credential Manager). Nothing sensitive is written to plaintext files.

#### Supported sources:

-   Resend (API key generation)

#### Supported targets:

-   GitHub (Actions secrets)
-   Vercel (Environment variables)
