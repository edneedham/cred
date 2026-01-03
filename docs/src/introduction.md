# Introduction

## What it is

**`cred`** is a command-line tool that stores encrypted secrets locally and safely pushes them to target platforms on demand. 

⚠️ **Status: Early Preview (v0.7.0)**

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

### **4. Target-specific secret pushing**

You manage secrets locally, but `cred` can upload them to specified targets.

#### Supported sources:

-   Resend (API key generation)

#### Supported targets:

-   GitHub (Actions secrets)