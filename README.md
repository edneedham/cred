# cred

## What it is

`cred` stores encrypted secrets locally and safely syncs them to CI/CD platforms on demand.

⚠️ **Status: Early Preview (v0.1.0)**

`cred` is currently in active development. The on-disk format, CLI surface, and security model may change between minor versions. Do not rely on it as your sole secrets backup yet.

## What it is **not**

- A hosted secrets manager
- A multi-user access control system
- A replacement for HashiCorp Vault or AWS Secrets Manager
- A bidirectional secrets sync tool
- A runtime secret injector for applications

It is a **developer-side deployment tool** for managing and pushing secrets safely.

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

Your secrets live inside `.cred/vault.enc` as an encrypted flat key/value store.

### **2. A global target configuration store**

Metadata and preferences live in `~/.config/cred/global.toml`, while target tokens are stored securely in the OS credential store (keyring). Nothing sensitive is written to the TOML.

### **3. Target-agnostic secret pushing**

You manage secrets locally, but `cred` can upload them to specified targets.

#### Supported targets:

- GitHub Actions (repository secrets)
- Vercel (planned)
- Fly.io (planned)
- AWS / Azure (future)

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

-   Creates `.cred/`, `project.toml`, `vault.enc`, and registers a project ID in your OS keychain.
-   If run inside a git repo, records `git_root` and normalized `git_repo` (`owner/name`) for safety checks.
-   If not in git, init still succeeds but will warn you; later GitHub push/prune requires `--repo owner/name`.

### Global target authentication

Set a token (GitHub v0.1.0):

```bash
cred target set github --token example-token
```

-   If `--token` is omitted, you’ll be prompted securely (no echo/history).

List configured targets:

```bash
cred target list
```

Revoke token:

```bash
cred target revoke github
```

Tokens are stored in the OS credential store under an internal `auth_ref`; `global.toml` keeps only references/metadata.

### Manage configuration (non-secret)

```bash
cred config set preferences.default_target github
cred config set preferences.confirm_destructive true
cred config get preferences.default_target
cred config list
```

### Manage local secrets (flat key/value)

Set:

```bash
cred secret set DATABASE_URL postgres://localhost:5432/db
```

Get:

```bash
cred secret get DATABASE_URL
```

List:

```bash
cred secret list
```

Remove locally (does NOT touch remote):

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

Therefore, if someone steals your project folder, repository, or filesystem snapshot without also compromising your OS user account, your secrets remain unreadable.

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

## Pushing secrets to targets (create/update only)
Note: GitHub secrets are write-only by design. `cred` cannot read, diff or verify existing remote secrets after upload.

-   Push all local secrets:

```bash
cred push github
```

-   Push specific keys only:

```bash
cred push github API_URL API_KEY
```

Repo rules for GitHub:

-   If git metadata was recorded at init, it’s auto-used.
-   If you pass `--repo` and it doesn’t match the recorded repo, cred hard-fails to prevent cross-repo mistakes.
-   If you initialized outside git, you must provide `--repo owner/name`.

`push` reads your local `.cred/vault.enc`, transforms formats required by the target, and upserts secrets via the target API. It never deletes remote secrets.

## Removing secrets from targets (remote-only)

Prune deletes exactly the keys you specify on the remote; it does not diff and does not touch your local vault.

```bash
cred prune github KEY1 KEY2 --repo owner/name
```

```bash
cred prune github <key> --repo owner/name
```

Notes:

-   `--repo` is required if no git metadata was recorded; if provided, it must match the recorded repo to prevent cross-repo mistakes.
-   Prune is remote-only; use `cred secret remove` for local deletes.

---

## Project structure

Once initialized:

```
.cred/
  project.toml
  vault.enc
```

Global configuration lives at:

```
~/.config/cred/global.toml
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your choice.