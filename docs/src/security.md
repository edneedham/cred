# Security Model

cred is designed with security as a core concern. This page explains how your secrets are protected.

## Encryption at Rest

Your vault (`.cred/vault.enc`) is encrypted using **ChaCha20-Poly1305**, a modern authenticated encryption algorithm. This provides both confidentiality and integrity protection.

## Key Derivation

cred supports two key modes:

### Keyring Mode (Default)

The encryption key is:
- Randomly generated on `cred init`
- Stored in your OS credential store
- Unique to your machine

Best for: Solo developers, local-only access.

### Passphrase Mode (Team Sharing)

The encryption key is:
- Derived from a shared passphrase using **Argon2id**
- Parameters: m=19456 KiB, t=2 iterations, p=1 (OWASP recommended)
- Salt stored in `project.toml` (safe to commit)

Best for: Teams who need shared vault access.

```bash
# Initialize with passphrase
cred init --passphrase

# Or convert existing project
cred key convert --to passphrase --yes
```

## Token Storage

Source and target tokens (API keys, PATs) are stored in your **OS credential store**:

| OS      | Backend                                 |
| ------- | --------------------------------------- |
| macOS   | Keychain                                |
| Linux   | Secret Service (GNOME Keyring, KWallet) |
| Windows | Credential Manager                      |

Tokens are **never** written to plaintext files like `~/.config/cred/global.toml`.

## What cred Protects Against

-   **Accidental exposure** — Secrets aren't in plaintext files that could be committed
-   **Disk compromise** — Vault is encrypted at rest
-   **Clipboard history** — Interactive prompts for sensitive input
-   **Overprivileged keys** — Sources generate restricted-scope credentials

## What cred Does NOT Protect Against

-   **Compromised machine** — If an attacker has access to your running system, they can access your keyring
-   **Memory attacks** — Secrets exist in memory during operations
-   **Malicious targets** — cred trusts the platforms you push to

## Safe Inspection

Use `--dry-run` to preview any operation before it executes:

```bash
cred push github --dry-run
cred prune github --all --dry-run
```

This is especially important for destructive operations.

## Best Practices

### 1. Never Commit Your Vault

Added to `.gitignore` on `cred init` otherwise check and add manually if needed:

```bash
echo .cred >> .gitignore
```

### 2. Use Least Privilege

-   For **sources**: Use master keys only for generation, deploy restricted keys
-   For **targets**: Create fine-grained PATs with minimal permissions

### 3. Rotation (coming soon)

### 4. Keep Backups

Export your vault periodically:

```bash
cred export secrets-backup.env
```

Store backups securely (encrypted, offline).

### 5. Audit Your Secrets

Review what's in your vault:

```bash
cred status
cred secret list
```

Remove secrets you no longer need.

## Threat Model

cred is designed for:

-   Individual developers
-   Small teams with trusted members
-   Projects that don't require enterprise-grade access control

It is **not** designed for:

-   Multi-tenant environments
-   Compliance-heavy industries (healthcare, finance) without additional controls
-   Scenarios requiring audit trails or approval workflows

## Team Sharing Security

When using passphrase mode:

-   **Passphrase strength matters** — Use 12+ characters with mixed case, numbers, symbols
-   **Share securely** — Use a password manager or encrypted channel, never plaintext
-   **Rotate when needed** — If a team member leaves, convert to a new passphrase
-   **The salt is public** — Only the passphrase must remain secret
