# Security Model

cred is designed with security as a core concern. This page explains how your secrets are protected.

## Encryption at Rest

Your vault (`.cred/vault.enc`) is encrypted using **ChaCha20-Poly1305**, a modern authenticated encryption algorithm. This provides both confidentiality and integrity protection.

## Key Storage

The encryption key is:
- Randomly generated on `cred init` (32 bytes)
- Stored in your OS credential store
- Never written to disk as plaintext

| OS      | Backend                                 |
| ------- | --------------------------------------- |
| macOS   | Keychain                                |
| Linux   | Secret Service (GNOME Keyring, KWallet) |
| Windows | Credential Manager                      |

## Token Storage

Source and target tokens (API keys, PATs) are also stored in your **OS credential store**.

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

The `.cred/` directory is added to `.gitignore` on init. Never commit it:

```bash
# Verify it's ignored
cat .gitignore | grep .cred
```

### 2. Use Least Privilege

-   For **sources**: Use master keys only for generation, deploy restricted keys
-   For **targets**: Create fine-grained PATs with minimal permissions

### 3. Keep Backups

Export your vault periodically:

```bash
cred export secrets-backup.env
```

Store backups securely (encrypted, offline).

### 4. Audit Your Secrets

Review what's in your vault:

```bash
cred status
cred secret list
```

Remove secrets you no longer need.

## Threat Model

cred is designed for:

-   **Solo developers** managing secrets on a single machine
-   Open-source maintainers who push secrets to deployment platforms
-   Projects that don't require multi-user access control

It is **not** designed for:

-   Team environments with multiple users
-   Multi-machine environments (cred is single-machine only)
-   Compliance-heavy industries (healthcare, finance) without additional controls
-   Scenarios requiring audit trails or approval workflows
