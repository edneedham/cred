# init

Initialize a cred project.

## Basic Usage

Initialize a new cred project in the current directory:

```bash
cred init
```

This creates:

```
.cred/
├── project.toml    # Project configuration
└── vault.enc       # Encrypted secrets vault
```

Run this once per project, typically at the repository root.

---

## Team Mode (Passphrase)

For team collaboration, initialize with passphrase-based key derivation:

```bash
cred init --passphrase
```

You'll be prompted to enter and confirm a passphrase (minimum 8 characters).

This mode:
- Derives the encryption key from a shared passphrase using Argon2id
- Stores a random salt in `project.toml` (safe to commit)
- Allows team members to access the vault with the same passphrase

### Sharing with Your Team

1. Commit the `.cred/project.toml` (but never `vault.enc`)
2. Share the passphrase securely (password manager, encrypted message)
3. Team members will be prompted for the passphrase on first use

### CI/CD Usage

Set the `CRED_PASSPHRASE` environment variable:

```bash
export CRED_PASSPHRASE="your-team-passphrase"
cred secret list
```

---

## Options

| Flag           | Description                              |
| -------------- | ---------------------------------------- |
| `--passphrase` | Use passphrase-based key (team sharing)  |

---

## Key Modes

| Mode         | Created By          | Best For           |
| ------------ | ------------------- | ------------------ |
| `keyring`    | `cred init`         | Solo developers    |
| `passphrase` | `cred init --passphrase` | Teams         |

You can convert between modes later with [`cred key convert`](./key.md).


