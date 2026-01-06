# init

Initialize a cred project.

## Usage

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

## What Happens

1. Creates the `.cred/` directory
2. Generates a random 32-byte encryption key
3. Stores the key in your OS credential store (Keychain, GNOME Keyring, etc.)
4. Creates an empty encrypted vault
5. Adds `.cred/` to `.gitignore`

## CI/CD Usage

For CI environments, export your encryption key as base64:

```bash
# On your machine, get the key
cred doctor --json | jq -r '.data.key_b64'
```

Then set it as a CI secret:

```yaml
# GitHub Actions example
env:
  CRED_MASTER_KEY_B64: ${{ secrets.CRED_MASTER_KEY }}
```

See [Security Model](../security.md) for more details.
