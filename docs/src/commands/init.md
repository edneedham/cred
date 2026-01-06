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

## Important Notes

-   cred is **single-machine only** — the vault and encryption key stay on your dev machine
-   Use `cred push` to deploy secrets to platforms like GitHub Actions
-   Your CI/CD reads secrets from the target platform directly, not from cred

See [Security Model](../security.md) for more details.
