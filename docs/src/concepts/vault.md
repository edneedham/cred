# Vault

The vault is your local encrypted secrets store. Each cred project has its own vault containing all secrets with rich metadata, organized by environment.

## Structure

When you run `cred init`, cred creates:

```
.cred/
├── project.toml    # Project metadata
└── vault.enc       # Encrypted secrets
```

Global configuration lives at:

```
~/.config/cred/global.toml
```

## Environments

Secrets are organized into environments (e.g., `default`, `staging`, `prod`). This allows you to manage different configurations for different deployment contexts.

```bash
# List environments
cred env list

# Create an environment
cred env create prod

# Set a secret in an environment
cred secret set DATABASE_URL "postgres://..." --env prod
```

By default, secrets are stored in the `default` environment.

See [`cred env`](../commands/env.md) for more details.

## Secret Metadata

Each secret in the vault includes:

| Field         | Description                                    |
| ------------- | ---------------------------------------------- |
| `key`         | The secret name (e.g., `DATABASE_URL`)         |
| `value`       | The encrypted secret value                     |
| `format`      | Content format (raw, json, pem, etc.)          |
| `created_at`  | When the secret was first added                |
| `updated_at`  | When the secret was last modified              |
| `description` | Optional human-readable description            |
| `source`      | Where it came from (`manual` or a source name) |
| `history`     | Up to 10 previous versions (for rollback)      |

## Secret Formats

cred auto-detects the format of your secrets:

| Format      | Detection                  | Example                    |
| ----------- | -------------------------- | -------------------------- |
| `pem`       | Starts with `-----BEGIN`   | Certificates, private keys |
| `json`      | Valid JSON object or array | `{"key": "value"}`         |
| `base64`    | Single-line base64 content | `SGVsbG8gV29ybGQ=`         |
| `multiline` | Contains newlines          | Multi-line text            |
| `raw`       | Everything else (default)  | `super-secret-value`       |

You can also specify format explicitly:

```bash
cred secret set MY_KEY "value" --format json
```

## Viewing the Vault

**List all secrets:**

```bash
cred secret list
```

Output:

```
Vault content:
  API_KEY = ***** (OpenAI production key)
  DATABASE_URL = *****
  JWT_SECRET = ***** [modified]
```

**Get a specific secret:**

```bash
cred secret get JWT_SECRET
```

**With full metadata (JSON):**

```bash
cred secret get JWT_SECRET --json
```

```json
{
    "data": {
        "key": "JWT_SECRET",
        "value": "super-secret",
        "format": "raw",
        "created_at": "2025-12-11T12:00:00Z",
        "updated_at": "2025-12-11T12:00:00Z",
        "description": null
    }
}
```

## Version History

cred automatically tracks up to 10 previous versions of each secret. View history and rollback:

```bash
# View version history
cred secret history DATABASE_URL

# Rollback to previous version (0 = most recent)
cred secret rollback DATABASE_URL --version 0 --yes
```

See [`cred secret history`](../commands/secret.md#history) for more details.

## Hub-and-Spoke Status

For a complete overview of your project:

```bash
cred status
```

```
Vault: 5 secrets (2 environments)

Environment: default
  RESEND_API_KEY       [resend]
  DATABASE_URL         [manual]

Environment: prod
  DATABASE_URL         [manual]
  JWT_SECRET           [manual]
  API_KEY              [manual]

Sources: resend ✓
Targets: github ✓
```

## Encryption

The vault is encrypted at rest using ChaCha20-Poly1305. The encryption key is generated on `cred init` and stored in your OS credential store (Keychain, GNOME Keyring, etc.). See [Security Model](../security.md) for details.

## Best Practices

1. **Add `.cred/` to `.gitignore`** — Never commit your vault
2. **Use descriptions** — Document what each secret is for
3. **Use environments** — Separate dev/staging/prod secrets
4. **Keep backups** — Export periodically with `cred export`
5. **Use sources when possible** — Generated keys have better audit trails
6. **Review history before rollback** — Use `cred secret history` first
