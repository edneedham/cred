# export

Export vault secrets to a `.env` file.

## Usage

```bash
cred export <path> [OPTIONS]
```

## Arguments

| Argument | Description                     |
| -------- | ------------------------------- |
| `<path>` | Path to write the exported file |

## Options

| Option             | Description                                                  |
| ------------------ | ------------------------------------------------------------ |
| `--force`          | Overwrite the output file if it exists                       |
| `-e, --env <name>` | Export only this environment (exports full vault if omitted) |
| `--plain`          | Plain `.env` format (no metadata, requires `--env`)          |

## Export Formats

### Full Vault Export (Default)

By default, `cred export` creates a rich export file containing all environments with metadata:

```bash
cred export vault.env
```

Output format:

```env
# cred-export v1
# exported: 2025-01-07T10:30:00Z
#
# To import: cred import <this-file>

# [environment: default]

# [API_KEY]
# description: Development API key
# created: 2025-01-01T00:00:00Z
API_KEY=sk-dev-xxx

# [DATABASE_URL]
DATABASE_URL=postgres://localhost/dev

# [environment: prod]

# [API_KEY]
# description: Production API key
# created: 2025-01-05T00:00:00Z
API_KEY=sk-prod-xxx
```

This format:

-   Preserves all environments
-   Includes secret metadata (descriptions, timestamps)
-   Can be imported by `cred import` to recreate the full vault

### Single Environment Export

Export just one environment with metadata:

```bash
cred export prod.env --env prod
```

Output format:

```env
# cred-export v1
# environment: prod
# exported: 2025-01-07T10:30:00Z
#
# To import: cred import <this-file>

# [API_KEY]
# description: Production API key
API_KEY=sk-prod-xxx
```

### Plain Export

Export as a standard `.env` file without metadata:

```bash
cred export .env --env default --plain
```

Output format:

```env
API_KEY=sk-dev-xxx
DATABASE_URL=postgres://localhost/dev
```

Use this when you need a standard `.env` file for tools that don't understand cred comments.

## Examples

```bash
# Export full vault with metadata
cred export vault.env

# Export only production environment
cred export prod.env --env prod

# Export as plain .env (no metadata)
cred export .env --env default --plain

# Overwrite existing file
cred export vault.env --force

# Preview what would be exported
cred export vault.env --dry-run
```

## Output

```
✓ Exported 10 secrets (3 environment(s)) to vault.env.
```

For single environment:

```
✓ Exported 5 secrets (env 'prod') to prod.env.
```

## Use Cases

### Sharing Secrets with Teammates

Export your vault and share the file securely:

```bash
cred export team-vault.env
# Transfer file securely (encrypted email, secure share, etc.)
```

Teammate imports:

```bash
cred import team-vault.env
```

### Backup

Create a backup of your entire vault:

```bash
cred export backup-$(date +%Y%m%d).env
```

### Integration with Other Tools

When you need a standard `.env` for other tools:

```bash
cred export .env --env default --plain
```
