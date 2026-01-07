# import

Import secrets from a `.env` file into the local vault.

## Usage

```bash
cred import <path> [OPTIONS]
```

## Arguments

| Argument | Description                       |
| -------- | --------------------------------- |
| `<path>` | Path to the `.env` file to import |

## Options

| Option             | Description                                          |
| ------------------ | ---------------------------------------------------- |
| `--overwrite`      | Overwrite existing keys instead of skipping          |
| `-e, --env <name>` | Target environment (auto-detected from cred exports) |

## Behavior

### Plain `.env` Files

When importing a standard `.env` file:

```bash
# Import to default environment
cred import .env

# Import to a specific environment
cred import .env --env prod
```

Secrets are imported as plain key-value pairs without metadata.

### Cred Export Files

When importing a file created by `cred export`:

```bash
# Import preserving environments and metadata
cred import vault.env
```

Cred automatically detects export files by their header and:

-   Recreates environment structure from the file
-   Restores secret metadata (descriptions, timestamps)
-   Creates any environments that don't exist

To force all secrets into a single environment:

```bash
# Override: import all secrets to staging environment
cred import vault.env --env staging
```

## Examples

```bash
# Import from .env, skip existing keys
cred import .env

# Import and overwrite existing keys
cred import .env --overwrite

# Import to production environment
cred import prod.env --env prod

# Import a cred export file (auto-detects format)
cred import teammate-vault.env

# Preview what would be imported
cred import .env --dry-run
```

## Output

```
✓ Imported .env (added 5, overwritten 0, skipped 2).
```

For cred export files with multiple environments:

```
✓ Imported vault.env (created 2 env(s)) (added 10, overwritten 0, skipped 0).
```
