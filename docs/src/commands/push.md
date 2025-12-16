# push

Push secrets from your vault to a target platform.

## Basic Usage

Push all secrets to GitHub:

```bash
cred push github
```

Push specific secrets only:

```bash
cred push github DATABASE_URL JWT_SECRET
```

## Dry Run

Preview what will change before pushing:

```bash
cred push github --dry-run
```

Preview specific keys:

```bash
cred push github DATABASE_URL JWT_SECRET --dry-run
```

Nothing is uploaded when `--dry-run` is used.

## Options

| Flag                | Description                     |
| ------------------- | ------------------------------- |
| `--dry-run`         | Preview changes without pushing |
| `--json`            | Machine-readable output         |
| `--non-interactive` | Fail instead of prompting       |

## Repository Detection

cred automatically detects your repository from git metadata when you're inside a git repository.

If you're not in a git repository, or need to push to a different repo:

```bash
cred push github --repo owner/repo
```

## Incremental Updates

cred tracks which secrets have changed since the last push. Only modified secrets are updated remotely, making pushes efficient.

## Workflow Example

```bash
# Add a secret
cred secret set DATABASE_URL "postgres://..."

# Preview the push
cred push github --dry-run

# Push when ready
cred push github
```

## Updating Secrets

To update a secret:

```bash
# Update locally
cred secret set JWT_SECRET "new-secret-value"

# Preview changes
cred push github --dry-run

# Apply
cred push github
```

Only the changed secret will be updated at the target.
