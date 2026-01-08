# push

Push secrets from your vault to a target platform.

## Basic Usage

Push all secrets to GitHub:

```bash
cred push github
```

Push all secrets to Vercel:

```bash
cred push vercel
```

Push all secrets to Fly.io:

```bash
cred push fly
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

## Environment-Specific Push

Push secrets from a specific environment:

```bash
cred push github --env prod
```

This pushes only secrets from the `prod` environment.

---

## Options

| Flag                  | Description                     |
| --------------------- | ------------------------------- |
| `--env <name>`        | Push from specific environment  |
| `--repo <owner/repo>` | Explicit repository (GitHub)    |
| `--project <id>`      | Explicit project ID (Vercel)    |
| `--app <name>`        | Explicit app name (Fly.io)      |
| `--dry-run`           | Preview changes without pushing |
| `--json`              | Machine-readable output         |
| `--non-interactive`   | Fail instead of prompting       |

## Target Detection

### GitHub

cred automatically detects your repository from git metadata when you're inside a git repository.

If you're not in a git repository, or need to push to a different repo:

```bash
cred push github --repo owner/repo
```

### Vercel

cred auto-detects your project from `.vercel/project.json` (created by `vercel link`).

If you haven't linked your project:

```bash
vercel link
```

Or specify the project ID explicitly:

```bash
cred push vercel --project prj_xxxxxxxxxxxxx
```

### Fly.io

cred auto-detects your app from `fly.toml` (created by `fly launch`).

If you haven't launched your app:

```bash
fly launch
```

Or specify the app name explicitly:

```bash
cred push fly --app my-app-name
```

**Note:** After pushing secrets to Fly.io, run `fly deploy` or `fly secrets deploy` to apply changes.

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
