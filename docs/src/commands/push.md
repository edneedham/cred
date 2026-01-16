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

No `--repo`, `--app`, or `--project` flags needed — cred uses the target bindings saved in your project.

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
| `--force`             | Ignore per-secret target scopes |
| `--dry-run`           | Preview changes without pushing |
| `--json`              | Machine-readable output         |
| `--non-interactive`   | Fail instead of prompting       |

## Target Scopes (v0.14.0+)

If a secret is scoped to specific targets, `cred push <target>` will:

-   Include unscoped secrets
-   Include secrets scoped to `<target>`
-   Skip (or refuse, if explicitly requested) secrets scoped to other targets

If you explicitly request a key that isn't scoped to the target, cred refuses by default. Use `--force` to override.

## Target Resolution

cred resolves target identifiers in this order:

1. **CLI flag** (`--repo`, `--app`, `--project`) — highest priority
2. **Project binding** (saved in `.cred/project.toml`)
3. **Auto-detection** (git remote, fly.toml, etc.) — fallback

### GitHub

Target binding is auto-detected from git remote during `cred init`, or set manually:

```bash
cred target bind github owner/repo
```

Override with CLI flag if needed:

```bash
cred push github --repo different/repo
```

### Vercel

Target binding is auto-detected from `.vercel/project.json` during `cred init`, or set manually:

```bash
cred target bind vercel prj_xxxxxxxxxxxxx
```

Override with CLI flag if needed:

```bash
cred push vercel --project prj_other
```

### Fly.io

Target binding is auto-detected from `fly.toml` during `cred init`, or set manually:

```bash
cred target bind fly my-app-name
```

Override with CLI flag if needed:

```bash
cred push fly --app different-app
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
