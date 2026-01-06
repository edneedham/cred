# env

Manage environments for organizing secrets. Environments allow you to separate secrets for different contexts (e.g., `dev`, `staging`, `prod`).

## Overview

By default, all secrets are stored in the `default` environment. You can create additional environments to isolate secrets for different deployment contexts.

## list

List all environments:

```bash
cred env list
```

Output:

```
Environments:
  default (3 secrets)
  staging (2 secrets)
  prod (5 secrets)
```

---

## create

Create a new environment:

```bash
cred env create staging
```

Output:

```
✓ Created environment 'staging'
```

---

## delete

Delete an environment and all its secrets:

```bash
cred env delete staging --yes
```

Output:

```
✓ Deleted environment 'staging' (2 secrets removed)
```

⚠️ **This is a destructive operation** — requires `--yes` to confirm.

---

## Using Environments

Most secret commands accept an `--env` flag:

```bash
# Set a secret in the prod environment
cred secret set DATABASE_URL "postgres://prod..." --env prod

# Get a secret from staging
cred secret get API_KEY --env staging

# List secrets in a specific environment
cred secret list --env prod

# Push prod secrets to GitHub
cred push github --env prod

# Export prod secrets to a file
cred export prod.env --env prod
```

---

## Environment Strategy

Common patterns:

| Environment | Purpose                   |
| ----------- | ------------------------- |
| `default`   | Development/local secrets |
| `staging`   | Pre-production testing    |
| `prod`      | Production secrets        |

---

## Migration from v0.5.x

If you're upgrading from a version without environments, your existing secrets are automatically migrated to the `default` environment. No action required.

