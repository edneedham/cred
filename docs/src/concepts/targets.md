# Targets

Targets are platforms where you **push secrets for deployment**. cred uploads your vault secrets to these platforms so your workflows can access them directly.

## How It Works

```
Your machine              Target platform          Your workflow
 ┌─────────┐               ┌──────────────┐         ┌──────────┐
 │  cred   │──push───────►│   GitHub     │◄────────│ workflow │
 │ (vault) │               │   Secrets    │  reads  │          │
 └─────────┘               └──────────────┘         └──────────┘
```

1. You run `cred push github` on your dev machine
2. cred uploads secrets to GitHub Actions
3. Your workflows read secrets directly from GitHub — no cred involved

## Adding a Target

Authenticate a deployment target:

```bash
cred target set github
```

You will be securely prompted for a token. The token is stored in your OS credential store, not in plaintext on disk.

## Managing Targets

**List configured targets:**

```bash
cred target list
```

**Revoke a target:**

```bash
cred target revoke github --yes
```

---

## GitHub

GitHub Actions secrets are the primary target for cred. Secrets you push become available to your workflows.

### Setup

1. Create a **fine-grained Personal Access Token** at [github.com/settings/tokens](https://github.com/settings/tokens)
2. Select only the repository you want to manage
3. Grant only the **Actions secrets** permission (read and write)
4. Add the token to cred:

```bash
cred target set github
```

### Pushing Secrets

```bash
# Push all secrets
cred push github

# Push specific secrets
cred push github DATABASE_URL API_KEY
```

cred automatically detects your repository from git metadata. If you're not in a git repository, specify it explicitly:

```bash
cred push github --repo owner/repo
```

### Using Secrets in Workflows

Once pushed, secrets are available in your GitHub Actions:

```yaml
jobs:
    deploy:
        runs-on: ubuntu-latest
        env:
            DATABASE_URL: ${{ secrets.DATABASE_URL }}
        steps:
            - run: echo "Secret is available"
```

---

## Why Targets Use Simple Tokens

Targets need **minimal permissions** — just enough to write secrets. This follows the principle of least privilege.

Unlike sources (which need elevated permissions to generate new credentials), targets only need write access to a specific resource (e.g., GitHub Actions secrets for one repository).
