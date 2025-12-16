# Targets

Targets are platforms where you **push secrets for deployment**. cred uploads your vault secrets to these platforms so your CI/CD pipelines can access them.

## Adding a Target

Authenticate a deployment target:

```bash
cred target set github
```

You will be securely prompted for a token. The token is stored in your OS credential store, not in plaintext on disk.

For non-interactive use (CI):

```bash
cred target set github --token "$GITHUB_TOKEN" --non-interactive
```

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
