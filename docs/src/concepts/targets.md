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

## Per-Project Tokens

**As of v0.13.0**, target tokens are stored **per-project**, not globally. This properly supports fine-grained tokens (like GitHub PATs scoped to specific repos).

Each project has its own:

-   **Target bindings** — the identifier for each target (repo, app, project ID)
-   **Target tokens** — authentication credentials stored in OS keyring

This means:

-   Project A can use a GitHub PAT scoped to `owner/repo-a`
-   Project B can use a different PAT scoped to `owner/repo-b`
-   No token conflicts or accidental cross-project access

## Target Bindings

Target bindings are saved in `.cred/project.toml` during `cred init` (auto-detected) or via `cred target bind`:

```toml
# .cred/project.toml
[targets]
github = "owner/repo"
fly = "my-app"
vercel = "prj_xxxxx"
```

**Bind a target manually:**

```bash
cred target bind github owner/repo
cred target bind fly my-app
cred target bind vercel prj_xxxxx
```

Once bound, you don't need `--repo`, `--app`, or `--project` flags when pushing.

## Target-Scoped Secrets (v0.14.0+)

Secrets can optionally be **scoped to specific targets**. This is useful when, for example, your Vercel target is “frontend only” and you want to avoid pushing backend secrets there.

-   **Unscoped secrets (default)**: eligible for all targets
-   **Scoped secrets**: only eligible for the listed targets

Set scopes when writing a secret:

```bash
cred secret set NEXT_PUBLIC_API_URL "https://..." --targets vercel
cred secret set DATABASE_URL "postgres://..." --targets github,fly
```

`cred push <target>` and `cred prune <target>` respect these scopes by default. Use `--force` to override.

## Adding a Target

Authenticate a deployment target (must be inside a cred project):

```bash
cred target set github
```

You will be securely prompted for a token. The token is stored in your OS credential store, scoped to this project.

## Managing Targets

**List configured targets for this project:**

```bash
cred target list
```

Output shows binding and authentication status:

```
Project Targets:
  ✓ github = owner/repo
  ✗ fly = my-app

Run 'cred target set <target>' to authenticate.
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

## Vercel

Push environment variables to Vercel projects. Secrets you push become available to your deployments.

### Setup

1. Create an **Access Token** at [vercel.com/account/tokens](https://vercel.com/account/tokens)
2. Grant **Full Account** scope (required for environment variable management)
3. Add the token to cred:

```bash
cred target set vercel
```

### Linking Your Project

cred auto-detects your Vercel project from `.vercel/project.json` (created by `vercel link`). If you haven't linked:

```bash
vercel link
```

Or specify the project ID explicitly:

```bash
cred push vercel --project prj_xxxxxxxxxxxxx
```

### Environment Mapping

cred environments map to Vercel targets:

| cred env  | Vercel target |
| --------- | ------------- |
| `prod`    | `production`  |
| `default` | `development` |
| others    | `preview`     |

```bash
# Push to Vercel production
cred push vercel --env prod

# Push to Vercel development (default)
cred push vercel
```

### Using Secrets in Deployments

Once pushed, environment variables are automatically available in your Vercel deployments:

```javascript
// Next.js example
const apiKey = process.env.API_KEY;
```

---

## Fly.io

Push secrets to Fly.io apps. Secrets you push become available to your deployed applications.

### Setup

1. Create a **Personal Access Token** at [fly.io/user/personal_access_tokens](https://fly.io/user/personal_access_tokens)
2. Add the token to cred:

```bash
cred target set fly
```

### Linking Your App

cred auto-detects your Fly.io app from `fly.toml` (created by `fly launch`). If you haven't launched:

```bash
fly launch
```

Or specify the app name explicitly:

```bash
cred push fly --app my-app-name
```

### Pushing Secrets

```bash
# Push all secrets
cred push fly

# Push specific secrets
cred push fly DATABASE_URL API_KEY

# Push to a specific app
cred push fly --app my-app-name
```

### Applying Secrets

After pushing secrets, Fly.io requires a deployment to apply them:

```bash
fly deploy
# or
fly secrets deploy
```

### Using Secrets in Your App

Once deployed, secrets are available as environment variables:

```javascript
// Node.js example
const apiKey = process.env.API_KEY;
```

```python
# Python example
import os
api_key = os.environ.get("API_KEY")
```

---

## Why Targets Use Simple Tokens

Targets need **minimal permissions** — just enough to write secrets. This follows the principle of least privilege.

Unlike sources (which need elevated permissions to generate new credentials), targets only need write access to a specific resource (e.g., GitHub Actions secrets for one repository, Vercel environment variables for one project).
