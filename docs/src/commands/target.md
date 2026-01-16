# target

Manage deployment targets for this project.

## Overview

Target commands manage:

-   **Authentication** — tokens for each target platform
-   **Bindings** — identifiers (repo, app, project ID) for each target

Both tokens and bindings are stored **per-project**, enabling fine-grained tokens scoped to specific resources.

---

## target set

Authenticate with a target platform.

```bash
cred target set <target>
```

### Examples

```bash
# Authenticate with GitHub (prompts for token)
cred target set github

# Provide token directly (for automation)
cred target set github --token ghp_xxxxx
```

### Supported Targets

| Target   | Token Type                                                    |
| -------- | ------------------------------------------------------------- |
| `github` | Fine-grained PAT with Actions secrets permission              |
| `vercel` | Access Token from vercel.com/account/tokens                   |
| `fly`    | Personal Access Token from fly.io/user/personal_access_tokens |

### Notes

-   Must be inside a cred project (`cred init` first)
-   Tokens are stored in OS credential store, scoped to this project
-   Each project can have different tokens for the same target

---

## target bind

Bind a target identifier to this project.

```bash
cred target bind <target> <identifier>
```

### Examples

```bash
# Bind GitHub repo
cred target bind github owner/repo

# Bind Fly.io app
cred target bind fly my-app-name

# Bind Vercel project
cred target bind vercel prj_xxxxxxxxxxxxx
```

### When to Use

-   When auto-detection during `cred init` didn't find your target
-   When you want to override the auto-detected binding
-   When setting up a new target after init

Bindings are saved in `.cred/project.toml`:

```toml
[targets]
github = "owner/repo"
fly = "my-app-name"
```

---

## target list

List targets configured for this project.

```bash
cred target list
```

### Output

```
Project Targets:
  ✓ github = owner/repo
  ✗ fly = my-app

Run 'cred target set <target>' to authenticate.
```

-   ✓ = authenticated (token stored)
-   ✗ = binding exists but not authenticated

### JSON Output

```bash
cred target list --json
```

```json
{
    "api_version": "1",
    "status": "ok",
    "data": {
        "targets": [
            {
                "name": "github",
                "identifier": "owner/repo",
                "authenticated": true
            },
            { "name": "fly", "identifier": "my-app", "authenticated": false }
        ]
    }
}
```

---

## target revoke

Remove a target's authentication token.

```bash
cred target revoke <target> --yes
```

### Examples

```bash
# Revoke GitHub token
cred target revoke github --yes

# Dry-run to preview
cred target revoke github --dry-run
```

### Notes

-   Requires `--yes` flag (destructive operation)
-   Only removes the token; the binding remains in project.toml
-   For some targets (GitHub), attempts remote token revocation first

---

## Workflow Example

```bash
# Initialize project (auto-detects GitHub from git remote)
cred init

# Authenticate GitHub with fine-grained PAT
cred target set github

# Add a Fly.io app binding
cred target bind fly my-app

# Authenticate Fly.io
cred target set fly

# List all targets
cred target list

# Push to GitHub (no --repo needed)
cred push github

# Push to Fly.io (no --app needed)
cred push fly
```
