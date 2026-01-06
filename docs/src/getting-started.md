# Getting Started

Get from zero to your first secret push in under 5 minutes.

## 1. Initialize your project

```bash
cred init
```

This creates `.cred/vault.enc` in your project and stores the encryption key in your OS credential store.

## 2. Add a target

```bash
cred target set github
```

You'll be prompted for a fine-grained PAT with **Actions secrets** permission.

## 3. Store a secret

```bash
cred secret set DATABASE_URL "postgres://user:pass@localhost/db"
```

## 4. Push to GitHub

Preview first:

```bash
cred push github --dry-run
```

Then push:
```bash
cred push github
```

Done! Your secret is now in GitHub Actions.

---

## Working with Environments

Organize secrets by environment (dev, staging, prod):

```bash
# Create environments
cred env create staging
cred env create prod

# Set secrets in specific environments
cred secret set DATABASE_URL "postgres://prod..." --env prod

# Push prod secrets to GitHub
cred push github --env prod
```

See [env command](./commands/env.md) for more details.

---

**Next steps:**
-   [Commands Reference](./commands/README.md) — all available commands
-   [Environments](./commands/env.md) — organize secrets by environment
-   [Sources](./concepts/sources.md) — generate credentials from APIs like Resend
-   [Security Model](./security.md) — how your secrets are protected
