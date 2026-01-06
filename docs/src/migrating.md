# Migrating Existing Secrets

If you choose to migrate to cred instead of continuing with manual `.env` files you'll need the original values from wherever you stored them (password manager, `.env` files, etc.).

## Migration Steps

**1. Initialize cred:**

```bash
cred init
```

**2. Import your secrets:**

From a `.env` file:

```bash
cred import .env
```

Or add individually:

```bash
cred secret set DATABASE_URL "postgres://..."
cred secret set API_KEY "sk-..."
```

**Tip:** Use environments to organize secrets by deployment context:

```bash
cred env create prod
cred import prod.env --env prod
```

**3. Set up the GitHub target:**

```bash
cred target set github
```

**4. Push to GitHub:**

Preview first:

```bash
cred push github --dry-run
```

Then push:

```bash
cred push github
```

Your existing workflows continue working unchanged — they reference secrets by name, and cred pushes to the same location.

### Why Migrate?

| Before (manual)                    | After (cred)                   |
| ---------------------------------- | ------------------------------ |
| Secrets in .env files or notes     | Single encrypted vault         |
| Copy-paste into GitHub UI          | `cred push github`             |
| No visibility into what's deployed | `cred status` shows everything |
| Hard to sync across repos          | Push to multiple targets       |
