# Migrating

## Upgrading from v0.13.x to v0.14.0

v0.14.0 introduces **first-class target scoping** for secrets.

### What Changed

-   Secrets can now be scoped to specific targets via `cred secret set --targets ...`
-   `cred push` / `cred prune` respect those scopes by default
-   Existing secrets are **unscoped** by default (no behavior change until you add scopes)

### Recommended Migration

For projects where some targets are “frontend only” (e.g. Vercel), start scoping the relevant secrets:

```bash
# Public frontend variables (Vercel only)
cred secret set NEXT_PUBLIC_API_URL "https://..." --targets vercel

# Backend secrets (GitHub only)
cred secret set DATABASE_URL "postgres://..." --targets github
```

If you ever need to override scoping for a one-off push/prune, use `--force`.

## Upgrading from v0.12.x to v0.13.0

v0.13.0 introduces **per-project target tokens**. Your existing vaults and secrets are unchanged, but target authentication needs to be re-configured.

### What Changed

| Before (v0.12.x)                    | After (v0.13.0)                      |
| ----------------------------------- | ------------------------------------ |
| One global token per target         | Per-project tokens                   |
| `cred target set` stored globally   | `cred target set` stores per-project |
| `--repo`/`--app` flags often needed | Target bindings saved in project     |

### Migration Steps

In each of your cred projects:

```bash
cd your-project

# Re-authenticate targets (tokens now stored per-project)
cred target set github --token <your-fine-grained-pat>

# Verify target bindings were auto-detected or set them manually
cred target list

# If needed, bind targets manually
cred target bind github owner/repo
cred target bind fly my-app
```

### Why This Change?

Modern fine-grained tokens (like GitHub PATs) are scoped to specific repos. A token for `repo-a` cannot access `repo-b`. Per-project token storage properly supports this security model.

---

## Migrating Existing Secrets to cred

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
